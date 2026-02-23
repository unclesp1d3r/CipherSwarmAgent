package lib

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// withHTTPAndState sets up httpmock and shared state for tests and runs fn.
func withHTTPAndState(t *testing.T, fn func()) {
	t.Helper()
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()
	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	defer cleanupState()
	// Mock SubmitErrorAgent endpoint to avoid recursion and enable call counting
	testhelpers.MockSubmitErrorSuccess(123)
	fn()
}

// assertSubmitErrorCalledIfAPIError asserts submit_error was called when err is an API error type.
func assertSubmitErrorCalledIfAPIError(t *testing.T, err error) {
	t.Helper()
	var ae *api.APIError
	if errors.As(err, &ae) {
		callCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
		assert.Positive(t, callCount)
	}
}

// TestHandleAuthenticationError tests the handleAuthenticationError function.
func TestHandleAuthenticationError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		expectError bool
	}{
		{
			name:        "APIError_ClientError",
			err:         testhelpers.NewValidationAPIError("authentication failed"),
			expectError: true,
		},
		{
			name:        "APIError_ServerError",
			err:         testhelpers.NewAPIError(http.StatusBadRequest, "bad request"),
			expectError: true,
		},
		{
			name:        "generic error",
			err:         errors.New("generic error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			defer cleanupState()

			result := handleAuthenticationError(context.Background(), tt.err)

			if tt.expectError {
				require.Error(t, result)
			} else {
				require.NoError(t, result)
			}
		})
	}
}

// TestHandleConfigurationError tests the handleConfigurationError function.
func TestHandleConfigurationError(t *testing.T) {
	tests := []struct {
		name              string
		err               error
		expectError       bool
		expectSubmitError bool
	}{
		{
			name:              "APIError_ClientError",
			err:               testhelpers.NewValidationAPIError("configuration error"),
			expectError:       true,
			expectSubmitError: true,
		},
		{
			name:              "APIError_ServerError",
			err:               testhelpers.NewAPIError(http.StatusBadRequest, "server error"),
			expectError:       true,
			expectSubmitError: true,
		},
		{
			name:              "generic error",
			err:               errors.New("generic error"),
			expectError:       true,
			expectSubmitError: true, // Generic errors are now sent to the server for visibility
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			defer cleanupState()

			// Mock SubmitErrorAgent endpoint
			initialCallCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
			testhelpers.MockSubmitErrorSuccess(123)

			result := handleConfigurationError(context.Background(), tt.err)

			if tt.expectError {
				require.Error(t, result)
			} else {
				require.NoError(t, result)
			}

			// Verify SubmitErrorAgent was called only for API error types
			finalCallCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
			if tt.expectSubmitError {
				assert.Greater(t, finalCallCount, initialCallCount, "submit_error should be called for API error types")
			} else {
				assert.Equal(
					t,
					finalCallCount,
					initialCallCount,
					"submit_error should not be called for generic errors",
				)
			}
		})
	}
}

// TestHandleAPIError tests the handleAPIError function.
func TestHandleAPIError(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		err         error
		expectError bool
	}{
		{
			name:        "APIError_ClientError",
			message:     "API error",
			err:         testhelpers.NewValidationAPIError("api error"),
			expectError: false, // function doesn't return error
		},
		{
			name:        "credential validation error",
			message:     "API error",
			err:         ErrCouldNotValidateCredentials,
			expectError: false,
		},
		{
			name:        "APIError for 401 Unauthorized",
			message:     "API error",
			err:         testhelpers.NewAPIError(http.StatusUnauthorized, "unauthorized"),
			expectError: false,
		},
		{
			name:        "APIError for 403 Forbidden",
			message:     "API error",
			err:         testhelpers.NewAPIError(http.StatusForbidden, "forbidden"),
			expectError: false,
		},
		{
			name:        "APIError for other status codes",
			message:     "API error",
			err:         testhelpers.NewAPIError(http.StatusBadRequest, "server error"),
			expectError: false,
		},
		{
			name:        "generic error",
			message:     "API error",
			err:         errors.New("generic error"),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			defer cleanupState()

			// Mock SubmitErrorAgent endpoint
			testhelpers.MockSubmitErrorSuccess(123)

			// This function doesn't return an error
			handleAPIError(context.Background(), tt.message, tt.err)

			// Verify SubmitErrorAgent was called for API errors
			if tt.err != nil {
				var ae *api.APIError
				if errors.As(tt.err, &ae) {
					callCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
					assert.Positive(t, callCount)
				}
			}
		})
	}
}

// TestHandleHeartbeatError tests the handleHeartbeatError function.
func TestHandleHeartbeatError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "APIError_ClientError",
			err:  testhelpers.NewValidationAPIError("heartbeat error"),
		},
		{
			name: "APIError_ServerError",
			err:  testhelpers.NewAPIError(http.StatusBadRequest, "server error"),
		},
		{
			name: "generic error",
			err:  errors.New("generic error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withHTTPAndState(t, func() {
				// This function doesn't return an error
				handleHeartbeatError(context.Background(), tt.err)
				assertSubmitErrorCalledIfAPIError(t, tt.err)
			})
		})
	}
}

// TestSendAgentError tests the cserrors.SendAgentError function.
func TestSendAgentError(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		task     *api.Task
		severity api.Severity
	}{
		{
			name:     "with nil task",
			message:  "test error",
			task:     nil,
			severity: api.SeverityCritical,
		},
		{
			name:     "with non-nil task",
			message:  "test error",
			task:     testhelpers.NewTestTask(456, 789),
			severity: api.SeverityCritical,
		},
		{
			name:     "different severity levels",
			message:  "test error",
			task:     nil,
			severity: api.SeverityWarning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			defer cleanupState()

			// Mock SubmitErrorAgent endpoint
			testhelpers.MockSubmitErrorSuccess(123)

			// This function doesn't return an error
			cserrors.SendAgentError(context.Background(), tt.message, tt.task, tt.severity)

			// Verify SubmitErrorAgent was called
			callCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
			assert.Positive(t, callCount)
		})
	}
}

// TestHandleCrackerUpdate tests the handleCrackerUpdate function
// Note: This function has many external dependencies and may need integration test approach.
func TestHandleCrackerUpdate(t *testing.T) {
	// This test is a placeholder - actual implementation would require extensive mocking
	// of downloader, cracker, and viper operations
	t.Skip("Skipping handleCrackerUpdate test - requires extensive mocking of external dependencies")
}
