package lib

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
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
			err:         testhelpers.NewErrorObject("authentication failed"),
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

			result := handleAuthenticationError(tt.err)

			if tt.expectError {
				assert.Error(t, result)
			} else {
				assert.NoError(t, result)
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
			err:               testhelpers.NewErrorObject("configuration error"),
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

			result := handleConfigurationError(tt.err)

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
			err:         testhelpers.NewErrorObject("api error"),
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
			handleAPIError(tt.message, tt.err)

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
			err:  testhelpers.NewErrorObject("heartbeat error"),
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
				handleHeartbeatError(tt.err)
				assertSubmitErrorCalledIfAPIError(t, tt.err)
			})
		})
	}
}

// TestHandleStatusUpdateError tests the handleStatusUpdateError function.
func TestHandleStatusUpdateError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		task *api.Task
	}{
		{
			name: "APIError_ClientError",
			err:  testhelpers.NewErrorObject("status update error"),
			task: testhelpers.NewTestTask(456, 789),
		},
		{
			name: "APIError_NotFound",
			err:  testhelpers.NewAPIError(http.StatusNotFound, "not found"),
			task: testhelpers.NewTestTask(456, 789),
		},
		{
			name: "generic error",
			err:  errors.New("generic error"),
			task: testhelpers.NewTestTask(456, 789),
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

			// Create a mock session
			sess, err := testhelpers.NewMockSession("test-session")
			if err != nil {
				t.Skipf("Skipping test: failed to create mock session: %v", err)
				return
			}
			defer sess.Cleanup()

			// This function doesn't return an error
			handleStatusUpdateError(tt.err, tt.task, sess)
		})
	}
}

// TestHandleTaskNotFound tests the handleTaskNotFound function.
func TestHandleTaskNotFound(t *testing.T) {
	tests := []struct {
		name string
		task *api.Task
	}{
		{
			name: "task not found",
			task: testhelpers.NewTestTask(456, 789),
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

			// Create a mock session
			sess, err := testhelpers.NewMockSession("test-session")
			if err != nil {
				t.Skipf("Skipping test: failed to create mock session: %v", err)
				return
			}
			defer sess.Cleanup()

			// This function doesn't return an error
			handleTaskNotFound(tt.task, sess)
		})
	}
}

// TestHandleTaskGone tests the handleTaskGone function.
func TestHandleTaskGone(t *testing.T) {
	tests := []struct {
		name string
		task *api.Task
	}{
		{
			name: "task gone",
			task: testhelpers.NewTestTask(456, 789),
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

			// Create a mock session
			sess, err := testhelpers.NewMockSession("test-session")
			if err != nil {
				t.Skipf("Skipping test: failed to create mock session: %v", err)
				return
			}
			defer sess.Cleanup()

			// This function doesn't return an error
			handleTaskGone(tt.task, sess)
		})
	}
}

// TestSendAgentError tests the SendAgentError function.
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
			SendAgentError(tt.message, tt.task, tt.severity)

			// Verify SubmitErrorAgent was called
			callCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
			assert.Positive(t, callCount)
		})
	}
}

// TestHandleSendError tests the handleSendError function.
// This function should only log errors and NOT attempt to send them again
// to prevent infinite recursion when error sending itself fails.
func TestHandleSendError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "APIError_ClientError",
			err:  testhelpers.NewErrorObject("send error"),
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
				// Get initial call count
				initialCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")

				// This function should only log, not send
				handleSendError(tt.err)

				// Verify that SubmitErrorAgent was NOT called (to prevent recursion)
				finalCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
				assert.Equal(
					t,
					initialCount,
					finalCount,
					"handleSendError should not call SendAgentError to prevent infinite recursion",
				)
			})
		})
	}
}

// TestHandleAcceptTaskError tests the handleAcceptTaskError function.
func TestHandleAcceptTaskError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "APIError_ClientError",
			err:  testhelpers.NewErrorObject("accept task error"),
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
				handleAcceptTaskError(tt.err)
				assertSubmitErrorCalledIfAPIError(t, tt.err)
			})
		})
	}
}

// TestHandleTaskError tests the handleTaskError function.
func TestHandleTaskError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		message string
	}{
		{
			name:    "APIError_ClientError",
			err:     testhelpers.NewErrorObject("task error"),
			message: "Task error occurred",
		},
		{
			name:    "SetTaskAbandonedError",
			err:     testhelpers.NewSetTaskAbandonedError("abandoned"),
			message: "Task error occurred",
		},
		{
			name:    "SetTaskAbandonedError_with_Error_fallback",
			err:     testhelpers.NewSetTaskAbandonedErrorWithErrorField("fallback error message"),
			message: "Task error occurred",
		},
		{
			name:    "SetTaskAbandonedError_with_nil_Error",
			err:     testhelpers.NewSetTaskAbandonedErrorWithNilError(),
			message: "Task error occurred",
		},
		{
			name:    "APIError_ServerError",
			err:     testhelpers.NewAPIError(http.StatusBadRequest, "server error"),
			message: "Task error occurred",
		},
		{
			name:    "generic error",
			err:     errors.New("generic error"),
			message: "Task error occurred",
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
			handleTaskError(tt.err, tt.message)

			// Verify SubmitErrorAgent was called for API error types
			var ae *api.APIError
			var sab *api.SetTaskAbandonedError
			if errors.As(tt.err, &ae) || errors.As(tt.err, &sab) {
				callCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
				assert.Positive(t, callCount)
			}
		})
	}
}

// TestHandleSendCrackError tests the handleSendCrackError function.
func TestHandleSendCrackError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "APIError_ClientError",
			err:  testhelpers.NewErrorObject("send crack error"),
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
				handleSendCrackError(tt.err)
				assertSubmitErrorCalledIfAPIError(t, tt.err)
			})
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
