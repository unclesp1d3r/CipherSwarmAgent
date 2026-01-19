package lib

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
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

// assertSubmitErrorCalledIfSDK asserts submit_error was called when err is an SDK error type.
func assertSubmitErrorCalledIfSDK(t *testing.T, err error) {
	t.Helper()
	var se *sdkerrors.SDKError
	var eo *sdkerrors.ErrorObject
	if errors.As(err, &se) || errors.As(err, &eo) {
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
			name:        "ErrorObject",
			err:         testhelpers.NewErrorObject("authentication failed"),
			expectError: true,
		},
		{
			name:        "SDKError",
			err:         testhelpers.NewSDKError(http.StatusBadRequest, "bad request"),
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
			name:              "ErrorObject",
			err:               testhelpers.NewErrorObject("configuration error"),
			expectError:       true,
			expectSubmitError: true,
		},
		{
			name:              "SDKError",
			err:               testhelpers.NewSDKError(http.StatusBadRequest, "server error"),
			expectError:       true,
			expectSubmitError: true,
		},
		{
			name:              "generic error",
			err:               errors.New("generic error"),
			expectError:       true,
			expectSubmitError: false, // Generic errors don't call SubmitErrorAgent
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

			// Verify SubmitErrorAgent was called only for SDK error types
			// Use GetSubmitErrorCallCount helper to handle httpmock key format differences
			finalCallCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
			if tt.expectSubmitError {
				assert.Greater(t, finalCallCount, initialCallCount, "submit_error should be called for SDK error types")
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
			name:        "ErrorObject",
			message:     "API error",
			err:         testhelpers.NewErrorObject("api error"),
			expectError: false, // function doesn't return error
		},
		{
			name:        "ErrorObject for credential validation",
			message:     "API error",
			err:         ErrCouldNotValidateCredentials,
			expectError: false,
		},
		{
			name:        "SDKError for 401 Unauthorized",
			message:     "API error",
			err:         testhelpers.NewSDKError(http.StatusUnauthorized, "unauthorized"),
			expectError: false,
		},
		{
			name:        "SDKError for 403 Forbidden",
			message:     "API error",
			err:         testhelpers.NewSDKError(http.StatusForbidden, "forbidden"),
			expectError: false,
		},
		{
			name:        "SDKError for other status codes",
			message:     "API error",
			err:         testhelpers.NewSDKError(http.StatusBadRequest, "server error"),
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

			// Verify SubmitErrorAgent was called for SDK errors
			if tt.err != nil {
				var se *sdkerrors.SDKError
				var eo *sdkerrors.ErrorObject
				if errors.As(tt.err, &se) || errors.As(tt.err, &eo) {
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
			name: "ErrorObject",
			err:  testhelpers.NewErrorObject("heartbeat error"),
		},
		{
			name: "SDKError",
			err:  testhelpers.NewSDKError(http.StatusBadRequest, "server error"),
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
				assertSubmitErrorCalledIfSDK(t, tt.err)
			})
		})
	}
}

// TestHandleStatusUpdateError tests the handleStatusUpdateError function.
func TestHandleStatusUpdateError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		task *components.Task
	}{
		{
			name: "ErrorObject",
			err:  testhelpers.NewErrorObject("status update error"),
			task: testhelpers.NewTestTask(456, 789),
		},
		{
			name: "SDKError",
			err:  testhelpers.NewSDKError(http.StatusNotFound, "not found"),
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

// TestHandleSDKError tests the handleSDKError function.
func TestHandleSDKError(t *testing.T) {
	tests := []struct {
		name       string
		sdkError   *sdkerrors.SDKError
		task       *components.Task
		expectKill bool
	}{
		{
			name:       "HTTP 404 Not Found",
			sdkError:   testhelpers.NewSDKError(http.StatusNotFound, "not found"),
			task:       testhelpers.NewTestTask(456, 789),
			expectKill: true,
		},
		{
			name:       "HTTP 410 Gone",
			sdkError:   testhelpers.NewSDKError(http.StatusGone, "gone"),
			task:       testhelpers.NewTestTask(456, 789),
			expectKill: true,
		},
		{
			name:       "other status codes",
			sdkError:   testhelpers.NewSDKError(http.StatusBadRequest, "server error"),
			task:       testhelpers.NewTestTask(456, 789),
			expectKill: false,
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
			handleSDKError(tt.sdkError, tt.task, sess)

			// For 404 and 410, session should be killed - ensure function completes
			if tt.expectKill {
				// No direct assertion without deeper mocking; ensure branch is executed without panics
				t.Log("kill path exercised")
			}
		})
	}
}

// TestHandleTaskNotFound tests the handleTaskNotFound function.
func TestHandleTaskNotFound(t *testing.T) {
	tests := []struct {
		name string
		task *components.Task
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
		task *components.Task
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
		task     *components.Task
		severity operations.Severity
	}{
		{
			name:     "with nil task",
			message:  "test error",
			task:     nil,
			severity: operations.SeverityCritical,
		},
		{
			name:     "with non-nil task",
			message:  "test error",
			task:     testhelpers.NewTestTask(456, 789),
			severity: operations.SeverityCritical,
		},
		{
			name:     "different severity levels",
			message:  "test error",
			task:     nil,
			severity: operations.SeverityWarning,
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
			// According to swagger.json, the endpoint is /api/v1/client/agents/{id}/submit_error
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
			name: "ErrorObject",
			err:  testhelpers.NewErrorObject("send error"),
		},
		{
			name: "SDKError",
			err:  testhelpers.NewSDKError(http.StatusBadRequest, "server error"),
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
			name: "ErrorObject",
			err:  testhelpers.NewErrorObject("accept task error"),
		},
		{
			name: "SDKError",
			err:  testhelpers.NewSDKError(http.StatusBadRequest, "server error"),
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
				assertSubmitErrorCalledIfSDK(t, tt.err)
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
			name:    "ErrorObject",
			err:     testhelpers.NewErrorObject("task error"),
			message: "Task error occurred",
		},
		{
			name:    "SetTaskAbandonedResponseBody",
			err:     testhelpers.NewSetTaskAbandonedError("abandoned"),
			message: "Task error occurred",
		},
		{
			name:    "SDKError",
			err:     testhelpers.NewSDKError(http.StatusBadRequest, "server error"),
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

			// Verify SubmitErrorAgent was called
			var se *sdkerrors.SDKError
			var eo *sdkerrors.ErrorObject
			var sab *sdkerrors.SetTaskAbandonedResponseBody
			if errors.As(tt.err, &se) || errors.As(tt.err, &eo) || errors.As(tt.err, &sab) {
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
			name: "ErrorObject",
			err:  testhelpers.NewErrorObject("send crack error"),
		},
		{
			name: "SDKError",
			err:  testhelpers.NewSDKError(http.StatusBadRequest, "server error"),
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
				assertSubmitErrorCalledIfSDK(t, tt.err)
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
