package task

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// withHTTPAndState sets up httpmock and shared state for tests and runs fn.
func withHTTPAndState(t *testing.T, fn func()) {
	t.Helper()
	cleanupHTTP := testhelpers.SetupHTTPMock()
	t.Cleanup(cleanupHTTP)
	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	t.Cleanup(cleanupState)
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

// TestHandleStatusUpdateError tests the handleStatusUpdateError function.
func TestHandleStatusUpdateError(t *testing.T) {
	tests := []struct {
		name             string
		err              error
		task             *api.Task
		wantCancelCalled bool
	}{
		{
			name:             "APIError_ClientError",
			err:              testhelpers.NewValidationAPIError("status update error"),
			task:             testhelpers.NewTestTask(456, 789),
			wantCancelCalled: false,
		},
		{
			name:             "APIError_NotFound",
			err:              testhelpers.NewAPIError(http.StatusNotFound, "not found"),
			task:             testhelpers.NewTestTask(456, 789),
			wantCancelCalled: true,
		},
		{
			name:             "APIError_Gone",
			err:              testhelpers.NewAPIError(http.StatusGone, "gone"),
			task:             testhelpers.NewTestTask(456, 789),
			wantCancelCalled: true,
		},
		{
			name:             "generic error",
			err:              errors.New("generic error"),
			task:             testhelpers.NewTestTask(456, 789),
			wantCancelCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			t.Cleanup(cleanupHTTP)

			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			t.Cleanup(cleanupState)

			// Mock SubmitErrorAgent endpoint
			testhelpers.MockSubmitErrorSuccess(123)

			// Create a mock session
			sess, err := testhelpers.NewMockSession("test-session")
			if err != nil {
				t.Skipf("Skipping test: failed to create mock session: %v", err)
				return
			}
			t.Cleanup(sess.Cleanup)

			cancelCalled := false
			taskCancel := func() { cancelCalled = true }

			// This function doesn't return an error
			handleStatusUpdateError(context.Background(), tt.err, tt.task, sess, taskCancel)

			assert.Equal(t, tt.wantCancelCalled, cancelCalled,
				"taskCancel invocation should match the 404/410 classification")
		})
	}
}

// TestHandleTaskNotFound asserts that a not-found task signals taskCancel so the
// event loop (the sole owner of Kill+Cleanup) tears the session down — preventing
// the P1 stall where the handler killed inline and the loop blocked until the 24h timer.
func TestHandleTaskNotFound(t *testing.T) {
	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	t.Cleanup(cleanupState)

	sess, err := testhelpers.NewMockSession("test-session")
	if err != nil {
		t.Skipf("Skipping test: failed to create mock session: %v", err)
		return
	}
	t.Cleanup(sess.Cleanup)

	cancelCalled := false
	taskCancel := func() { cancelCalled = true }

	handleTaskNotFound(context.Background(), testhelpers.NewTestTask(456, 789), sess, taskCancel)

	assert.True(t, cancelCalled, "handleTaskNotFound must signal taskCancel")
}

// TestHandleTaskGone asserts that a gone task signals taskCancel rather than
// killing the session inline.
func TestHandleTaskGone(t *testing.T) {
	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	t.Cleanup(cleanupState)

	sess, err := testhelpers.NewMockSession("test-session")
	if err != nil {
		t.Skipf("Skipping test: failed to create mock session: %v", err)
		return
	}
	t.Cleanup(sess.Cleanup)

	cancelCalled := false
	taskCancel := func() { cancelCalled = true }

	handleTaskGone(context.Background(), testhelpers.NewTestTask(456, 789), sess, taskCancel)

	assert.True(t, cancelCalled, "handleTaskGone must signal taskCancel")
}

// TestHandleAcceptTaskError tests the handleAcceptTaskError function.
func TestHandleAcceptTaskError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "APIError_ClientError",
			err:  testhelpers.NewValidationAPIError("accept task error"),
		},
		{
			name: "APIError_NotFound",
			err:  testhelpers.NewAPIError(http.StatusNotFound, "not found"),
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
				handleAcceptTaskError(context.Background(), tt.err)
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
			err:     testhelpers.NewValidationAPIError("task error"),
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
			t.Cleanup(cleanupHTTP)

			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			t.Cleanup(cleanupState)

			// Mock SubmitErrorAgent endpoint
			testhelpers.MockSubmitErrorSuccess(123)

			// This function doesn't return an error
			handleTaskError(context.Background(), tt.err, tt.message)

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
			err:  testhelpers.NewValidationAPIError("send crack error"),
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
				handleSendCrackError(context.Background(), tt.err)
				assertSubmitErrorCalledIfAPIError(t, tt.err)
			})
		})
	}
}
