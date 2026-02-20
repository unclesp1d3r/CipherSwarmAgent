package apierrors

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

const testErrorMessage = "test error"

// setupTestState sets up a minimal test state for the handler tests.
func setupTestState() func() {
	// Save original values
	originalAgentID := agentstate.State.AgentID
	originalURL := agentstate.State.URL
	originalAPIToken := agentstate.State.APIToken

	// Set test values
	agentstate.State.AgentID = 123
	agentstate.State.URL = "https://test.api"
	agentstate.State.APIToken = "test-token"

	return func() {
		// Restore original values
		agentstate.State.AgentID = originalAgentID
		agentstate.State.URL = originalURL
		agentstate.State.APIToken = originalAPIToken
	}
}

func TestHandler_Handle_NilError(t *testing.T) {
	t.Parallel()

	h := &Handler{}
	opts := DefaultOptions("test message")

	result := h.Handle(nil, opts)

	assert.NoError(t, result)
}

func TestHandler_Handle_APIError_ClientError(t *testing.T) {
	cleanup := setupTestState()
	defer cleanup()

	var sentMessage string
	var sentSeverity api.Severity

	h := &Handler{
		SendError: func(message string, severity api.Severity) {
			sentMessage = message
			sentSeverity = severity
		},
	}

	apiErr := &api.APIError{
		StatusCode: http.StatusUnprocessableEntity,
		Message:    testErrorMessage,
	}

	opts := Options{
		Message:      "API error occurred",
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}

	result := h.Handle(apiErr, opts)

	require.Error(t, result)
	assert.NotEmpty(t, sentMessage)
	assert.Equal(t, api.SeverityCritical, sentSeverity)
}

func TestHandler_Handle_APIError_ServerError(t *testing.T) {
	cleanup := setupTestState()
	defer cleanup()

	var sentMessage string
	var sentSeverity api.Severity

	h := &Handler{
		SendError: func(message string, severity api.Severity) {
			sentMessage = message
			sentSeverity = severity
		},
	}

	apiErr := &api.APIError{
		StatusCode: http.StatusInternalServerError,
		Message:    "internal server error",
	}

	opts := Options{
		Message:      "API error occurred",
		Severity:     api.SeverityMajor,
		SendToServer: true,
	}

	result := h.Handle(apiErr, opts)

	require.Error(t, result)
	assert.NotEmpty(t, sentMessage)
	assert.Equal(t, api.SeverityMajor, sentSeverity)
}

func TestHandler_Handle_APIError_AuthRelated(t *testing.T) {
	cleanup := setupTestState()
	defer cleanup()

	h := &Handler{
		SendError: func(_ string, _ api.Severity) {},
	}

	testCases := []struct {
		name       string
		statusCode int
	}{
		{"Unauthorized", http.StatusUnauthorized},
		{"Forbidden", http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiErr := &api.APIError{
				StatusCode: tc.statusCode,
				Message:    "auth error",
			}

			opts := Options{
				Message:      "Auth error",
				Severity:     api.SeverityCritical,
				SendToServer: true,
			}

			result := h.Handle(apiErr, opts)
			require.Error(t, result)
		})
	}
}

func TestHandler_Handle_GenericError(t *testing.T) {
	cleanup := setupTestState()
	defer cleanup()

	sendCalled := false
	h := &Handler{
		SendError: func(_ string, _ api.Severity) {
			sendCalled = true
		},
	}

	genericErr := errors.New("generic error")

	opts := Options{
		Message:      "Generic error occurred",
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}

	result := h.Handle(genericErr, opts)

	require.Error(t, result)
	// Generic errors should also trigger SendError for server visibility
	assert.True(t, sendCalled)
}

func TestHandler_Handle_NoSendToServer(t *testing.T) {
	cleanup := setupTestState()
	defer cleanup()

	sendCalled := false
	h := &Handler{
		SendError: func(_ string, _ api.Severity) {
			sendCalled = true
		},
	}

	apiErr := &api.APIError{
		StatusCode: http.StatusUnprocessableEntity,
		Message:    testErrorMessage,
	}

	opts := Options{
		Message:      "Error",
		Severity:     api.SeverityCritical,
		SendToServer: false,
	}

	err := h.Handle(apiErr, opts)
	require.Error(t, err)

	assert.False(t, sendCalled, "SendError should not be called when SendToServer is false")
}

func TestHandler_Handle_NilSendError(t *testing.T) {
	cleanup := setupTestState()
	defer cleanup()

	h := &Handler{
		SendError: nil,
	}

	apiErr := &api.APIError{
		StatusCode: http.StatusUnprocessableEntity,
		Message:    testErrorMessage,
	}

	opts := Options{
		Message:      "Error",
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}

	// Should not panic even with nil SendError
	result := h.Handle(apiErr, opts)
	require.Error(t, result)
}

func TestHandler_LogOnly(t *testing.T) {
	cleanup := setupTestState()
	defer cleanup()

	sendCalled := false
	h := &Handler{
		SendError: func(_ string, _ api.Severity) {
			sendCalled = true
		},
	}

	err := errors.New(testErrorMessage)
	result := h.LogOnly(err, "Log only message")

	require.Error(t, result)
	assert.False(t, sendCalled, "SendError should not be called for LogOnly")
}

func TestHandler_HandleWithSeverity(t *testing.T) {
	cleanup := setupTestState()
	defer cleanup()

	var sentSeverity api.Severity

	h := &Handler{
		SendError: func(_ string, severity api.Severity) {
			sentSeverity = severity
		},
	}

	apiErr := &api.APIError{
		StatusCode: http.StatusUnprocessableEntity,
		Message:    testErrorMessage,
	}

	err := h.HandleWithSeverity(apiErr, "Test message", api.SeverityWarning)
	require.Error(t, err)

	assert.Equal(t, api.SeverityWarning, sentSeverity)
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions("test message")

	assert.Equal(t, "test message", opts.Message)
	assert.Equal(t, api.SeverityCritical, opts.Severity)
	assert.True(t, opts.SendToServer)
	assert.False(t, opts.LogAuthContext)
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "NotFound APIError",
			err:      &api.APIError{StatusCode: http.StatusNotFound},
			expected: true,
		},
		{
			name:     "Other APIError",
			err:      &api.APIError{StatusCode: http.StatusInternalServerError},
			expected: false,
		},
		{
			name:     "Generic error",
			err:      errors.New("not found"),
			expected: false,
		},
		{
			name:     "Nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNotFoundError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsGoneError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Gone APIError",
			err:      &api.APIError{StatusCode: http.StatusGone},
			expected: true,
		},
		{
			name:     "Other APIError",
			err:      &api.APIError{StatusCode: http.StatusNotFound},
			expected: false,
		},
		{
			name:     "Generic error",
			err:      errors.New("gone"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsGoneError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetStatusCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "APIError with status",
			err:      &api.APIError{StatusCode: http.StatusBadRequest},
			expected: http.StatusBadRequest,
		},
		{
			name:     "Generic error",
			err:      errors.New("generic"),
			expected: 0,
		},
		{
			name:     "Nil error",
			err:      nil,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetStatusCode(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHandler_Handle_WithAuthContext(t *testing.T) {
	cleanup := setupTestState()
	defer cleanup()

	h := &Handler{
		SendError: func(_ string, _ api.Severity) {},
	}

	apiErr := &api.APIError{
		StatusCode: http.StatusUnprocessableEntity,
		Message:    testErrorMessage,
	}

	opts := Options{
		Message:        "Auth error",
		Severity:       api.SeverityCritical,
		SendToServer:   true,
		LogAuthContext: true,
	}

	// Should not panic and should log with auth context
	result := h.Handle(apiErr, opts)
	require.Error(t, result)
}
