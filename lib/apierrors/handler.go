// Package apierrors provides unified error handling for CipherSwarm API interactions.
package apierrors

import (
	"context"
	stderrors "errors"
	"net/http"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// ErrorSender is a function type for sending errors to the server.
// This allows dependency injection for testing and prevents circular imports.
type ErrorSender func(message string, severity api.Severity)

// Handler provides unified error handling for API operations.
type Handler struct {
	// SendError is the function to call for sending errors to the server.
	// If nil, errors are only logged locally.
	SendError ErrorSender
}

// Options configures how an error should be handled.
type Options struct {
	// Message is the context message to log with the error.
	Message string
	// Severity is the severity level for the error report.
	Severity api.Severity
	// SendToServer indicates whether to send the error to the server.
	SendToServer bool
	// LogAuthContext adds agent_id, api_url, has_token to auth-related errors.
	LogAuthContext bool
}

// DefaultOptions returns Options with sensible defaults.
func DefaultOptions(message string) Options {
	return Options{
		Message:        message,
		Severity:       api.SeverityCritical,
		SendToServer:   true,
		LogAuthContext: false,
	}
}

// Handle processes an API error according to the provided options.
// It extracts error details from API error types and logs/reports appropriately.
// Returns the original error for chaining.
func (h *Handler) Handle(err error, opts Options) error {
	if err == nil {
		return nil
	}

	var ae *api.APIError

	switch {
	case stderrors.As(err, &ae):
		h.handleAPIError(ae, opts)
	default:
		agentstate.ErrorLogger.Error(opts.Message, "error", err)
		// Skip server reporting for context cancellation (expected during shutdown)
		if stderrors.Is(err, context.Canceled) || stderrors.Is(err, context.DeadlineExceeded) {
			break
		}
		if opts.SendToServer && h.SendError != nil {
			h.SendError(err.Error(), opts.Severity)
		}
	}

	return err
}

// handleAPIError handles *api.APIError type errors.
func (h *Handler) handleAPIError(ae *api.APIError, opts Options) {
	isAuthError := ae.StatusCode == http.StatusUnauthorized || ae.StatusCode == http.StatusForbidden

	if opts.LogAuthContext || isAuthError {
		agentstate.Logger.Error(opts.Message,
			"status_code", ae.StatusCode,
			"message", ae.Message,
			"agent_id", agentstate.State.AgentID,
			"api_url", agentstate.State.URL,
			"has_token", agentstate.State.APIToken != "")
	} else {
		agentstate.Logger.Error(opts.Message,
			"status_code", ae.StatusCode,
			"message", ae.Message)
	}

	if opts.SendToServer && h.SendError != nil {
		h.SendError(ae.Error(), opts.Severity)
	}
}

// LogOnly logs an error without sending to the server.
// Useful for preventing infinite recursion when error sending fails.
func (h *Handler) LogOnly(err error, message string) error {
	opts := Options{
		Message:      message,
		SendToServer: false,
	}
	return h.Handle(err, opts)
}

// HandleWithSeverity handles an error with a specific severity level.
func (h *Handler) HandleWithSeverity(err error, message string, severity api.Severity) error {
	opts := Options{
		Message:      message,
		Severity:     severity,
		SendToServer: true,
	}
	return h.Handle(err, opts)
}

// IsNotFoundError checks if the error is a 404 Not Found error.
func IsNotFoundError(err error) bool {
	var ae *api.APIError
	if stderrors.As(err, &ae) {
		return ae.StatusCode == http.StatusNotFound
	}
	return false
}

// IsGoneError checks if the error is a 410 Gone error.
func IsGoneError(err error) bool {
	var ae *api.APIError
	if stderrors.As(err, &ae) {
		return ae.StatusCode == http.StatusGone
	}
	return false
}

// GetStatusCode extracts the HTTP status code from an API error.
// Returns 0 if the error is not an APIError.
func GetStatusCode(err error) int {
	var ae *api.APIError
	if stderrors.As(err, &ae) {
		return ae.StatusCode
	}
	return 0
}
