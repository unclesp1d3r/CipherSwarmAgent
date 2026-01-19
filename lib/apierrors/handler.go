// Package apierrors provides unified error handling for CipherSwarm API interactions.
package apierrors

import (
	stderrors "errors"
	"net/http"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// ErrorSender is a function type for sending errors to the server.
// This allows dependency injection for testing and prevents circular imports.
type ErrorSender func(message string, severity operations.Severity)

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
	Severity operations.Severity
	// SendToServer indicates whether to send the error to the server.
	SendToServer bool
	// LogAuthContext adds agent_id, api_url, has_token to auth-related errors.
	LogAuthContext bool
}

// DefaultOptions returns Options with sensible defaults.
func DefaultOptions(message string) Options {
	return Options{
		Message:        message,
		Severity:       operations.SeverityCritical,
		SendToServer:   true,
		LogAuthContext: false,
	}
}

// Handle processes an API error according to the provided options.
// It extracts error details from SDK error types and logs/reports appropriately.
// Returns the original error for chaining.
func (h *Handler) Handle(err error, opts Options) error {
	if err == nil {
		return nil
	}

	var eo *sdkerrors.ErrorObject
	var se *sdkerrors.SDKError

	switch {
	case stderrors.As(err, &eo):
		h.handleErrorObject(eo, opts)
	case stderrors.As(err, &se):
		h.handleSDKError(se, opts)
	default:
		agentstate.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
	}

	return err
}

// handleErrorObject handles sdkerrors.ErrorObject type errors.
func (h *Handler) handleErrorObject(eo *sdkerrors.ErrorObject, opts Options) {
	if opts.LogAuthContext {
		agentstate.Logger.Error(opts.Message,
			"error", eo.Error(),
			"agent_id", agentstate.State.AgentID,
			"api_url", agentstate.State.URL,
			"has_token", agentstate.State.APIToken != "")
	} else {
		agentstate.Logger.Error(opts.Message, "error", eo.Error())
	}

	if opts.SendToServer && h.SendError != nil {
		h.SendError(eo.Error(), opts.Severity)
	}
}

// handleSDKError handles sdkerrors.SDKError type errors.
func (h *Handler) handleSDKError(se *sdkerrors.SDKError, opts Options) {
	isAuthError := se.StatusCode == http.StatusUnauthorized || se.StatusCode == http.StatusForbidden

	if opts.LogAuthContext || isAuthError {
		agentstate.Logger.Error(opts.Message,
			"status_code", se.StatusCode,
			"message", se.Message,
			"agent_id", agentstate.State.AgentID,
			"api_url", agentstate.State.URL,
			"has_token", agentstate.State.APIToken != "")
	} else {
		agentstate.Logger.Error(opts.Message+", unexpected error",
			"status_code", se.StatusCode,
			"message", se.Message)
	}

	if opts.SendToServer && h.SendError != nil {
		h.SendError(se.Error(), opts.Severity)
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
func (h *Handler) HandleWithSeverity(err error, message string, severity operations.Severity) error {
	opts := Options{
		Message:      message,
		Severity:     severity,
		SendToServer: true,
	}
	return h.Handle(err, opts)
}

// IsNotFoundError checks if the error is a 404 Not Found error.
func IsNotFoundError(err error) bool {
	var se *sdkerrors.SDKError
	if stderrors.As(err, &se) {
		return se.StatusCode == http.StatusNotFound
	}
	return false
}

// IsGoneError checks if the error is a 410 Gone error.
func IsGoneError(err error) bool {
	var se *sdkerrors.SDKError
	if stderrors.As(err, &se) {
		return se.StatusCode == http.StatusGone
	}
	return false
}

// GetStatusCode extracts the HTTP status code from an SDK error.
// Returns 0 if the error is not an SDKError.
func GetStatusCode(err error) int {
	var se *sdkerrors.SDKError
	if stderrors.As(err, &se) {
		return se.StatusCode
	}
	return 0
}
