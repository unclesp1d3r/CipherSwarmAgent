// Package cserrors provides error handling and logging utilities for CipherSwarm.
package cserrors

import (
	"context"
	"sync"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/apierrors"
)

// apiErrorHandler is the shared error handler instance.
// It's initialized lazily to avoid circular dependency with SendAgentError.
// Uses sync.Once for thread-safe initialization.
var (
	apiErrorHandler     *apierrors.Handler //nolint:gochecknoglobals // Singleton error handler
	apiErrorHandlerOnce sync.Once          //nolint:gochecknoglobals // Singleton initialization guard
)

// GetErrorHandler returns the shared error handler, initializing it if needed.
// Thread-safe via sync.Once.
func GetErrorHandler() *apierrors.Handler {
	apiErrorHandlerOnce.Do(func() {
		apiErrorHandler = &apierrors.Handler{
			SendError: func(message string, severity api.Severity) {
				SendAgentError(message, nil, severity)
			},
		}
	})
	return apiErrorHandler
}

// GetErrorHandlerNoSend returns an error handler that only logs (no server send).
// Used to prevent infinite recursion when error sending fails.
func GetErrorHandlerNoSend() *apierrors.Handler {
	return &apierrors.Handler{
		SendError: nil,
	}
}

// errorReportConfig holds optional configuration for error reporting.
type errorReportConfig struct {
	category          string
	retryable         bool
	hasClassification bool
}

// ErrorOption configures optional error reporting behavior.
type ErrorOption func(*errorReportConfig)

// WithClassification adds error classification metadata (category and retryable flag)
// for better error handling on the server side.
func WithClassification(category string, retryable bool) ErrorOption {
	return func(c *errorReportConfig) {
		c.category = category
		c.retryable = retryable
		c.hasClassification = true
	}
}

// SendAgentError sends an error message to the centralized server, including metadata and severity level.
// Optional ErrorOption arguments can enhance the error with classification metadata.
// Safe to call before API client initialization — logs locally and returns if client is nil.
func SendAgentError(stdErrLine string, task *api.Task, severity api.Severity, opts ...ErrorOption) {
	if agentstate.State.APIClient == nil {
		agentstate.ErrorLogger.Error("Cannot send error to server: API client not initialized",
			"message", stdErrLine, "severity", severity)

		return
	}

	var cfg errorReportConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	var taskID *int64
	if task != nil {
		taskID = &task.Id
	}

	otherMap := map[string]any{
		"platform": agentstate.State.Platform,
		"version":  agentstate.State.AgentVersion,
	}

	if cfg.hasClassification {
		otherMap["category"] = cfg.category
		otherMap["retryable"] = cfg.retryable
	}

	agentError := api.SubmitErrorAgentJSONRequestBody{
		Message:  stdErrLine,
		Severity: severity,
		AgentId:  agentstate.State.AgentID,
		TaskId:   taskID,
		Metadata: &struct {
			ErrorDate time.Time       `json:"error_date"`
			Other     *map[string]any `json:"other"`
		}{
			ErrorDate: time.Now(),
			Other:     &otherMap,
		},
	}

	if _, err := agentstate.State.APIClient.Agents().SubmitErrorAgent(
		context.Background(),
		agentstate.State.AgentID,
		agentError,
	); err != nil {
		handleSendError(err)
	}
}

// handleSendError handles errors that occur during communication with the server.
// It logs the error locally but does not attempt to send errors to the server again
// to prevent infinite recursion if the error sending itself fails.
func handleSendError(err error) {
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	GetErrorHandlerNoSend().LogOnly(err, "Error sending agent error to server")
}

// LogAndSendError logs an error message with severity and sends it to the CipherSwarm API.
// When task is nil, the error is reported without a task context. API submission is
// skipped only when the APIClient has not been initialized yet.
// Returns the original error for further handling.
//
// Uses context.Background() because these errors must be delivered even during shutdown.
func LogAndSendError(message string, err error, severity api.Severity, task *api.Task) error {
	agentstate.ErrorLogger.Error(message, "error", err)

	if agentstate.State.APIClient != nil {
		SendAgentError(message, task, severity)
	}

	return err
}
