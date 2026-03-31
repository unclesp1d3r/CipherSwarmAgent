// Package cserrors provides error handling and logging utilities for CipherSwarm.
package cserrors

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/apierrors"
)

// apiErrorHandler is the shared error handler instance.
// Uses sync.Once for thread-safe lazy initialization.
var (
	apiErrorHandler     *apierrors.Handler //nolint:gochecknoglobals // Singleton error handler
	apiErrorHandlerOnce sync.Once          //nolint:gochecknoglobals // Singleton initialization guard
)

// GetErrorHandler returns the shared error handler, initializing it if needed.
// Thread-safe via sync.Once.
func GetErrorHandler() *apierrors.Handler {
	apiErrorHandlerOnce.Do(func() {
		apiErrorHandler = &apierrors.Handler{
			SendError: func(ctx context.Context, message string, severity api.Severity) {
				SendAgentError(ctx, message, nil, severity)
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
	context           map[string]any
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

// WithContext adds structured context fields to the error metadata.
// Fields are merged into the metadata map alongside classification and platform info.
// Nil or empty maps are ignored.
func WithContext(ctx map[string]any) ErrorOption {
	return func(c *errorReportConfig) {
		if len(ctx) > 0 {
			c.context = ctx
		}
	}
}

// SendAgentError sends an error message to the centralized server, including metadata and severity level.
// Optional ErrorOption arguments can enhance the error with classification metadata.
// Safe to call before API client initialization — logs locally and returns if client is nil.
// Empty or whitespace-only messages are silently dropped with a Warn-level log to prevent
// noise in server logs (see issue #140).
// Callers control context: pass ctx for cancellable operations, or context.Background() for
// errors that must be delivered even during shutdown.
func SendAgentError(
	ctx context.Context,
	stdErrLine string,
	task *api.Task,
	severity api.Severity,
	opts ...ErrorOption,
) {
	apiClient := agentstate.State.GetAPIClient()
	if apiClient == nil {
		agentstate.ErrorLogger.Error("Cannot send error to server: API client not initialized",
			"message", stdErrLine, "severity", severity)

		return
	}

	if strings.TrimSpace(stdErrLine) == "" {
		agentstate.ErrorLogger.Warn("Skipping empty error message", "severity", severity)

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

	// Build typed metadata with additional properties for extensibility.
	other := buildErrorMetadataOther(cfg)

	agentError := api.SubmitErrorAgentJSONRequestBody{
		Message:  stdErrLine,
		Severity: severity,
		AgentId:  agentstate.State.AgentID,
		TaskId:   taskID,
		Metadata: &api.ErrorMetadata{
			ErrorDate: time.Now(),
			Other:     other,
		},
	}

	if _, err := apiClient.Agents().SubmitErrorAgent(
		ctx,
		agentstate.State.AgentID,
		agentError,
	); err != nil {
		handleSendError(ctx, err)
	}
}

// buildErrorMetadataOther constructs a typed ErrorMetadata_Other from the error report config.
// Well-known fields (category, retryable, error_type, affected_count, total_count, terminal)
// are mapped to their typed struct fields. All remaining context entries plus reserved keys
// (platform, version) go into AdditionalProperties.
func buildErrorMetadataOther(cfg errorReportConfig) *api.ErrorMetadata_Other {
	other := &api.ErrorMetadata_Other{
		AdditionalProperties: make(map[string]interface{}),
	}

	// Copy context fields, routing known keys to typed fields.
	for k, v := range cfg.context {
		switch k {
		case "error_type":
			if s, ok := v.(string); ok {
				other.ErrorType = &s
			}
		case "affected_count":
			if n, ok := toIntPtr(v); ok {
				other.AffectedCount = n
			}
		case "total_count":
			if n, ok := toIntPtr(v); ok {
				other.TotalCount = n
			}
		case "terminal":
			if b, ok := v.(bool); ok {
				other.Terminal = &b
			}
		default:
			other.AdditionalProperties[k] = v
		}
	}

	// Reserved keys always go to AdditionalProperties (they overwrite context collisions).
	other.AdditionalProperties["platform"] = agentstate.State.Platform
	other.AdditionalProperties["version"] = agentstate.State.AgentVersion

	if cfg.hasClassification {
		other.Category = &cfg.category
		other.Retryable = &cfg.retryable
	}

	return other
}

// toIntPtr attempts to convert a value to *int. Handles int, int64, and float64 (from JSON).
func toIntPtr(v any) (*int, bool) {
	switch n := v.(type) {
	case int:
		return &n, true
	case int64:
		i := int(n)
		return &i, true
	case float64:
		i := int(n)
		return &i, true
	default:
		return nil, false
	}
}

// handleSendError handles errors that occur during communication with the server.
// It logs the error locally but does not attempt to send errors to the server again
// to prevent infinite recursion if the error sending itself fails.
func handleSendError(ctx context.Context, err error) {
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	GetErrorHandlerNoSend().LogOnly(ctx, err, "Error sending agent error to server")
}

// LogAndSendError logs an error message with severity and sends it to the CipherSwarm API.
// When task is nil, the error is reported without a task context. API submission is
// skipped only when the APIClient has not been initialized yet.
// Empty or whitespace-only messages are handled by the centralised guard inside SendAgentError,
// so callers do not need their own empty-message check.
// Returns the original error for further handling.
// Callers control context: pass ctx for cancellable operations, or context.Background() for
// errors that must be delivered even during shutdown.
func LogAndSendError(ctx context.Context, message string, err error, severity api.Severity, task *api.Task) error {
	agentstate.ErrorLogger.Error(message, "error", err)
	// SendAgentError handles nil APIClient internally — no need to guard here.
	SendAgentError(ctx, message, task, severity)

	return err
}
