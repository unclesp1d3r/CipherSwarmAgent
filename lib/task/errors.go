package task

import (
	"context"
	stderrors "errors"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/apierrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// handleAPIError handles errors returned from the CipherSwarm API.
// It logs error messages and sends error reports based on the error type.
func handleAPIError(ctx context.Context, message string, err error) {
	opts := apierrors.Options{
		Message:      message,
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.GetErrorHandler().Handle(ctx, err, opts)
}

// handleStatusUpdateError handles specific error types during a status update and logs or processes them accordingly.
// On task-not-found (404) or task-gone (410), it cancels taskCtx via taskCancel so the event loop tears the
// session down through its single Kill+Cleanup path, rather than killing the session inline (which left the
// loop blocked until the 24h task timer).
func handleStatusUpdateError(
	ctx context.Context,
	err error,
	task *api.Task,
	sess *hashcat.Session,
	taskCancel context.CancelFunc,
) {
	// Check for special status codes that require specific handling
	if apierrors.IsNotFoundError(err) {
		handleTaskNotFound(ctx, task, sess, taskCancel)
		return
	}

	if apierrors.IsGoneError(err) {
		handleTaskGone(ctx, task, sess, taskCancel)
		return
	}

	// For all other errors, log and send
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.LogAndSendError(ctx, "Error sending status update", err, api.SeverityCritical, task)
}

// handleTaskNotFound handles the scenario where a task is not found in the system.
// It logs the cancellation and signals taskCancel; the event loop owns Kill+Cleanup
// via its <-taskCtx.Done() branch. The sess parameter is retained for symmetry and
// future diagnostics.
func handleTaskNotFound(_ context.Context, task *api.Task, _ *hashcat.Session, taskCancel context.CancelFunc) {
	agentstate.Logger.Error("Task not found", "task_id", task.Id)
	agentstate.Logger.Info("Cancelling task", "task_id", task.Id)

	taskCancel()
}

// handleTaskGone handles the termination of a task when it is no longer needed,
// signalling taskCancel so the event loop tears the session down on its own.
func handleTaskGone(_ context.Context, task *api.Task, _ *hashcat.Session, taskCancel context.CancelFunc) {
	agentstate.Logger.Info("Pausing task", "task_id", task.Id)

	taskCancel()
}

// handleAcceptTaskError handles errors that occur when attempting to accept a task.
func handleAcceptTaskError(ctx context.Context, err error) {
	severity := api.SeverityCritical
	message := "Error accepting task"

	if apierrors.IsNotFoundError(err) {
		severity = api.SeverityInfo
		message = "Task no longer exists on server"
	}

	opts := apierrors.Options{
		Message:      message,
		Severity:     severity,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.GetErrorHandler().Handle(ctx, err, opts)
}

// handleTaskError handles different types of errors encountered during task operations.
func handleTaskError(ctx context.Context, err error, message string) {
	// Handle SetTaskAbandonedError specially
	var e1 *api.SetTaskAbandonedError
	if stderrors.As(err, &e1) {
		details := e1.Details
		// If Details is empty, fall back to Error_ field
		if len(details) == 0 && e1.Error_ != nil && *e1.Error_ != "" {
			details = []string{*e1.Error_}
		}
		agentstate.Logger.Error(
			"Notified server of task abandonment, but it could not update the task properly",
			"details",
			details,
		)
		errMsg := e1.Error()
		if strings.TrimSpace(errMsg) == "" {
			agentstate.Logger.Warn("SetTaskAbandonedError has no message to report")
			return
		}
		cserrors.SendAgentError(ctx, errMsg, nil, api.SeverityWarning)
		return
	}

	opts := apierrors.Options{
		Message:      message,
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.GetErrorHandler().Handle(ctx, err, opts)
}

// handleSendCrackError processes different types of errors encountered when communicating with the CipherSwarm API.
func handleSendCrackError(ctx context.Context, err error) {
	// Client errors (4xx) get Major severity, other errors get Critical
	var ae *api.APIError
	severity := api.SeverityCritical
	message := "Error sending cracked hash to server"
	if stderrors.As(err, &ae) && ae.StatusCode >= 400 && ae.StatusCode < 500 {
		severity = api.SeverityMajor
		message = "Error notifying server of cracked hash, task not found"
	}

	opts := apierrors.Options{
		Message:      message,
		Severity:     severity,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.GetErrorHandler().Handle(ctx, err, opts)
}
