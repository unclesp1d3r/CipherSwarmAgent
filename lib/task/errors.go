package task

import (
	stderrors "errors"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/apierrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// handleAPIError handles errors returned from the CipherSwarm API.
// It logs error messages and sends error reports based on the error type.
func handleAPIError(message string, err error) {
	opts := apierrors.Options{
		Message:      message,
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.GetErrorHandler().Handle(err, opts)
}

// handleStatusUpdateError handles specific error types during a status update and logs or processes them accordingly.
func handleStatusUpdateError(err error, task *api.Task, sess *hashcat.Session) {
	// Check for special status codes that require specific handling
	if apierrors.IsNotFoundError(err) {
		handleTaskNotFound(task, sess)
		return
	}

	if apierrors.IsGoneError(err) {
		handleTaskGone(task, sess)
		return
	}

	// For all other errors, log and send
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.LogAndSendError("Error sending status update", err, api.SeverityCritical, task)
}

// handleTaskNotFound handles the scenario where a task is not found in the system.
// It logs an error message with the task ID, attempts to kill the session, and cleans up the session.
func handleTaskNotFound(task *api.Task, sess *hashcat.Session) {
	agentstate.Logger.Error("Task not found", "task_id", task.Id)
	agentstate.Logger.Info("Killing task", "task_id", task.Id)
	agentstate.Logger.Info(
		"It is possible that multiple errors appear as the task takes some time to kill. This is expected.",
	)

	if err := sess.Kill(); err != nil {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error killing task",
			err,
			api.SeverityCritical,
			task,
		)
	}

	sess.Cleanup()
}

// handleTaskGone handles the termination of a task when it is no longer needed, ensuring the session is appropriately killed.
func handleTaskGone(task *api.Task, sess *hashcat.Session) {
	agentstate.Logger.Info("Pausing task", "task_id", task.Id)

	if err := sess.Kill(); err != nil {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error pausing task",
			err,
			api.SeverityFatal,
			task,
		)
	}

	sess.Cleanup()
}

// handleAcceptTaskError handles errors that occur when attempting to accept a task.
func handleAcceptTaskError(err error) {
	// Client errors (4xx) get Info severity, other errors get Critical
	var ae *api.APIError
	severity := api.SeverityCritical
	if stderrors.As(err, &ae) && ae.StatusCode >= 400 && ae.StatusCode < 500 {
		severity = api.SeverityInfo
	}

	opts := apierrors.Options{
		Message:      "Error accepting task",
		Severity:     severity,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.GetErrorHandler().Handle(err, opts)
}

// handleTaskError handles different types of errors encountered during task operations.
func handleTaskError(err error, message string) {
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
		cserrors.SendAgentError(e1.Error(), nil, api.SeverityWarning)
		return
	}

	opts := apierrors.Options{
		Message:      message,
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.GetErrorHandler().Handle(err, opts)
}

// handleSendCrackError processes different types of errors encountered when communicating with the CipherSwarm API.
func handleSendCrackError(err error) {
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
	cserrors.GetErrorHandler().Handle(err, opts)
}
