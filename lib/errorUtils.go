package lib

import (
	"context"
	stderrors "errors"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/downloader"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/state"
)

// Static errors to comply with err113 linter.
var (
	ErrCouldNotValidateCredentials = stderrors.New("could not validate credentials")
)

// handleAuthenticationError handles authentication errors from the CipherSwarm API.
// It logs detailed error information based on the type of error and returns the original error.
func handleAuthenticationError(err error) error {
	var eo *sdkerrors.ErrorObject
	if stderrors.As(err, &eo) {
		state.Logger.Error("Error connecting to the CipherSwarm API", "error", eo.Error())

		return err
	}

	var se *sdkerrors.SDKError
	if stderrors.As(err, &se) {
		state.Logger.Error("Error connecting to the CipherSwarm API, unexpected error",
			"status_code", se.StatusCode,
			"message", se.Message)

		return err
	}

	state.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)

	return err
}

// handleConfigurationError processes configuration errors by logging them and sending critical error reports.
// If the error is an sdkerrors.ErrorObject, logs the error and sends a critical error report.
// If the error is an sdkerrors.SDKError, logs the error with status code and message, and sends a critical error report.
// For all other errors, logs a critical communication error with the CipherSwarm API.
func handleConfigurationError(err error) error {
	var eo *sdkerrors.ErrorObject
	if stderrors.As(err, &eo) {
		state.Logger.Error("Error getting agent configuration", "error", eo.Error())
		SendAgentError(eo.Error(), nil, operations.SeverityCritical)

		return err
	}

	var se *sdkerrors.SDKError
	if stderrors.As(err, &se) {
		state.Logger.Error("Error getting agent configuration, unexpected error",
			"status_code", se.StatusCode,
			"message", se.Message)
		SendAgentError(se.Error(), nil, operations.SeverityCritical)

		return err
	}

	state.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)

	return err
}

// handleCrackerUpdate manages the process of updating the cracker tool.
// It follows these steps:
// 1. Logs the new cracker update information.
// 2. Creates a temporary directory for download and extraction.
// 3. Downloads the cracker archive from the provided URL.
// 4. Moves the downloaded archive to a predefined location.
// 5. Extracts the archive to replace the old cracker directory.
// 6. Validates the new cracker directory and executable.
// 7. Updates the configuration with the new executable path.
// Returns an error if any step in the process fails.
func handleCrackerUpdate(update *components.CrackerUpdate) error {
	DisplayNewCrackerAvailable(update)

	tempDir, err := os.MkdirTemp("", "cipherswarm-*")
	if err != nil {
		return cserrors.LogAndSendError("Error creating temporary directory", err, operations.SeverityCritical, nil)
	}
	defer func(tempDir string) {
		_ = downloader.CleanupTempDir(tempDir) //nolint:errcheck // Cleanup in defer, error not critical
	}(tempDir)

	tempArchivePath := path.Join(tempDir, "hashcat.7z")
	if err := downloader.DownloadFile(*update.GetDownloadURL(), tempArchivePath, ""); err != nil {
		return cserrors.LogAndSendError("Error downloading cracker", err, operations.SeverityCritical, nil)
	}

	newArchivePath, err := cracker.MoveArchiveFile(tempArchivePath)
	if err != nil {
		return cserrors.LogAndSendError("Error moving file", err, operations.SeverityCritical, nil)
	}

	hashcatDirectory, err := cracker.ExtractHashcatArchive(context.Background(), newArchivePath)
	if err != nil {
		return cserrors.LogAndSendError("Error extracting file", err, operations.SeverityCritical, nil)
	}

	if !validateHashcatDirectory(hashcatDirectory, *update.GetExecName()) {
		return nil
	}

	if err := os.Remove(newArchivePath); err != nil {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error removing 7z file",
			err,
			operations.SeverityWarning,
			nil,
		)
	}

	viper.Set("hashcat_path", path.Join(state.State.CrackersPath, "hashcat", *update.GetExecName()))
	_ = viper.WriteConfig() //nolint:errcheck // Config write failure not critical

	return nil
}

// handleAPIError handles errors returned from the CipherSwarm API. Logs error messages and sends error reports based on the error type.
// Parameters:
// - message: Description of the error context.
// - err: The original error object encountered.
func handleAPIError(message string, err error) {
	{
		var (
			e  *sdkerrors.ErrorObject
			e1 *sdkerrors.SDKError
		)

		switch {
		case stderrors.As(err, &e):
			// Enhanced logging for credential validation errors
			if stderrors.Is(err, ErrCouldNotValidateCredentials) {
				state.Logger.Error(message+" - credentials validation failed",
					"error", e.Error(),
					"agent_id", state.State.AgentID,
					"api_url", state.State.URL,
					"has_token", state.State.APIToken != "")
			} else {
				state.Logger.Error(message, "error", e.Error())
			}

			SendAgentError(e.Error(), nil, operations.SeverityCritical)
		case stderrors.As(err, &e1):
			// Enhanced logging for HTTP status errors that might indicate auth issues
			if e1.StatusCode == http.StatusUnauthorized || e1.StatusCode == http.StatusForbidden {
				state.Logger.Error(message+" - authentication/authorization error",
					"status_code", e1.StatusCode,
					"message", e1.Message,
					"agent_id", state.State.AgentID,
					"api_url", state.State.URL,
					"has_token", state.State.APIToken != "")
			} else {
				state.Logger.Error(message+", unexpected error", "status_code", e1.StatusCode, "message", e1.Message)
			}

			SendAgentError(e1.Error(), nil, operations.SeverityCritical)
		default:
			state.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		}
	}
}

// handleHeartbeatError processes and logs errors occurring during the heartbeat operation.
// It handles different types of errors and manages logging and reporting based on severity.
// - For *sdkerrors.ErrorObject: logs a critical error and sends a critical agent error message.
// - For *sdkerrors.SDKError: logs an unexpected error with status code and message, and sends a critical agent error message.
// - For all other errors: logs a critical communication error with the CipherSwarm API.
func handleHeartbeatError(err error) {
	{
		var (
			e  *sdkerrors.ErrorObject
			e1 *sdkerrors.SDKError
		)

		switch {
		case stderrors.As(err, &e):
			//nolint:errcheck // Error already being handled
			_ = cserrors.LogAndSendError(
				"Error sending heartbeat",
				e,
				operations.SeverityCritical,
				nil,
			)
		case stderrors.As(err, &e1):
			state.Logger.Error(
				"Error sending heartbeat, unexpected error",
				"status_code",
				e1.StatusCode,
				"message",
				e1.Message,
			)
			SendAgentError(e1.Error(), nil, operations.SeverityCritical)
		default:
			state.ErrorLogger.Error("Error communicating with the CipherSwarm API", "error", err)
		}
	}
}

// handleStatusUpdateError handles specific error types during a status update and logs or processes them accordingly.
func handleStatusUpdateError(err error, task *components.Task, sess *hashcat.Session) {
	var eo *sdkerrors.ErrorObject
	if stderrors.As(err, &eo) {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error sending status update",
			eo,
			operations.SeverityCritical,
			task,
		)

		return
	}

	var se *sdkerrors.SDKError
	if stderrors.As(err, &se) {
		handleSDKError(se, task, sess)

		return
	}

	state.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
}

// handleSDKError handles errors from the SDK by taking appropriate action based on the error's status code.
func handleSDKError(se *sdkerrors.SDKError, task *components.Task, sess *hashcat.Session) {
	switch se.StatusCode {
	case http.StatusNotFound:
		// Not an error, just log and kill the task
		handleTaskNotFound(task, sess)
	case http.StatusGone:
		// Not an error, just log and pause the task
		handleTaskGone(task, sess)
	default:
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error connecting to the CipherSwarm API, unexpected error",
			se,
			operations.SeverityCritical,
			task,
		)
	}
}

// handleTaskNotFound handles the scenario where a task is not found in the system.
// It logs an error message with the task ID, attempts to kill the session, and cleans up the session.
// If killing the session fails, it logs and sends an error.
func handleTaskNotFound(task *components.Task, sess *hashcat.Session) {
	state.Logger.Error("Task not found", "task_id", task.GetID())
	state.Logger.Info("Killing task", "task_id", task.GetID())
	state.Logger.Info(
		"It is possible that multiple errors appear as the task takes some time to kill. This is expected.",
	)

	if err := sess.Kill(); err != nil {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error killing task",
			err,
			operations.SeverityCritical,
			task,
		)
	}

	sess.Cleanup()
}

// handleTaskGone handles the termination of a task when it is no longer needed, ensuring the session is appropriately killed.
func handleTaskGone(task *components.Task, sess *hashcat.Session) {
	state.Logger.Info("Pausing task", "task_id", task.GetID())

	if err := sess.Kill(); err != nil {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error pausing task",
			err,
			operations.SeverityFatal,
			task,
		)
	}
}

// SendAgentError sends an error message to the centralized server, including metadata and severity level.
// - stdErrLine: The error message string to send.
// - task: Pointer to the task associated with the error, can be nil.
// - severity: The severity level of the error (e.g., critical, warning).
// The function prepares metadata including platform and agent version details, constructs the request body,
// and sends it to the server using the SDK client. If the sending fails, it handles the error accordingly.
func SendAgentError(stdErrLine string, task *components.Task, severity operations.Severity) {
	var taskID *int64
	if task != nil {
		taskID = &task.ID
	}

	metadata := &operations.Metadata{
		ErrorDate: time.Now(),
		Other: map[string]any{
			"platform": agentPlatform,
			"version":  AgentVersion,
		},
	}

	agentError := &operations.SubmitErrorAgentRequestBody{
		Message:  stdErrLine,
		Metadata: metadata,
		Severity: severity,
		AgentID:  state.State.AgentID,
		TaskID:   taskID,
	}

	if _, err := state.State.SdkClient.Agents.SubmitErrorAgent(context.Background(), state.State.AgentID, agentError); err != nil {
		handleSendError(err)
	}
}

// handleSendError handles errors that occur during communication with the server.
// It logs the error locally and attempts to send critical errors to the server.
func handleSendError(err error) {
	{
		var (
			e  *sdkerrors.ErrorObject
			e1 *sdkerrors.SDKError
		)

		switch {
		case stderrors.As(err, &e):
			state.Logger.Error("Error sending agent error to server", "error", e.Error())
			SendAgentError(e.Error(), nil, operations.SeverityCritical)
		case stderrors.As(err, &e1):
			state.Logger.Error(
				"Error sending agent error to server, unexpected error",
				"status_code",
				e1.StatusCode,
				"message",
				e1.Message,
			)
			SendAgentError(e1.Error(), nil, operations.SeverityCritical)
		default:
			state.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		}
	}
}

// handleAcceptTaskError handles errors that occur when attempting to accept a task.
// It distinguishes between different error types and logs messages accordingly.
// For specific SDK errors, it logs the error and sends an info-severity agent error.
// For unexpected SDK errors, it logs the error including status code and message, and sends a critical-severity agent error.
// For all other errors, it logs a critical communication error.
func handleAcceptTaskError(err error) {
	{
		var (
			e  *sdkerrors.ErrorObject
			e1 *sdkerrors.SDKError
		)

		switch {
		case stderrors.As(err, &e):
			state.Logger.Error("Error accepting task", "error", e.Error())
			SendAgentError(e.Error(), nil, operations.SeverityInfo)
		case stderrors.As(err, &e1):
			state.Logger.Error(
				"Error accepting task, unexpected error",
				"status_code",
				e1.StatusCode,
				"message",
				e1.Message,
			)
			SendAgentError(e1.Error(), nil, operations.SeverityCritical)
		default:
			state.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		}
	}
}

// handleTaskError handles different types of errors encountered during task operations and logs appropriate messages.
// It sends error details to a centralized server based on the error's severity level.
func handleTaskError(err error, message string) {
	{
		var (
			e  *sdkerrors.ErrorObject
			e1 *sdkerrors.SetTaskAbandonedResponseBody
			e2 *sdkerrors.SDKError
		)

		switch {
		case stderrors.As(err, &e):
			state.Logger.Error(message, "error", e.Error())
			SendAgentError(e.Error(), nil, operations.SeverityCritical)
		case stderrors.As(err, &e1):
			state.Logger.Error(
				"Notified server of task abandonment, but it could not update the task properly",
				"error",
				e1.State,
			)
			SendAgentError(e1.Error(), nil, operations.SeverityWarning)
		case stderrors.As(err, &e2):
			state.Logger.Error(message, "status_code", e2.StatusCode, "message", e2.Message)
			SendAgentError(e2.Error(), nil, operations.SeverityCritical)
		default:
			state.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		}
	}
}

// handleSendCrackError processes different types of errors encountered when communicating with the CipherSwarm API.
// Logs errors based on their type and reports major or critical severity, or logs a critical error for unknown types.
func handleSendCrackError(err error) {
	{
		var (
			e  *sdkerrors.ErrorObject
			e1 *sdkerrors.SDKError
		)

		switch {
		case stderrors.As(err, &e):
			state.Logger.Error("Error notifying server of cracked hash, task not found", "error", e.Error())
			SendAgentError(e.Error(), nil, operations.SeverityMajor)
		case stderrors.As(err, &e1):
			state.Logger.Error(
				"Error sending cracked hash to server, unexpected error",
				"status_code",
				e1.StatusCode,
				"message",
				e1.Message,
			)
			SendAgentError(e1.Error(), nil, operations.SeverityCritical)
		default:
			state.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		}
	}
}
