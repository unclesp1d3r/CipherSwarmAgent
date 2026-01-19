package lib

import (
	"context"
	stderrors "errors"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/apierrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/downloader"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// Static errors to comply with err113 linter.
var (
	ErrCouldNotValidateCredentials = stderrors.New("could not validate credentials")
)

// apiErrorHandler is the shared error handler instance.
// It's initialized lazily to avoid circular dependency with SendAgentError.
// Uses sync.Once for thread-safe initialization.
var (
	apiErrorHandler     *apierrors.Handler //nolint:gochecknoglobals // Singleton error handler
	apiErrorHandlerOnce sync.Once          //nolint:gochecknoglobals // Singleton initialization guard
)

// getErrorHandler returns the shared error handler, initializing it if needed.
// Thread-safe via sync.Once.
func getErrorHandler() *apierrors.Handler {
	apiErrorHandlerOnce.Do(func() {
		apiErrorHandler = &apierrors.Handler{
			SendError: func(message string, severity operations.Severity) {
				SendAgentError(message, nil, severity)
			},
		}
	})
	return apiErrorHandler
}

// getErrorHandlerNoSend returns an error handler that only logs (no server send).
// Used to prevent infinite recursion when error sending fails.
func getErrorHandlerNoSend() *apierrors.Handler {
	return &apierrors.Handler{
		SendError: nil,
	}
}

// handleAuthenticationError handles authentication errors from the CipherSwarm API.
// It logs detailed error information based on the type of error and returns the original error.
func handleAuthenticationError(err error) error {
	opts := apierrors.Options{
		Message:        "Error connecting to the CipherSwarm API",
		SendToServer:   false, // Auth errors don't send to server (agent not authenticated yet)
		LogAuthContext: true,
	}
	return getErrorHandlerNoSend().Handle(err, opts)
}

// handleConfigurationError processes configuration errors by logging them and sending critical error reports.
func handleConfigurationError(err error) error {
	opts := apierrors.Options{
		Message:      "Error getting agent configuration",
		Severity:     operations.SeverityCritical,
		SendToServer: true,
	}
	return getErrorHandler().Handle(err, opts)
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
		return cserrors.LogAndSendError(
			"Hashcat directory validation failed after extraction",
			stderrors.New("hashcat binary validation failed"),
			operations.SeverityCritical,
			nil,
		)
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

	viper.Set("hashcat_path", path.Join(agentstate.State.CrackersPath, "hashcat", *update.GetExecName()))
	_ = viper.WriteConfig() //nolint:errcheck // Config write failure not critical

	return nil
}

// handleAPIError handles errors returned from the CipherSwarm API.
// It logs error messages and sends error reports based on the error type.
func handleAPIError(message string, err error) {
	opts := apierrors.Options{
		Message:        message,
		Severity:       operations.SeverityCritical,
		SendToServer:   true,
		LogAuthContext: stderrors.Is(err, ErrCouldNotValidateCredentials),
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	getErrorHandler().Handle(err, opts)
}

// handleHeartbeatError processes and logs errors occurring during the heartbeat operation.
func handleHeartbeatError(err error) {
	opts := apierrors.Options{
		Message:      "Error sending heartbeat",
		Severity:     operations.SeverityCritical,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	getErrorHandler().Handle(err, opts)
}

// handleStatusUpdateError handles specific error types during a status update and logs or processes them accordingly.
func handleStatusUpdateError(err error, task *components.Task, sess *hashcat.Session) {
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
	cserrors.LogAndSendError("Error sending status update", err, operations.SeverityCritical, task)
}

// handleSDKError handles errors from the SDK by taking appropriate action based on the error's status code.
func handleSDKError(se *sdkerrors.SDKError, task *components.Task, sess *hashcat.Session) {
	switch se.StatusCode {
	case http.StatusNotFound:
		handleTaskNotFound(task, sess)
	case http.StatusGone:
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
func handleTaskNotFound(task *components.Task, sess *hashcat.Session) {
	agentstate.Logger.Error("Task not found", "task_id", task.GetID())
	agentstate.Logger.Info("Killing task", "task_id", task.GetID())
	agentstate.Logger.Info(
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
	agentstate.Logger.Info("Pausing task", "task_id", task.GetID())

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
		AgentID:  agentstate.State.AgentID,
		TaskID:   taskID,
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
	getErrorHandlerNoSend().LogOnly(err, "Error sending agent error to server")
}

// handleAcceptTaskError handles errors that occur when attempting to accept a task.
func handleAcceptTaskError(err error) {
	// ErrorObject gets Info severity, SDKError gets Critical
	var eo *sdkerrors.ErrorObject
	severity := operations.SeverityCritical
	if stderrors.As(err, &eo) {
		severity = operations.SeverityInfo
	}

	opts := apierrors.Options{
		Message:      "Error accepting task",
		Severity:     severity,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	getErrorHandler().Handle(err, opts)
}

// handleTaskError handles different types of errors encountered during task operations.
func handleTaskError(err error, message string) {
	// Handle SetTaskAbandonedResponseBody specially
	var e1 *sdkerrors.SetTaskAbandonedResponseBody
	if stderrors.As(err, &e1) {
		agentstate.Logger.Error(
			"Notified server of task abandonment, but it could not update the task properly",
			"error",
			e1.State,
		)
		SendAgentError(e1.Error(), nil, operations.SeverityWarning)
		return
	}

	opts := apierrors.Options{
		Message:      message,
		Severity:     operations.SeverityCritical,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	getErrorHandler().Handle(err, opts)
}

// handleSendCrackError processes different types of errors encountered when communicating with the CipherSwarm API.
func handleSendCrackError(err error) {
	// ErrorObject gets Major severity, SDKError gets Critical
	var eo *sdkerrors.ErrorObject
	severity := operations.SeverityCritical
	message := "Error sending cracked hash to server"
	if stderrors.As(err, &eo) {
		severity = operations.SeverityMajor
		message = "Error notifying server of cracked hash, task not found"
	}

	opts := apierrors.Options{
		Message:      message,
		Severity:     severity,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	getErrorHandler().Handle(err, opts)
}
