package lib

import (
	"context"
	stderrors "errors"
	"os"
	"path"
	"sync"
	"time"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
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
			SendError: func(message string, severity api.Severity) {
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
		Severity:     api.SeverityCritical,
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
func handleCrackerUpdate(update *api.CrackerUpdate) error {
	if update.GetDownloadURL() == nil || update.GetExecName() == nil {
		return cserrors.LogAndSendError(
			"Cracker update missing download URL or exec name",
			stderrors.New("incomplete cracker update response"),
			api.SeverityCritical,
			nil,
		)
	}

	DisplayNewCrackerAvailable(update)

	tempDir, err := os.MkdirTemp("", "cipherswarm-*")
	if err != nil {
		return cserrors.LogAndSendError("Error creating temporary directory", err, api.SeverityCritical, nil)
	}
	defer func(tempDir string) {
		_ = downloader.CleanupTempDir(tempDir) //nolint:errcheck // Cleanup in defer, error not critical
	}(tempDir)

	tempArchivePath := path.Join(tempDir, "hashcat.7z")
	// TODO: propagate cancellable context for graceful shutdown support
	if err := downloader.DownloadFile(context.TODO(), *update.GetDownloadURL(), tempArchivePath, ""); err != nil {
		return cserrors.LogAndSendError("Error downloading cracker", err, api.SeverityCritical, nil)
	}

	newArchivePath, err := cracker.MoveArchiveFile(tempArchivePath)
	if err != nil {
		return cserrors.LogAndSendError("Error moving file", err, api.SeverityCritical, nil)
	}

	hashcatDirectory, err := cracker.ExtractHashcatArchive(context.Background(), newArchivePath)
	if err != nil {
		return cserrors.LogAndSendError("Error extracting file", err, api.SeverityCritical, nil)
	}

	if !validateHashcatDirectory(hashcatDirectory, *update.GetExecName()) {
		return cserrors.LogAndSendError(
			"Hashcat directory validation failed after extraction",
			stderrors.New("hashcat binary validation failed"),
			api.SeverityCritical,
			nil,
		)
	}

	if err := os.Remove(newArchivePath); err != nil {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error removing 7z file",
			err,
			api.SeverityWarning,
			nil,
		)
	}

	viper.Set("hashcat_path", path.Join(agentstate.State.CrackersPath, "hashcat", *update.GetExecName()))
	if err := viper.WriteConfig(); err != nil {
		agentstate.Logger.Warn("Failed to persist hashcat path to config; update will be lost on restart",
			"error", err, "hashcat_path", viper.GetString("hashcat_path"))
	}

	return nil
}

// handleAPIError handles errors returned from the CipherSwarm API.
// It logs error messages and sends error reports based on the error type.
func handleAPIError(message string, err error) {
	opts := apierrors.Options{
		Message:        message,
		Severity:       api.SeverityCritical,
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
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	getErrorHandler().Handle(err, opts)
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
}

// SendAgentError sends an error message to the centralized server, including metadata and severity level.
func SendAgentError(stdErrLine string, task *api.Task, severity api.Severity) {
	var taskID *int64
	if task != nil {
		taskID = &task.Id
	}

	otherMap := map[string]any{
		"platform": agentPlatform,
		"version":  AgentVersion,
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

// SendClassifiedError sends a classified error message to the server with enhanced metadata.
// It includes the error category and retryable flag for better error handling on the server side.
func SendClassifiedError(
	message string,
	task *api.Task,
	severity api.Severity,
	category string,
	retryable bool,
) {
	var taskID *int64
	if task != nil {
		taskID = &task.Id
	}

	otherMap := map[string]any{
		"platform":  agentPlatform,
		"version":   AgentVersion,
		"category":  category,
		"retryable": retryable,
	}

	agentError := api.SubmitErrorAgentJSONRequestBody{
		Message:  message,
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
	getErrorHandlerNoSend().LogOnly(err, "Error sending agent error to server")
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
	getErrorHandler().Handle(err, opts)
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
		SendAgentError(e1.Error(), nil, api.SeverityWarning)
		return
	}

	opts := apierrors.Options{
		Message:      message,
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	getErrorHandler().Handle(err, opts)
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
	getErrorHandler().Handle(err, opts)
}
