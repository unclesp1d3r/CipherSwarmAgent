package lib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/pointer"
	"github.com/spf13/viper"
	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// GetNewTask retrieves a new task from the server.
// It sends a request using SdkClient, handles any errors, and returns the task if available.
// If the server responds with no content, it means no new task is available, and the function returns nil without error.
// For any other unexpected response status, an error is returned.
func GetNewTask() (*components.Task, error) {
	response, err := SdkClient.Tasks.GetNewTask(Context)
	if err != nil {
		handleAPIError("Error getting new task", err, operations.SeverityCritical)

		return nil, err
	}

	switch response.StatusCode {
	case http.StatusNoContent:
		// No new task available
		return nil, nil
	case http.StatusOK:
		// New task available
		return response.Task, nil
	default:
		return nil, errors.New("bad response: " + response.RawResponse.Status)
	}
}

// GetAttackParameters retrieves the attack parameters for a given attackID via the SdkClient.
// Returns an Attack object if the API call is successful and the response status is OK.
func GetAttackParameters(attackID int64) (*components.Attack, error) {
	response, err := SdkClient.Attacks.GetAttack(Context, attackID)
	if err != nil {
		handleAPIError("Error getting attack parameters", err, operations.SeverityCritical)

		return nil, err
	}

	if response.StatusCode == http.StatusOK {
		return response.Attack, nil
	}

	return nil, errors.New("bad response: " + response.RawResponse.Status)
}

// handleAPIError handles errors returned from the CipherSwarm API. Logs error messages and sends error reports based on the error type.
// Parameters:
// - message: Description of the error context.
// - err: The original error object encountered.
// - severity: The severity level of the error for reporting.
func handleAPIError(message string, err error, severity operations.Severity) {
	switch e := err.(type) {
	case *sdkerrors.ErrorObject:
		shared.Logger.Error(message, "error", e.Error())
		SendAgentError(e.Error(), nil, severity)
	case *sdkerrors.SDKError:
		shared.Logger.Error(message+", unexpected error",
			"status_code", e.StatusCode,
			"message", e.Message)
		SendAgentError(e.Error(), nil, severity)
	default:
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
	}
}

// sendStatusUpdate sends a status update to the server for a given task and session.
// It ensures the update time is set, converts device statuses, and converts hashcat.Status to cipherswarm.TaskStatus.
// Finally, it sends the status update to the server and handles the response.
func sendStatusUpdate(update hashcat.Status, task *components.Task, sess *hashcat.Session) {
	// Ensure the update time is set
	if update.Time.IsZero() {
		update.Time = time.Now()
	}
	if shared.State.ExtraDebugging {
		shared.Logger.Debug("Sending status update", "status", update)
	}

	// Convert device statuses
	deviceStatuses := make([]components.DeviceStatus, len(update.Devices))
	for i, device := range update.Devices {
		deviceStatuses[i] = components.DeviceStatus{
			DeviceID:    device.DeviceID,
			DeviceName:  device.DeviceName,
			DeviceType:  parseStringToDeviceType(device.DeviceType),
			Speed:       device.Speed,
			Utilization: device.Util,
			Temperature: device.Temp,
		}
	}

	// Convert hashcat.Status to cipherswarm.TaskStatus
	taskStatus := components.TaskStatus{
		OriginalLine: update.OriginalLine,
		Time:         update.Time,
		Session:      update.Session,
		HashcatGuess: components.HashcatGuess{
			GuessBase:           update.Guess.GuessBase,
			GuessBaseCount:      update.Guess.GuessBaseCount,
			GuessBaseOffset:     update.Guess.GuessBaseOffset,
			GuessBasePercentage: update.Guess.GuessModPercent,
			GuessMod:            update.Guess.GuessMod,
			GuessModCount:       update.Guess.GuessModCount,
			GuessModOffset:      update.Guess.GuessModOffset,
			GuessModPercentage:  update.Guess.GuessModPercent,
			GuessMode:           update.Guess.GuessMode,
		},
		Status:          update.Status,
		Target:          update.Target,
		Progress:        update.Progress,
		RestorePoint:    update.RestorePoint,
		RecoveredHashes: update.RecoveredHashes,
		RecoveredSalts:  update.RecoveredSalts,
		Rejected:        update.Rejected,
		DeviceStatuses:  deviceStatuses,
		TimeStart:       time.Unix(update.TimeStart, 0),
		EstimatedStop:   time.Unix(update.EstimatedStop, 0),
	}

	// Send status update to the server
	resp, err := SdkClient.Tasks.SendStatus(Context, task.GetID(), taskStatus)
	if err != nil {
		handleStatusUpdateError(err, task, sess)

		return
	}

	// Handle non-error responses
	switch resp.StatusCode {
	case http.StatusNoContent:
		if shared.State.ExtraDebugging {
			shared.Logger.Debug("Status update sent")
		}
	case http.StatusAccepted:
		shared.Logger.Debug("Status update sent, but stale")
		getZaps(task)
	}
}

// handleStatusUpdateError handles specific error types during a status update and logs or processes them accordingly.
func handleStatusUpdateError(err error, task *components.Task, sess *hashcat.Session) {
	var eo *sdkerrors.ErrorObject
	if errors.As(err, &eo) {
		_ = logAndSendError("Error sending status update", eo, operations.SeverityCritical, task)

		return
	}

	var se *sdkerrors.SDKError
	if errors.As(err, &se) {
		handleSDKError(se, task, sess)

		return
	}

	shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
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
		_ = logAndSendError("Error connecting to the CipherSwarm API, unexpected error", se, operations.SeverityCritical, task)
	}
}

// handleTaskNotFound handles the scenario where a task is not found in the system.
// It logs an error message with the task ID, attempts to kill the session, and cleans up the session.
// If killing the session fails, it logs and sends an error.
func handleTaskNotFound(task *components.Task, sess *hashcat.Session) {
	shared.Logger.Error("Task not found", "task_id", task.GetID())
	shared.Logger.Info("Killing task", "task_id", task.GetID())
	shared.Logger.Info("It is possible that multiple errors appear as the task takes some time to kill. This is expected.")
	if err := sess.Kill(); err != nil {
		_ = logAndSendError("Error killing task", err, operations.SeverityCritical, task)
	}
	sess.Cleanup()
}

// handleTaskGone handles the termination of a task when it is no longer needed, ensuring the session is appropriately killed.
func handleTaskGone(task *components.Task, sess *hashcat.Session) {
	shared.Logger.Info("Pausing task", "task_id", task.GetID())
	if err := sess.Kill(); err != nil {
		_ = logAndSendError("Error pausing task", err, operations.SeverityFatal, task)
	}
}

// getZaps fetches zap data for a given task, handles errors, and processes the response stream if available.
// Logs an error if the task is nil, displays job progress, and retrieves zaps from the SdkClient.
func getZaps(task *components.Task) {
	if task == nil {
		shared.Logger.Error("Task is nil")

		return
	}

	displayJobGetZap(task)

	res, err := SdkClient.Tasks.GetTaskZaps(Context, task.GetID())
	if err != nil {
		handleGetZapsError(err)

		return
	}

	if res.ResponseStream != nil {
		_ = handleResponseStream(task, res.ResponseStream)
	}
}

// handleGetZapsError handles different types of errors when fetching zaps from the server.
// - If the error is of type sdkerrors.ErrorObject, it logs the error and sends a critical agent error message.
// - If the error is of type sdkerrors.SDKError, it logs an unexpected error with its status code and message, then sends a critical agent error message.
// - For all other errors, it logs a critical communication error with the CipherSwarm API.
func handleGetZapsError(err error) {
	switch e := err.(type) {
	case *sdkerrors.ErrorObject:
		shared.Logger.Error("Error getting zaps from server", "error", e.Error())
		SendAgentError(e.Error(), nil, operations.SeverityCritical)
	case *sdkerrors.SDKError:
		shared.Logger.Error("Error getting zaps from server, unexpected error",
			"status_code", e.StatusCode,
			"message", e.Message)
		SendAgentError(e.Error(), nil, operations.SeverityCritical)
	default:
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
	}
}

// handleResponseStream processes a received response stream for a given task, writing it to a zap file on disk.
// Constructs the zap file path from the task ID, removes existing zap files if necessary, and writes the new zap file.
// Logs debug information for non-critical errors when removing existing files and logs critical errors for failures in creating or writing the zap file.
func handleResponseStream(task *components.Task, responseStream io.Reader) error {
	zapFilePath := path.Join(shared.State.ZapsPath, fmt.Sprintf("%d.zap", task.GetID()))

	if err := removeExistingZapFile(zapFilePath); err != nil {
		// It's not critical to remove the existing zap file since we're going to overwrite it anyway
		_ = logAndSendError("Error removing existing zap file", err, operations.SeverityCritical, task)
	}

	if err := createAndWriteZapFile(zapFilePath, responseStream, task); err != nil {
		// This is a critical error since we need the zap file to be written
		return logAndSendError("Error handling zap file", err, operations.SeverityCritical, task)
	}

	return nil
}

// removeExistingZapFile removes the zap file at the given path if it exists, logging debug information.
// Returns an error if the file removal fails.
func removeExistingZapFile(zapFilePath string) error {
	if fileutil.IsExist(zapFilePath) {
		shared.Logger.Debug("Zap file already exists", "path", zapFilePath)

		return fileutil.RemoveFile(zapFilePath)
	}

	return nil
}

// createAndWriteZapFile creates a zap file at the specified path and writes data from the provided responseStream.
// The task parameter is used for logging and error reporting in case of failures.
// Returns an error if file creation, writing, or closing fails.
func createAndWriteZapFile(zapFilePath string, responseStream io.Reader, task *components.Task) error {
	outFile, err := os.Create(zapFilePath)
	if err != nil {
		return fmt.Errorf("error creating zap file: %w", err)
	}
	if _, err := io.Copy(outFile, responseStream); err != nil {
		return fmt.Errorf("error writing zap file: %w", err)
	}

	if cerr := outFile.Close(); cerr != nil {
		return logAndSendError("Error closing zap file", cerr, operations.SeverityCritical, task)
	}

	return nil
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
		AgentID:  shared.State.AgentID,
		TaskID:   taskID,
	}

	if _, err := SdkClient.Agents.SubmitErrorAgent(Context, shared.State.AgentID, agentError); err != nil {
		handleSendError(err)
	}
}

// handleSendError handles errors that occur during communication with the server.
// It logs the error locally and attempts to send critical errors to the server.
func handleSendError(err error) {
	switch e := err.(type) {
	case *sdkerrors.ErrorObject:
		shared.Logger.Error("Error sending agent error to server", "error", e.Error())
		SendAgentError(e.Error(), nil, operations.SeverityCritical)
	case *sdkerrors.SDKError:
		shared.Logger.Error("Error sending agent error to server, unexpected error",
			"status_code", e.StatusCode,
			"message", e.Message)
		SendAgentError(e.Error(), nil, operations.SeverityCritical)
	default:
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
	}
}
