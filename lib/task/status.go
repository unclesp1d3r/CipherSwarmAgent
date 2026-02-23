package task

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/zap"
)

const (
	filePermissions = 0o600 // Default file permissions for created files
)

// sendStatusUpdate sends a status update to the server for a given task and session.
// It ensures the update time is set, converts device statuses, and converts hashcat.Status to api.TaskStatus.
// Finally, it sends the status update to the server and handles the response.
func (m *Manager) sendStatusUpdate(ctx context.Context, update hashcat.Status, task *api.Task, sess *hashcat.Session) {
	// Ensure the update time is set
	if update.Time.IsZero() {
		update.Time = time.Now()
	}

	if agentstate.State.ExtraDebugging {
		agentstate.Logger.Debug("Sending status update", "status", update)
	}

	deviceStatuses := convertDeviceStatuses(update.Devices)
	taskStatus := convertToTaskStatus(update, deviceStatuses)

	// Send status update to the server
	resp, err := m.tasksClient.SendStatus(ctx, task.Id, taskStatus)
	if err != nil {
		handleStatusUpdateError(ctx, err, task, sess)
		return
	}

	m.handleSendStatusResponse(ctx, resp, task)
}

func convertDeviceStatuses(devices []hashcat.StatusDevice) []api.DeviceStatus {
	deviceStatuses := make([]api.DeviceStatus, len(devices))
	for i, device := range devices {
		deviceStatuses[i] = api.DeviceStatus{
			DeviceId:    int(device.DeviceID),
			DeviceName:  device.DeviceName,
			DeviceType:  parseStringToDeviceType(device.DeviceType),
			Speed:       device.Speed,
			Utilization: int(device.Util),
			Temperature: int(device.Temp),
		}
	}

	return deviceStatuses
}

func convertToTaskStatus(update hashcat.Status, deviceStatuses []api.DeviceStatus) api.TaskStatus {
	return api.TaskStatus{
		OriginalLine: update.OriginalLine,
		Time:         update.Time,
		Session:      update.Session,
		HashcatGuess: api.HashcatGuess{
			GuessBase:           update.Guess.GuessBase,
			GuessBaseCount:      update.Guess.GuessBaseCount,
			GuessBaseOffset:     update.Guess.GuessBaseOffset,
			GuessBasePercentage: update.Guess.GuessBasePercent,
			GuessMod:            update.Guess.GuessMod,
			GuessModCount:       update.Guess.GuessModCount,
			GuessModOffset:      update.Guess.GuessModOffset,
			GuessModPercentage:  update.Guess.GuessModPercent,
			GuessMode:           int(update.Guess.GuessMode),
		},
		Status:          int(update.Status),
		Target:          update.Target,
		Progress:        update.Progress,
		RestorePoint:    update.RestorePoint,
		RecoveredHashes: convertAndWarn(update.RecoveredHashes, "RecoveredHashes"),
		RecoveredSalts:  convertAndWarn(update.RecoveredSalts, "RecoveredSalts"),
		Rejected:        update.Rejected,
		DeviceStatuses:  deviceStatuses,
		TimeStart:       time.Unix(update.TimeStart, 0),
		EstimatedStop:   time.Unix(update.EstimatedStop, 0),
	}
}

// convertAndWarn converts an int64 slice to int, logging a warning if any values were clamped.
func convertAndWarn(s []int64, field string) []int {
	result, clamped := api.ConvertInt64SliceToInt(s)
	if clamped > 0 {
		agentstate.Logger.Warn("int64 values exceeded platform int range and were clamped to zero",
			"field", field, "clamped_count", clamped)
	}
	return result
}

func (m *Manager) handleSendStatusResponse(ctx context.Context, resp *api.SendStatusResponse, task *api.Task) {
	switch resp.StatusCode() {
	case http.StatusNoContent:
		if agentstate.State.ExtraDebugging {
			agentstate.Logger.Debug("Status update sent")
		}
	case http.StatusAccepted:
		agentstate.Logger.Debug("Status update sent, but stale")
		zap.GetZaps(ctx, task, m.sendCrackedHash)
	default:
		if resp.StatusCode() >= http.StatusOK && resp.StatusCode() < http.StatusMultipleChoices {
			agentstate.Logger.Warn("Unexpected success status code for status update",
				"status_code", resp.StatusCode(), "task_id", task.Id)
			// Defensively fetch zaps for any other 2xx success code to avoid losing cracked hashes
			zap.GetZaps(ctx, task, m.sendCrackedHash)
		} else {
			agentstate.Logger.Error("Failed to send status update",
				"status_code", resp.StatusCode(), "task_id", task.Id)
		}
	}
}

// sendCrackedHash sends a cracked hash result to the task server and logs relevant information.
// If the task pointer is nil, it logs an error and returns early.
// Constructs a HashcatResult object and sends it to the server via the API client interface.
// Logs and handles any errors encountered during the sending process.
// If configured, writes the cracked hash to a file.
// Logs additional information based on the HTTP response status.
func (m *Manager) sendCrackedHash(ctx context.Context, timestamp time.Time, hash, plaintext string, task *api.Task) {
	if task == nil {
		agentstate.Logger.Error("Task is nil")

		return
	}

	hashcatResult := api.HashcatResult{
		Timestamp: timestamp,
		Hash:      hash,
		PlainText: plaintext,
	}

	agentstate.Logger.Info("Cracked hash", "hash", hash)

	response, err := m.tasksClient.SendCrack(ctx, task.Id, hashcatResult)
	if err != nil {
		handleSendCrackError(ctx, err)

		return
	}

	if agentstate.State.WriteZapsToFile {
		hashFile := path.Join(agentstate.State.ZapsPath, fmt.Sprintf("%d_clientout.zap", task.Id))

		file, err := os.OpenFile(
			hashFile,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			filePermissions,
		)
		if err != nil {
			//nolint:errcheck // LogAndSendError handles logging+sending internally
			_ = cserrors.LogAndSendError(
				ctx,
				"Error opening cracked hash file",
				err,
				api.SeverityCritical,
				task,
			)
			return
		}

		defer func() {
			if cerr := file.Close(); cerr != nil {
				agentstate.Logger.Error("Error closing cracked hash file; data may not be persisted",
					"error", cerr, "path", hashFile)
			}
		}()

		_, err = file.WriteString(fmt.Sprintf("%s:%s", hash, plaintext) + "\n")
		if err != nil {
			//nolint:errcheck // LogAndSendError handles logging+sending internally
			_ = cserrors.LogAndSendError(
				ctx,
				"Error writing cracked hash to file",
				err,
				api.SeverityCritical,
				task,
			)
			return
		}
	}

	agentstate.Logger.Debug("Cracked hash sent")

	if response.StatusCode() == http.StatusNoContent {
		agentstate.Logger.Info("Hashlist completed", "hash", hash)
	}
}

// parseStringToDeviceType converts a string representing a device type to the corresponding api.DeviceStatusDeviceType enum.
// If the input string does not match any known device type, it defaults to api.CPU.
func parseStringToDeviceType(deviceType string) api.DeviceStatusDeviceType {
	switch deviceType {
	case "CPU":
		return api.CPU
	case "GPU":
		return api.GPU
	default:
		return api.CPU
	}
}
