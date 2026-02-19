// Package lib provides core functionality for the CipherSwarm agent.
package lib

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/duke-git/lancet/v2/pointer"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	cserrors "github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/downloader"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/zap"
)

const (
	defaultAgentUpdateInterval = 300   // Default agent update interval in seconds
	filePermissions            = 0o600 // Default file permissions for created files
)

var (
	agentPlatform string //nolint:gochecknoglobals // agentPlatform represents the platform on which the agent is running.
	// Configuration represents the configuration of the agent.
	Configuration agentConfiguration //nolint:gochecknoglobals // Global agent configuration

	// setNativeHashcatPathFn allows stubbing setNativeHashcatPath for testing.
	setNativeHashcatPathFn = setNativeHashcatPath //nolint:gochecknoglobals // Used for testing
	// getDevicesListFn allows stubbing getDevicesList for testing.
	getDevicesListFn = getDevicesList //nolint:gochecknoglobals // Used for testing
)

// Define static errors.
var (
	ErrAuthenticationFailed = errors.New("failed to authenticate with the CipherSwarm API")
	ErrConfigurationFailed  = errors.New("failed to get agent configuration")
	ErrBadResponse          = errors.New("bad response from server")
)

// AuthenticateAgent authenticates the agent with the CipherSwarm API using the API client interface.
// It sends an authentication request to the API, processes the response, and updates the shared state.
// On error, it logs the error and returns it. If the response is nil or indicates a failed authentication,
// an error is logged and returned.
func AuthenticateAgent() error {
	response, err := agentstate.State.APIClient.Auth().Authenticate(context.Background())
	if err != nil {
		return handleAuthenticationError(err)
	}

	if response.JSON200 == nil || !response.JSON200.Authenticated {
		agentstate.Logger.Error("Failed to authenticate with the CipherSwarm API")

		return ErrAuthenticationFailed
	}

	agentstate.State.AgentID = response.JSON200.AgentId

	return nil
}

// GetAgentConfiguration retrieves the agent configuration from the CipherSwarm API and handles errors.
// It updates the global Configuration variable with the fetched configuration.
// If UseNativeHashcat is true in the configuration, it sets the native Hashcat path.
func GetAgentConfiguration() error {
	response, err := agentstate.State.APIClient.Auth().GetConfiguration(context.Background())
	if err != nil {
		return handleConfigurationError(err)
	}

	if response.JSON200 == nil {
		agentstate.Logger.Error("Error getting agent configuration")

		return ErrConfigurationFailed
	}

	agentConfig := mapConfiguration(response.JSON200.ApiVersion, response.JSON200.Config)

	if agentConfig.Config.UseNativeHashcat {
		if err := setNativeHashcatPathFn(); err != nil {
			return err
		}
	} else {
		agentstate.Logger.Debug("Using server-provided Hashcat binary")
	}

	Configuration = agentConfig
	agentstate.Logger.Debug("Agent configuration", "config", Configuration)

	return nil
}

// mapConfiguration converts the API configuration response into an agentConfiguration for use within the agent.
func mapConfiguration(apiVersion int, config api.AdvancedAgentConfiguration) agentConfiguration {
	agentConfig := agentConfiguration{
		APIVersion: int64(apiVersion),
		Config: agentConfig{
			UseNativeHashcat:    pointer.UnwrapOr(config.UseNativeHashcat, false),
			AgentUpdateInterval: int64(pointer.UnwrapOr(config.AgentUpdateInterval, defaultAgentUpdateInterval)),
			BackendDevices:      pointer.UnwrapOr(config.BackendDevice, ""),
			OpenCLDevices:       pointer.UnwrapOr(config.OpenclDevices, ""),
		},
	}

	return agentConfig
}

// UpdateAgentMetadata updates the agent's metadata and sends it to the CipherSwarm API.
// It retrieves host information, device list, constructs the agent update request body,
// and sends the updated metadata to the API. Logs relevant information and handles any API errors.
func UpdateAgentMetadata() error {
	info, err := host.Info()
	if err != nil {
		return cserrors.LogAndSendError("Error getting host info", err, api.SeverityCritical, nil)
	}

	clientSignature := fmt.Sprintf("CipherSwarm Agent/%s %s/%s", AgentVersion, info.OS, info.KernelArch)

	devices, err := getDevicesListFn(context.Background())
	if err != nil {
		return cserrors.LogAndSendError("Error getting devices", err, api.SeverityCritical, nil)
	}

	agentPlatform = info.OS
	agentUpdate := api.UpdateAgentJSONRequestBody{
		Id:              agentstate.State.AgentID,
		HostName:        info.Hostname,
		ClientSignature: clientSignature,
		OperatingSystem: info.OS,
		Devices:         devices,
	}

	// Debug logging for troubleshooting credentials issue
	agentstate.Logger.Debug("Preparing agent metadata update",
		"agent_id", agentstate.State.AgentID,
		"hostname", info.Hostname,
		"client_signature", clientSignature,
		"os", info.OS,
		"devices", devices,
		"api_url", agentstate.State.URL,
		"has_token", agentstate.State.APIToken != "")

	response, err := agentstate.State.APIClient.Agents().UpdateAgent(
		context.Background(),
		agentstate.State.AgentID,
		agentUpdate,
	)
	if err != nil {
		handleAPIError("Error updating agent metadata", err)

		return err
	}

	if response.JSON200 != nil {
		displayAgentMetadataUpdated(response)
	} else {
		status := response.Status()
		agentstate.ErrorLogger.Error("bad response", "status", status)

		return fmt.Errorf("%w: %s", ErrBadResponse, status)
	}

	return nil
}

// getDevicesList retrieves a list of device names based on the configured device identification method.
// It checks the global state to determine if the legacy method should be used, then calls the appropriate function.
func getDevicesList(ctx context.Context) ([]string, error) {
	if agentstate.State.UseLegacyDeviceIdentificationMethod {
		return arch.GetDevices(ctx)
	}

	return getDevices(ctx)
}

// DownloadFiles downloads the necessary files for the provided attack.
// It performs the following steps:
// 1. Logs the start of the download process.
// 2. Downloads the hash list associated with the attack.
// 3. Iterates over resource files (word list, rule list, and mask list) and downloads each one.
// If any step encounters an error, the function returns that error.
func DownloadFiles(ctx context.Context, attack *api.Attack) error {
	displayDownloadFileStart(attack)

	if err := downloader.DownloadHashList(ctx, attack); err != nil {
		return err
	}

	resourceFiles := []*api.AttackResourceFile{
		attack.WordList,
		attack.RuleList,
		attack.MaskList,
	}

	for _, resource := range resourceFiles {
		if err := downloadResourceFile(ctx, resource); err != nil {
			return err
		}
	}

	return nil
}

// downloadResourceFile downloads a resource file if the provided resource is not nil.
// Constructs the file path based on the resource file name and logs the download action.
// If checksum verification is not always skipped, converts the checksum bytes to hex.
// Downloads the file using the resource's download URL, target file path, and checksum for verification.
// Logs and sends an error report if file download fails or if the downloaded file is empty.
func downloadResourceFile(ctx context.Context, resource *api.AttackResourceFile) error {
	if resource == nil {
		return nil
	}

	filePath := path.Join(agentstate.State.FilePath, resource.FileName)
	agentstate.Logger.Debug("Downloading resource file", "url", resource.DownloadUrl, "path", filePath)

	checksum := ""
	if !agentstate.State.AlwaysTrustFiles {
		checksum = hex.EncodeToString(resource.Checksum)
	} else {
		agentstate.Logger.Debug("Skipping checksum verification")
	}

	if err := downloader.DownloadFile(ctx, resource.DownloadUrl, filePath, checksum); err != nil {
		//nolint:contextcheck // LogAndSendError uses context.Background() internally
		return cserrors.LogAndSendError("Error downloading attack resource", err, api.SeverityCritical, nil)
	}

	fileInfo, statErr := os.Stat(filePath)
	if statErr != nil {
		//nolint:contextcheck // LogAndSendError uses context.Background() internally
		return cserrors.LogAndSendError("Error checking downloaded file", statErr, api.SeverityCritical, nil)
	}

	if fileInfo.Size() == 0 {
		//nolint:contextcheck // LogAndSendError uses context.Background() internally
		return cserrors.LogAndSendError(
			"Downloaded file is empty: "+filePath,
			fmt.Errorf("file %s has zero bytes", filePath),
			api.SeverityCritical,
			nil,
		)
	}

	agentstate.Logger.Debug("Downloaded resource file", "path", filePath)

	return nil
}

// SendHeartBeat sends a heartbeat signal to the server and processes the server's response.
// It handles different response status codes and logs relevant messages.
// It returns the agent's state object (or nil for no state change) and an error if the heartbeat failed.
func SendHeartBeat() (*api.SendHeartbeat200State, error) {
	resp, err := agentstate.State.APIClient.Agents().SendHeartbeat(context.Background(), agentstate.State.AgentID)
	if err != nil {
		handleHeartbeatError(err)

		return nil, err
	}

	if resp.StatusCode() == http.StatusNoContent {
		logHeartbeatSent()

		return nil, nil //nolint:nilnil // nil state with nil error means successful heartbeat with no state change
	}

	if resp.StatusCode() == http.StatusOK {
		logHeartbeatSent()

		return handleStateResponse(resp.JSON200), nil
	}

	agentstate.Logger.Warn("Unexpected heartbeat response code", "status_code", resp.StatusCode())

	return nil, nil //nolint:nilnil // nil state with nil error means successful heartbeat with no state change
}

// logHeartbeatSent logs a debug message indicating a heartbeat was sent if extra debugging is enabled.
// It also sets the JobCheckingStopped state to false.
func logHeartbeatSent() {
	if agentstate.State.ExtraDebugging {
		agentstate.Logger.Debug("Heartbeat sent")
	}

	agentstate.State.JobCheckingStopped = false
}

// handleStateResponse processes the given state response and performs logging based on the agent state.
// It returns the agent's state object or nil if the response is nil.
func handleStateResponse(stateResponse *struct {
	State api.SendHeartbeat200State `json:"state"`
},
) *api.SendHeartbeat200State {
	if stateResponse == nil {
		return nil
	}

	state := stateResponse.State
	switch state {
	case api.StatePending:
		if agentstate.State.ExtraDebugging {
			agentstate.Logger.Debug("Agent is pending")
		}
	case api.StateStopped:
		agentstate.Logger.Debug("Agent is stopped")
	case api.StateError:
		agentstate.Logger.Debug("Agent is in error state")
	default:
		if agentstate.State.ExtraDebugging {
			agentstate.Logger.Debug("Unknown agent state")
		}
	}

	return &state
}

// sendStatusUpdate sends a status update to the server for a given task and session.
// It ensures the update time is set, converts device statuses, and converts hashcat.Status to api.TaskStatus.
// Finally, it sends the status update to the server and handles the response.
func sendStatusUpdate(update hashcat.Status, task *api.Task, sess *hashcat.Session) {
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
	resp, err := agentstate.State.APIClient.Tasks().SendStatus(context.Background(), task.Id, taskStatus)
	if err != nil {
		handleStatusUpdateError(err, task, sess)
		return
	}

	handleSendStatusResponse(resp, task)
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
		RecoveredHashes: api.ConvertInt64SliceToInt(update.RecoveredHashes),
		RecoveredSalts:  api.ConvertInt64SliceToInt(update.RecoveredSalts),
		Rejected:        update.Rejected,
		DeviceStatuses:  deviceStatuses,
		TimeStart:       time.Unix(update.TimeStart, 0),
		EstimatedStop:   time.Unix(update.EstimatedStop, 0),
	}
}

func handleSendStatusResponse(resp *api.SendStatusResponse, task *api.Task) {
	switch resp.StatusCode() {
	case http.StatusNoContent:
		if agentstate.State.ExtraDebugging {
			agentstate.Logger.Debug("Status update sent")
		}
	case http.StatusAccepted:
		agentstate.Logger.Debug("Status update sent, but stale")
		zap.GetZaps(task, sendCrackedHash)
	default:
		agentstate.Logger.Warn("Unexpected status update response code",
			"status_code", resp.StatusCode(), "task_id", task.Id)
	}
}

// SendAgentShutdown notifies the server of the agent shutdown and handles any errors during the API call.
func SendAgentShutdown() {
	_, err := agentstate.State.APIClient.Agents().SetAgentShutdown(context.Background(), agentstate.State.AgentID)
	if err != nil {
		handleAPIError("Error notifying server of agent shutdown", err)
	}
}

// sendCrackedHash sends a cracked hash result to the task server and logs relevant information.
// If the task pointer is nil, it logs an error and returns early.
// Constructs a HashcatResult object and sends it to the server via the API client interface.
// Logs and handles any errors encountered during the sending process.
// If configured, writes the cracked hash to a file.
// Logs additional information based on the HTTP response status.
func sendCrackedHash(timestamp time.Time, hash, plaintext string, task *api.Task) {
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

	response, err := agentstate.State.APIClient.Tasks().SendCrack(context.Background(), task.Id, hashcatResult)
	if err != nil {
		handleSendCrackError(err)

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
			//nolint:errcheck // Error already being handled
			_ = cserrors.LogAndSendError(
				"Error opening cracked hash file",
				err,
				api.SeverityCritical,
				task,
			)
			return
		}

		defer func() { _ = file.Close() }()

		_, err = file.WriteString(fmt.Sprintf("%s:%s", hash, plaintext) + "\n")
		if err != nil {
			//nolint:errcheck // Error already being handled
			_ = cserrors.LogAndSendError(
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
