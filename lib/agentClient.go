package lib

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/duke-git/lancet/v2/pointer"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	cserrors "github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/downloader"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/zap"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

var (
	agentPlatform string             // agentPlatform represents the platform on which the agent is running.
	Configuration agentConfiguration // Configuration represents the configuration of the agent.
)

// AuthenticateAgent authenticates the agent with the CipherSwarm API using the SDK client.
// It sends an authentication request to the API, processes the response, and updates the shared state.
// On error, it logs the error and returns it. If the response is nil or indicates a failed authentication,
// an error is logged and returned.
func AuthenticateAgent() error {
	response, err := shared.State.SdkClient.Client.Authenticate(shared.State.Context)
	if err != nil {
		return handleAuthenticationError(err)
	}

	if response.Object == nil || !response.GetObject().Authenticated {
		shared.Logger.Error("Failed to authenticate with the CipherSwarm API")

		return fmt.Errorf("failed to authenticate with the CipherSwarm API")
	}

	shared.State.AgentID = response.GetObject().AgentID

	return nil
}

// GetAgentConfiguration retrieves the agent configuration from the CipherSwarm API and handles errors.
// It updates the global Configuration variable with the fetched configuration.
// If UseNativeHashcat is true in the configuration, it sets the native Hashcat path.
func GetAgentConfiguration() error {
	response, err := shared.State.SdkClient.Client.GetConfiguration(shared.State.Context)
	if err != nil {
		return handleConfigurationError(err)
	}

	if response.Object == nil {
		shared.Logger.Error("Error getting agent configuration")

		return fmt.Errorf("failed to get agent configuration")
	}

	config := response.GetObject()
	agentConfig := mapConfiguration(config)

	if agentConfig.Config.UseNativeHashcat {
		if err := setNativeHashcatPath(); err != nil {
			return err
		}
	} else {
		shared.Logger.Debug("Using server-provided Hashcat binary")
	}

	Configuration = agentConfig
	shared.Logger.Debug("Agent configuration", "config", Configuration)

	return nil
}

// mapConfiguration converts the GetConfigurationResponseBody into an agentConfiguration for use within the agent.
func mapConfiguration(config *operations.GetConfigurationResponseBody) agentConfiguration {
	agentConfig := agentConfiguration{
		APIVersion: config.APIVersion,
		Config: agentConfig{
			UseNativeHashcat:    pointer.UnwrapOr(config.Config.UseNativeHashcat, false),
			AgentUpdateInterval: pointer.UnwrapOr(config.Config.AgentUpdateInterval, 300),
			BackendDevices:      pointer.UnwrapOr(config.Config.BackendDevice, ""),
			OpenCLDevices:       pointer.UnwrapOr(config.Config.OpenclDevices, ""),
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
		return cserrors.LogAndSendError("Error getting host info", err, operations.SeverityCritical, nil)
	}

	clientSignature := fmt.Sprintf("CipherSwarm Agent/%s %s/%s", AgentVersion, info.OS, info.KernelArch)

	devices, err := getDevicesList()
	if err != nil {
		return cserrors.LogAndSendError("Error getting devices", err, operations.SeverityCritical, nil)
	}

	agentPlatform = info.OS
	agentUpdate := &operations.UpdateAgentRequestBody{
		ID:              shared.State.AgentID,
		HostName:        info.Hostname,
		ClientSignature: clientSignature,
		OperatingSystem: info.OS,
		Devices:         devices,
	}

	shared.Logger.Debug("Updating agent metadata", "agent_id", shared.State.AgentID, "hostname", info.Hostname, "client_signature", clientSignature, "os", info.OS, "devices", devices)
	response, err := shared.State.SdkClient.Agents.UpdateAgent(shared.State.Context, shared.State.AgentID, agentUpdate)
	if err != nil {
		handleAPIError("Error updating agent metadata", err, operations.SeverityCritical)

		return err
	}

	if response.Agent != nil {
		displayAgentMetadataUpdated(response)
	} else {
		shared.ErrorLogger.Error("bad response: %v", response.RawResponse.Status)

		return fmt.Errorf("bad response: %s", response.RawResponse.Status)
	}

	return nil
}

// getDevicesList retrieves a list of device names based on the configured device identification method.
// It checks the global state to determine if the legacy method should be used, then calls the appropriate function.
func getDevicesList() ([]string, error) {
	if shared.State.UseLegacyDeviceIdentificationMethod {
		return arch.GetDevices()
	}

	return getDevices()
}

// DownloadFiles downloads the necessary files for the provided attack.
// It performs the following steps:
// 1. Logs the start of the download process.
// 2. Downloads the hash list associated with the attack.
// 3. Iterates over resource files (word list, rule list, and mask list) and downloads each one.
// If any step encounters an error, the function returns that error.
func DownloadFiles(attack *components.Attack) error {
	displayDownloadFileStart(attack)

	if err := downloader.DownloadHashList(attack); err != nil {
		return err
	}

	resourceFiles := []*components.AttackResourceFile{
		attack.WordList,
		attack.RuleList,
		attack.MaskList,
	}

	for _, resource := range resourceFiles {
		if err := downloadResourceFile(resource); err != nil {
			return err
		}
	}

	return nil
}

// downloadResourceFile downloads a resource file if the provided resource is not nil.
// Constructs the file path based on the resource file name and logs the download action.
// If checksum verification is not always skipped, converts the base64 checksum to hex.
// Downloads the file using the resource's download URL, target file path, and checksum for verification.
// Logs and sends an error report if file download fails or if the downloaded file is empty.
func downloadResourceFile(resource *components.AttackResourceFile) error {
	if resource == nil {
		return nil
	}

	filePath := path.Join(shared.State.FilePath, resource.FileName)
	shared.Logger.Debug("Downloading resource file", "url", resource.GetDownloadURL(), "path", filePath)

	checksum := ""
	if !shared.State.AlwaysTrustFiles {
		checksum = downloader.Base64ToHex(resource.GetChecksum())
	} else {
		shared.Logger.Debug("Skipping checksum verification")
	}

	if err := downloader.DownloadFile(resource.GetDownloadURL(), filePath, checksum); err != nil {
		return cserrors.LogAndSendError("Error downloading attack resource", err, operations.SeverityCritical, nil)
	}

	if fileInfo, err := os.Stat(filePath); err != nil || fileInfo.Size() == 0 {
		return cserrors.LogAndSendError("Downloaded file is empty", nil, operations.SeverityCritical, nil)
	}

	shared.Logger.Debug("Downloaded resource file", "path", filePath)

	return nil
}

// SendHeartBeat sends a heartbeat signal to the server and processes the server's response.
// It handles different response status codes and logs relevant messages.
// It returns the agent's state object or nil if an error occurs or if the response status is http.StatusNoContent.
func SendHeartBeat() *operations.State {
	resp, err := shared.State.SdkClient.Agents.SendHeartbeat(shared.State.Context, shared.State.AgentID)
	if err != nil {
		handleHeartbeatError(err)

		return nil
	}

	if resp.StatusCode == http.StatusNoContent {
		logHeartbeatSent()

		return nil
	}

	if resp.StatusCode == http.StatusOK {
		logHeartbeatSent()

		return handleStateResponse(resp.GetObject())
	}

	return nil
}

// logHeartbeatSent logs a debug message indicating a heartbeat was sent if extra debugging is enabled.
// It also sets the JobCheckingStopped state to false.
func logHeartbeatSent() {
	if shared.State.ExtraDebugging {
		shared.Logger.Debug("Heartbeat sent")
	}
	shared.State.JobCheckingStopped = false
}

// handleStateResponse processes the given state response and performs logging based on the agent state.
// It returns the agent's state object or nil if the response is nil.
func handleStateResponse(stateResponse *operations.SendHeartbeatResponseBody) *operations.State {
	if stateResponse == nil {
		return nil
	}

	state := stateResponse.GetState()
	switch state {
	case operations.StatePending:
		if shared.State.ExtraDebugging {
			shared.Logger.Debug("Agent is pending")
		}
	case operations.StateStopped:
		shared.Logger.Debug("Agent is stopped")
	case operations.StateError:
		shared.Logger.Debug("Agent is in error state")
	default:
		if shared.State.ExtraDebugging {
			shared.Logger.Debug("Unknown agent state")
		}
	}

	return &state
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

	deviceStatuses := convertDeviceStatuses(update.Devices)
	taskStatus := convertToTaskStatus(update, deviceStatuses)

	// Send status update to the server
	resp, err := shared.State.SdkClient.Tasks.SendStatus(shared.State.Context, task.GetID(), taskStatus)
	if err != nil {
		handleStatusUpdateError(err, task, sess)
		return
	}
	handleSendStatusResponse(resp, task)
}

func convertDeviceStatuses(devices []hashcat.StatusDevice) []components.DeviceStatus {
	deviceStatuses := make([]components.DeviceStatus, len(devices))
	for i, device := range devices {
		deviceStatuses[i] = components.DeviceStatus{
			DeviceID:    device.DeviceID,
			DeviceName:  device.DeviceName,
			DeviceType:  parseStringToDeviceType(device.DeviceType),
			Speed:       device.Speed,
			Utilization: device.Util,
			Temperature: device.Temp,
		}
	}
	return deviceStatuses
}

func convertToTaskStatus(update hashcat.Status, deviceStatuses []components.DeviceStatus) components.TaskStatus {
	return components.TaskStatus{
		OriginalLine: update.OriginalLine,
		Time:         update.Time,
		Session:      update.Session,
		HashcatGuess: components.HashcatGuess{
			GuessBase:           update.Guess.GuessBase,
			GuessBaseCount:      update.Guess.GuessBaseCount,
			GuessBaseOffset:     update.Guess.GuessBaseOffset,
			GuessBasePercentage: update.Guess.GuessBasePercent,
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
}

func handleSendStatusResponse(resp *operations.SendStatusResponse, task *components.Task) {
	switch resp.StatusCode {
	case http.StatusNoContent:
		if shared.State.ExtraDebugging {
			shared.Logger.Debug("Status update sent")
		}
	case http.StatusAccepted:
		shared.Logger.Debug("Status update sent, but stale")
		zap.GetZaps(task, sendCrackedHash)
	}
}

// SendAgentShutdown notifies the server of the agent shutdown and handles any errors during the API call.
func SendAgentShutdown() {
	_, err := shared.State.SdkClient.Agents.SetAgentShutdown(shared.State.Context, shared.State.AgentID)
	if err != nil {
		handleAPIError("Error notifying server of agent shutdown", err, operations.SeverityCritical)
	}
}

// sendCrackedHash sends a cracked hash result to the task server and logs relevant information.
// If the task pointer is nil, it logs an error and returns early.
// Constructs a HashcatResult object and sends it to the server via the SDK client.
// Logs and handles any errors encountered during the sending process.
// If configured, writes the cracked hash to a file.
// Logs additional information based on the HTTP response status.
func sendCrackedHash(timestamp time.Time, hash string, plaintext string, task *components.Task) {
	if task == nil {
		shared.Logger.Error("Task is nil")

		return
	}

	hashcatResult := &components.HashcatResult{
		Timestamp: timestamp,
		Hash:      hash,
		PlainText: plaintext,
	}

	shared.Logger.Info("Cracked hash", "hash", hash, "plaintext", plaintext)

	response, err := shared.State.SdkClient.Tasks.SendCrack(shared.State.Context, task.GetID(), hashcatResult)
	if err != nil {
		handleSendCrackError(err)

		return
	}

	if shared.State.WriteZapsToFile {
		hashFile := path.Join(shared.State.ZapsPath, fmt.Sprintf("%d_clientout.zap", task.GetID()))
		file, err := os.OpenFile(hashFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			_ = cserrors.LogAndSendError("Error opening cracked hash file", err, operations.SeverityCritical, task)
			return
		}
		defer file.Close()
		_, err = file.WriteString(fmt.Sprintf("%s:%s", hash, plaintext) + "\n")
		if err != nil {
			_ = cserrors.LogAndSendError("Error writing cracked hash to file", err, operations.SeverityCritical, task)
			return
		}
	}

	shared.Logger.Debug("Cracked hash sent")
	if response.StatusCode == http.StatusNoContent {
		shared.Logger.Info("Hashlist completed", "hash", hash)
	}
}
