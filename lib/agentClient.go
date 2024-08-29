package lib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/duke-git/lancet/convertor"
	"github.com/duke-git/lancet/fileutil"
	"github.com/duke-git/lancet/v2/pointer"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"

	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
)

var (
	// agentPlatform represents the platform on which the agent is running.
	agentPlatform = ""               // agentPlatform represents the platform on which the agent is running.
	Configuration agentConfiguration // agentConfiguration represents the configuration of the agent.
	Context       context.Context    // Context represents the context of the agent.
	SdkClient     *sdk.CipherSwarmAgentSDK
)

// AuthenticateAgent authenticates the agent with the CipherSwarm API.
// It sends an authentication request to the API and checks the response status.
// If the authentication is successful, it sets the agent ID in the shared state.
// If the authentication fails, it returns an error.
// The function returns an error if there is an error connecting to the API or if the response status is not OK.
func AuthenticateAgent() error {
	response, err := SdkClient.Client.Authenticate(Context)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error connecting to the CipherSwarm API", "error", eo.Error())
			return err
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error connecting to the CipherSwarm API, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			return err
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return err
	}

	if response.Object == nil {
		shared.Logger.Error("Error authenticating with the CipherSwarm API")
		return errors.New("failed to authenticate with the CipherSwarm API")
	}

	if !response.GetObject().Authenticated {
		shared.Logger.Error("Failed to authenticate with the CipherSwarm API")
		return errors.New("failed to authenticate with the CipherSwarm API")
	}

	shared.State.AgentID = response.GetObject().AgentID
	return nil
}

func GetAgentConfiguration() error {
	agentConfig := agentConfiguration{}
	response, err := SdkClient.Client.GetConfiguration(Context)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error getting agent configuration", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return err
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error getting agent configuration, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return err
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return err
	}

	if response.Object == nil {
		shared.Logger.Error("Error getting agent configuration")
		return errors.New("failed to get agent configuration")
	}

	config := response.GetObject()

	agentConfig.APIVersion = config.APIVersion
	if config.Config.UseNativeHashcat != nil {
		agentConfig.Config.UseNativeHashcat = *config.Config.UseNativeHashcat
	}
	if config.Config.AgentUpdateInterval != nil {
		agentConfig.Config.AgentUpdateInterval = *config.Config.AgentUpdateInterval
	} else {
		agentConfig.Config.AgentUpdateInterval = 300
	}

	if config.Config.BackendDevice != nil {
		agentConfig.Config.BackendDevices = *config.Config.BackendDevice
	}

	// TODO: Check if the OpenCL devices are set
	// This has not been implemented in the API yet.

	if agentConfig.Config.UseNativeHashcat {
		shared.Logger.Debug("Using native Hashcat")
		// Find the Hashcat binary path
		binPath, err := exec.LookPath("hashcat")
		if err != nil {
			shared.Logger.Error("Error finding hashcat binary: ", err)
			SendAgentError(err.Error(), nil, operations.SeverityCritical)
			return err
		} else {
			shared.Logger.Info("Found Hashcat binary", "path", binPath)
			viper.Set("hashcat_path", binPath)
			_ = viper.WriteConfig()
		}
	} else {
		shared.Logger.Debug("Using server-provided Hashcat binary")
	}

	Configuration = agentConfig

	shared.Logger.Debug("Agent configuration", "config", Configuration)

	return nil
}

func UpdateAgentMetadata() {
	info, err := host.Info()
	if err != nil {
		shared.Logger.Error("Error getting info info: ", err)
		SendAgentError(err.Error(), nil, operations.SeverityCritical)
		return
	}

	// client_signature represents the signature of the client, which includes the CipherSwarm Agent version, operating system,
	//   and kernel architecture.
	clientSignature := fmt.Sprintf("CipherSwarm Agent/%s %s/%s", AgentVersion, info.OS, info.KernelArch)

	devices, err := arch.GetDevices()
	if err != nil {
		shared.Logger.Error("Error getting devices: ", err)
		SendAgentError(err.Error(), nil, operations.SeverityCritical)
	}

	agentPlatform = info.OS
	agentUpdate := &operations.UpdateAgentRequestBody{
		ID:              shared.State.AgentID,
		Name:            info.Hostname,
		ClientSignature: clientSignature,
		OperatingSystem: info.OS,
		Devices:         devices,
	}
	shared.Logger.Debug("Updating agent metadata", "agent_id", shared.State.AgentID, "hostname", info.Hostname, "client_signature", clientSignature, "os", info.OS, "devices", devices)
	response, err := SdkClient.Agents.UpdateAgent(Context, shared.State.AgentID, agentUpdate)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error updating agent metadata", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error updating agent metadata, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}

	if response.Agent != nil {
		DisplayAgentMetadataUpdated(response)
	} else {
		shared.ErrorLogger.Error("bad response: %v", response.RawResponse.Status)
	}

}

// UpdateCracker checks for an updated version of the cracker and performs the necessary updates.
// It connects to the CipherSwarm API to check for updates, downloads the updated cracker if available,
// moves the file to the correct location, extracts the file, and updates the config file with the new hashcat path.
func UpdateCracker() {
	shared.Logger.Info("Checking for updated cracker")
	currentVersion, err := getCurrentHashcatVersion()
	if err != nil {
		shared.Logger.Error("Error getting current hashcat version", "error", err)
		return
	}

	response, err := SdkClient.Crackers.CheckForCrackerUpdate(Context, &agentPlatform, &currentVersion)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error connecting to the CipherSwarm API", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error connecting to the CipherSwarm API, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}

	if response.StatusCode == http.StatusNoContent {
		shared.Logger.Debug("No new cracker available")
		return
	}

	if response.StatusCode == http.StatusOK {
		update := response.GetCrackerUpdate()
		if update.GetAvailable() {
			DisplayNewCrackerAvailable(update)

			// Get the file to a temporary location and then move it to the correct location
			// This is to prevent the file from being corrupted if the download is interrupted
			tempDir, err := os.MkdirTemp("", "cipherswarm-*")
			if err != nil {
				shared.Logger.Error("Error creating temporary directory: ", "error", err)
				SendAgentError(err.Error(), nil, operations.SeverityCritical)
			}
			defer func(path string) {
				err := os.RemoveAll(path)
				if err != nil {
					shared.Logger.Error("Error removing temporary directory: ", "error", err)
					SendAgentError(err.Error(), nil, operations.SeverityCritical)
				}
			}(tempDir)

			tempArchivePath := path.Join(tempDir, "hashcat.7z")

			err = downloadFile(*update.GetDownloadURL(), tempArchivePath, "")
			if err != nil {
				shared.Logger.Error("Error downloading cracker: ", "error", err)
				SendAgentError(err.Error(), nil, operations.SeverityCritical)
			}
			// Move the file to the correct location in the crackers directory
			newArchivePath, err := moveArchiveFile(tempArchivePath)
			if err != nil {
				shared.Logger.Error("Error moving file: ", "error", err)
				SendAgentError(err.Error(), nil, operations.SeverityCritical)
				return // Don't continue if we can't move the file
			}

			// Extract the file
			// At some point, we should check the hash of the file to make sure it's not corrupted
			// We should also implement 7z extraction in Go, for now we'll use the 7z command
			hashcatDirectory, err := extractHashcatArchive(newArchivePath)
			if err != nil {
				shared.Logger.Error("Error extracting file: ", err)
				SendAgentError(err.Error(), nil, operations.SeverityCritical)
				return // Don't continue if we can't extract the file
			}

			// Check if the new hashcat directory exists
			hashcatExists := fileutil.IsDir(hashcatDirectory)
			if !hashcatExists {
				shared.Logger.Error("New hashcat directory does not exist", "path", hashcatDirectory)
			}

			// Check to make sure there's a hashcat binary in the new directory
			hashcatBinaryPath := path.Join(hashcatDirectory, *update.GetExecName())
			hashcatBinaryExists := fileutil.IsExist(hashcatBinaryPath)
			if !hashcatBinaryExists {
				shared.Logger.Error("New hashcat binary does not exist", "path", hashcatBinaryPath)
			}

			err = os.Remove(newArchivePath)
			if err != nil {
				shared.Logger.Error("Error removing 7z file", "error", err)
				SendAgentError(err.Error(), nil, operations.SeverityWarning)
			}

			// Update the config file with the new hashcat path
			viper.Set(
				"hashcat_path",
				path.Join(shared.State.CrackersPath, "hashcat", *update.GetExecName()),
			)
			_ = viper.WriteConfig()
		} else {
			shared.Logger.Debug("No new cracker available", "latest_version", update.GetLatestVersion())
		}
	} else {
		shared.Logger.Error("Error checking for updated cracker", "CrackerUpdate", response.RawResponse.Status)
	}
}

// GetNewTask retrieves a new task from the CipherSwarm API.
// It returns the new task if available, or nil if no new task is available.
// If there is an error connecting to the API, it logs the error and returns the error.
func GetNewTask() (*components.Task, error) {
	response, err := SdkClient.Tasks.GetNewTask(Context)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error getting new task", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return nil, err
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error getting new task, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return nil, err
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return nil, err
	}
	if response.StatusCode == http.StatusNoContent {
		// No new task available
		return nil, nil
	}

	if response.StatusCode == http.StatusOK {
		// New task available
		return response.Task, nil
	}

	return nil, errors.New("bad response: " + response.RawResponse.Status)
}

// GetAttackParameters retrieves the attack parameters for the specified attack ID.
// It makes a request to the CipherSwarm API using the SdkClient and returns the attack parameters if the request is successful.
// If there is an error connecting to the API or if the response status is not OK, an error is returned.
func GetAttackParameters(attackID int64) (*components.Attack, error) {
	response, err := SdkClient.Attacks.GetAttack(Context, attackID)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error getting attack parameters", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return nil, err
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error getting attack parameters, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return nil, err
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return nil, err
	}

	if response.StatusCode == http.StatusOK {
		return response.Attack, nil
	}
	return nil, errors.New("bad response: " + response.RawResponse.Status)
}

// sendBenchmarkResults sends benchmark results to the SDK client.
// It takes a slice of BenchmarkResult as input and returns an error if any.
// The function iterates over the benchmark results and converts the necessary fields to their respective types.
// Then, it creates a HashcatBenchmark object and appends it to the results slice.
// Finally, it submits the benchmark results to the SDK client using the SdkClient.Agents.SubmitBenchmark method.
// If the submission is successful (HTTP status code 204), it returns nil.
// Otherwise, it returns an error with the corresponding status message.
func sendBenchmarkResults(benchmarkResults []BenchmarkResult) error {
	var benchmarks []components.HashcatBenchmark
	for _, result := range benchmarkResults {
		hashType, err := convertor.ToInt(result.HashType)
		if err != nil {
			continue
		}
		runtimeMs, err := convertor.ToInt(result.RuntimeMs)
		if err != nil {
			continue
		}
		speedHs, err := convertor.ToFloat(result.SpeedHs)
		if err != nil {
			continue
		}
		device, err := convertor.ToInt(result.Device)
		if err != nil {
			continue
		}

		benchmark := components.HashcatBenchmark{
			HashType:  hashType,
			Runtime:   runtimeMs,
			HashSpeed: speedHs,
			Device:    device,
		}

		benchmarks = append(benchmarks, benchmark)
	}

	results := operations.SubmitBenchmarkRequestBody{
		HashcatBenchmarks: benchmarks,
	}

	res, err := SdkClient.Agents.SubmitBenchmark(Context, shared.State.AgentID, results)
	if err != nil {
		return err
	}

	if res.StatusCode == http.StatusNoContent {
		return nil
	}
	return errors.New("bad response: " + res.RawResponse.Status)
}

// UpdateBenchmarks updates the benchmarks for the agent.
// It creates a new hashcat session for benchmarking and sends the benchmark results.
// If any error occurs during the process, it logs the error and sends an agent error.
func UpdateBenchmarks() {
	jobParams := hashcat.Params{
		AttackMode:                hashcat.AttackBenchmark,
		AdditionalArgs:            arch.GetAdditionalHashcatArgs(),
		BackendDevices:            Configuration.Config.BackendDevices,
		OpenCLDevices:             Configuration.Config.OpenCLDevices,
		EnableAdditionalHashTypes: shared.State.EnableAdditionalHashTypes,
	}

	sess, err := hashcat.NewHashcatSession("benchmark", jobParams)
	if err != nil {
		shared.Logger.Error("Failed to create benchmark session", "error", err)
		SendAgentError(err.Error(), nil, operations.SeverityMajor)
		return
	}
	shared.Logger.Debug("Starting benchmark session", "cmdline", sess.CmdLine())

	DisplayBenchmarkStarting()
	benchmarkResult, done := RunBenchmarkTask(sess)
	if done {
		return
	}
	DisplayBenchmarksComplete(benchmarkResult)
	err = sendBenchmarkResults(benchmarkResult)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error updating benchmarks", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error updating benchmarks, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}
}

// DownloadFiles downloads the necessary files for the given attack.
// It downloads the hashlist, wordlists, and rulelists required for the attack.
// The downloaded files are saved to the specified file paths.
// If any error occurs during the download process, the function returns the error.
func DownloadFiles(attack *components.Attack) error {
	DisplayDownloadFileStart(attack)

	err := downloadHashList(attack)
	if err != nil {
		return err
	}

	// Download all resource files

	err = downloadResourceFile(attack.WordList)
	if err != nil {
		return err
	}

	err = downloadResourceFile(attack.RuleList)
	if err != nil {
		return err
	}

	err = downloadResourceFile(attack.MaskList)
	if err != nil {
		return err
	}

	return nil
}

func downloadResourceFile(resource *components.AttackResourceFile) error {
	if resource == nil {
		return nil
	}

	filePath := path.Join(shared.State.FilePath, resource.FileName)
	shared.Logger.Debug("Downloading resource file", "url", resource.GetDownloadURL(), "path", filePath)
	checksum := ""
	if shared.State.AlwaysTrustFiles {
		shared.Logger.Debug("Skipping checksum verification")
	} else {
		// Check the checksum of the file
		checksum = base64ToHex(resource.GetChecksum())
	}
	err := downloadFile(resource.GetDownloadURL(), filePath, checksum)
	if err != nil {
		shared.Logger.Error("Error downloading attack resource", "error", err)
		SendAgentError(err.Error(), nil, operations.SeverityCritical)
		return err
	}
	downloadSize, _ := fileutil.FileSize(filePath)
	if downloadSize == 0 {
		shared.Logger.Error("Downloaded file is empty", "path", filePath)
		SendAgentError("Downloaded file is empty", nil, operations.SeverityCritical)
		return errors.New("downloaded file is empty")
	}
	shared.Logger.Debug("Downloaded resource file", "path", filePath)

	return nil
}

// SendHeartBeat sends a heartbeat to the server and returns the agent heartbeat response state.
// If an error occurs while sending the heartbeat, it logs the error and sends an agent error.
// If the response status code is http.StatusNoContent, it logs that the heartbeat was sent and returns nil.
// If the response status code is http.StatusOK, it logs that the heartbeat was sent and checks the agent heartbeat response state.
// It logs the corresponding agent state based on the response state and returns a pointer to the response state.
// If the response status code is neither http.StatusNoContent nor http.StatusOK, it returns nil.
func SendHeartBeat() *operations.State {
	resp, err := SdkClient.Agents.SendHeartbeat(Context, shared.State.AgentID)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error sending heartbeat", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return nil
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error sending heartbeat, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return nil
		}
		// This isn't a critical error, but we should log it, just in case
		shared.ErrorLogger.Error("Error communicating with the CipherSwarm API", "error", err)
		return nil
	}
	// All good, nothing to see here
	// We are not being asked to change anything
	if resp.StatusCode == http.StatusNoContent {

		if shared.State.ExtraDebugging {
			shared.Logger.Debug("Heartbeat sent")
		}
		shared.State.JobCheckingStopped = false // Reset the flag
		return nil
	}

	// We are being asked to change something, so we need to check the response
	if resp.StatusCode == http.StatusOK {
		if shared.State.ExtraDebugging {
			shared.Logger.Debug("Heartbeat sent")
		}
		stateResponse := resp.GetObject()
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

	return nil
}

// RunTask executes a task using the provided attack parameters.
// It creates a hashcat session based on the attack parameters and runs the attack task.
// If the task is accepted, it displays a message indicating that the task has been accepted.
// After the attack task is completed, it displays a message indicating that the task has been completed.
// If any error occurs during the process, it logs the error and returns.
func RunTask(task *components.Task, attack *components.Attack) {
	DisplayRunTaskStarting(task)
	// Create the hashcat session

	if attack == nil {
		shared.Logger.Error("Attack is nil")
		SendAgentError("Attack is nil", task, operations.SeverityCritical)
		return
	}

	// TODO: Need to unify the AttackParameters and HashcatParams structs
	jobParams := hashcat.Params{
		AttackMode:       pointer.UnwrapOr(attack.AttackModeHashcat),
		HashType:         pointer.UnwrapOr(attack.HashMode),
		HashFile:         path.Join(shared.State.HashlistPath, convertor.ToString(attack.GetHashListID())+".txt"),
		Mask:             pointer.UnwrapOr(attack.GetMask(), ""),
		MaskIncrement:    pointer.UnwrapOr(attack.GetIncrementMode(), false),
		MaskIncrementMin: attack.GetIncrementMinimum(),
		MaskIncrementMax: attack.GetIncrementMaximum(),
		MaskCustomCharsets: []string{
			pointer.UnwrapOr(attack.GetCustomCharset1(), ""),
			pointer.UnwrapOr(attack.GetCustomCharset2(), ""),
			pointer.UnwrapOr(attack.GetCustomCharset3(), ""),
			pointer.UnwrapOr(attack.GetCustomCharset4(), ""),
		},
		WordListFilename: resourceNameOrBlank(attack.WordList),
		RuleListFilename: resourceNameOrBlank(attack.RuleList),
		MaskListFilename: resourceNameOrBlank(attack.MaskList),
		AdditionalArgs:   arch.GetAdditionalHashcatArgs(),
		OptimizedKernels: *attack.Optimized,
		SlowCandidates:   *attack.SlowCandidateGenerators,
		Skip:             pointer.UnwrapOr(task.GetSkip(), 0),
		Limit:            pointer.UnwrapOr(task.GetLimit(), 0),
		BackendDevices:   Configuration.Config.BackendDevices,
		OpenCLDevices:    Configuration.Config.OpenCLDevices,
		RestoreFilePath:  path.Join(shared.State.RestoreFilePath, convertor.ToString(attack.GetID())+".restore"),
	}

	sess, err := hashcat.NewHashcatSession(convertor.ToString(attack.GetID()), jobParams)
	if err != nil {
		shared.Logger.Error("Failed to create attack session", "error", err)
		SendAgentError(err.Error(), task, operations.SeverityCritical)
		return
	}

	RunAttackTask(sess, task)
	DisplayRunTaskCompleted()
}

// sendStatusUpdate sends a status update to the server for a given task.
// It takes a hashcat.Status object and a pointer to a cipherswarm.Task object as parameters.
// The function first checks if the update.Time field is zero and sets it to the current time if it is.
// Then, it creates a list of cipherswarm.DeviceStatus objects based on the update.Devices field.
// Next, it creates a cipherswarm.HashcatGuess object based on the update.Guess field.
// After that, it creates a cipherswarm.TaskStatus object based on the update and the previously created objects.
// Finally, it submits the task status to the server using the apiClient.TasksAPI.SubmitStatus method.
// If there is an error during the submission, an error message is logged and the function returns.
// If the submission is successful, a debug message is logged.
func sendStatusUpdate(update hashcat.Status, task *components.Task, sess *hashcat.Session) {
	// Hashcat doesn't seem to update the time consistently, so we'll set it here
	if update.Time.IsZero() {
		update.Time = time.Now()
	}
	if shared.State.ExtraDebugging {
		shared.Logger.Debug("Sending status update", "status", update)
	}

	deviceStatuses := make([]components.DeviceStatus, len(update.Devices))
	for i, device := range update.Devices {
		deviceStatus := components.DeviceStatus{
			DeviceID:    device.DeviceID,
			DeviceName:  device.DeviceName,
			DeviceType:  parseStringToDeviceType(device.DeviceType),
			Speed:       device.Speed,
			Utilization: device.Util,
			Temperature: device.Temp,
		}
		deviceStatuses[i] = deviceStatus
	}

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

	// We'll do something with the status update responses at some point. Maybe tell the job to stop or pause.
	resp, err := SdkClient.Tasks.SendStatus(Context, task.GetID(), taskStatus)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			// There's a few responses that are errors:
			// 401	Unauthorized
			// 422	malformed status data
			// nothing we can do about these

			shared.Logger.Error("Error sending status update", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			// There's a few responses are error-like:
			// 404	Task not found
			// 410	status received successfully, but task paused
			// these are fine and we can just keep going

			if se.StatusCode == http.StatusNotFound {
				// The task has been deleted by the server, which means we need to kill the task
				// This can happen because another agent has taken the task or because the attack has been deleted
				shared.Logger.Error("Task not found", "task_id", task.GetID())
				// Going to kill the task here
				shared.Logger.Info("Killing task", "task_id", task.GetID())
				shared.Logger.Info("It is possible that multiple errors appear as the task takes some time to kill. This is expected.")
				err = sess.Kill()
				if err != nil {
					shared.Logger.Error("Error killing task", "error", err)
					SendAgentError(err.Error(), nil, operations.SeverityCritical)
				}
				sess.Cleanup()
				return
			}

			if se.StatusCode == http.StatusGone {
				// The task has been paused by the server and we need to pause it
				shared.Logger.Info("Pausing task", "task_id", task.GetID())
				// TODO: Implement pausing the task
				// err = sess.Pause()
				err = sess.Kill()
				if err != nil {
					shared.Logger.Error("Error pausing task", "error", err)
					SendAgentError(err.Error(), task, operations.SeverityFatal)
				}

				return
			}

			shared.Logger.Error("Error connecting to the CipherSwarm API, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}

	// There's a few possible responses that aren't actually errors:
	// 202	status received successfully, but stale
	// 204	status received successfully

	if resp.StatusCode == http.StatusNoContent {
		// Everything is fine. We'll just keep going
		if shared.State.ExtraDebugging {
			shared.Logger.Debug("Status update sent")
		}
		return
	}

	if resp.StatusCode == http.StatusAccepted {
		// The status was sent successfully, but there's new zaps we need to download
		shared.Logger.Debug("Status update sent, but stale")
		getZaps(task)
		return
	}
}

// getZaps retrieves the Zaps for a given task.
// It takes a pointer to a `components.Task` as a parameter.
// If the task is nil, it logs an error and returns.
// Otherwise, it calls the `GetTaskZaps` method of the `SdkClient` to get the Zaps for the task.
// If there is an error, it logs the error.
// If the response stream is not nil, it creates a zap file named after the task ID and writes the response stream to it.
// If there is an error creating the zap file, it logs the error, sends an agent error, and returns.
// Finally, it closes the zap file.
func getZaps(task *components.Task) {
	if task == nil {
		shared.Logger.Error("Task is nil")
		return
	}

	DisplayJobGetZap(task)

	res, err := SdkClient.Tasks.GetTaskZaps(Context, task.GetID())
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error getting zaps from server", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error getting zaps from server, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}

	if res.ResponseStream != nil {
		// Create a zap file named for the task ID and write the response stream to it
		zapFilePath := path.Join(shared.State.ZapsPath, fmt.Sprintf("%d.zap", task.GetID()))
		if fileutil.IsExist(zapFilePath) {
			shared.Logger.Debug("Zap file already exists", "path", zapFilePath)
			err = fileutil.RemoveFile(zapFilePath)
			if err != nil {
				shared.Logger.Error("Error removing existing zap file", "error", err)
				SendAgentError(err.Error(), task, operations.SeverityCritical)
			}
		}

		outFile, err := os.Create(zapFilePath)
		if err != nil {
			shared.Logger.Error("Error creating zap file", "error", err)
			SendAgentError(err.Error(), task, operations.SeverityCritical)
			return
		}
		defer func(outFile *os.File) {
			err := outFile.Close()
			if err != nil {
				shared.Logger.Error("Error closing zap file", "error", err)
				SendAgentError(err.Error(), task, operations.SeverityCritical)
			}
		}(outFile)
		_, err = io.Copy(outFile, res.ResponseStream)
		if err != nil {
			shared.Logger.Error("Error writing zap file", "error", err)
			SendAgentError(err.Error(), task, operations.SeverityCritical)
		}
	}
}

// SendAgentError sends an agent error to the server.
// It takes the following parameters:
// - stdErrLine: a string representing the error message.
// - task: a pointer to a Task object representing the task associated with the error.
// - severity: a Severity object representing the severity of the error.
//
// If the task parameter is nil, the taskID will be set to nil.
// Otherwise, the taskID will be set to the ID of the task.
//
// The function creates a Metadata object with the current error date and additional metadata,
// such as the agent platform and version.
//
// It then creates an AgentError object with the error message, metadata, severity, agent ID,
// and task ID.
//
// Finally, it submits the agent error to the server using the SdkClient.Agents.SubmitErrorAgent method.
// If there is an error during the submission, it logs the error using the shared.Logger.Error method.
func SendAgentError(stdErrLine string, task *components.Task, severity operations.Severity) {
	var taskID *int64
	if task == nil {
		taskID = nil
	} else {
		taskID = &task.ID
	}

	metadata := &operations.Metadata{
		ErrorDate: time.Now(),
		Other: map[string]any{
			"platform": agentPlatform,
			"version":  AgentVersion,
		},
	}

	var agentError = &operations.SubmitErrorAgentRequestBody{
		Message:  stdErrLine,
		Metadata: metadata,
		Severity: severity,
		AgentID:  shared.State.AgentID,
		TaskID:   taskID,
	}
	_, err := SdkClient.Agents.SubmitErrorAgent(Context, shared.State.AgentID, agentError)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error sending agent error to server", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error sending agent error to server, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}

}

// AcceptTask accepts a task and returns a boolean indicating whether the task was accepted successfully.
// It takes a pointer to a `components.Task` as input.
// If the task is nil, it logs an error message and returns false.
// If there is an error while accepting the task, it checks the type of error and handles it accordingly:
// - If the error is of type `sdkerrors.ErrorObject`, it logs an error message, sends an agent error, and returns false.
// - If the error is of type `sdkerrors.SDKError`, it logs an error message, sends an agent error with severity set to "Critical", and returns false.
// If there are no errors, it logs a debug message and returns true.
func AcceptTask(task *components.Task) bool {
	if task == nil {
		shared.Logger.Error("Task is nil")
		return false
	}

	_, err := SdkClient.Tasks.SetTaskAccepted(Context, task.GetID())
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			// There's a few responses that are errors:
			// 404 Task not found
			// 422 Task already completed
			// In these cases, we can just keep going because the task is either complete or deleted
			// Both of these are expected and we don't need to do anything
			shared.Logger.Error("Error accepting task", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityInfo)
			return false
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			// In this case, we have an unexpected error and we need to log it
			shared.Logger.Error("Error accepting task, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return false
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return false
	}

	shared.Logger.Debug("Task accepted")
	return true
}

// markTaskExhausted marks a task as exhausted.
// If the task is nil, it logs an error and returns.
// Otherwise, it notifies the server that the task is exhausted.
// If there is an error notifying the server, it logs the error and sends an agent error.
func markTaskExhausted(task *components.Task) {
	if task == nil {
		shared.Logger.Error("Task is nil")
		return
	}
	_, err := SdkClient.Tasks.SetTaskExhausted(Context, task.GetID())
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error notifying server of task exhaustion", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error notifying server of task exhaustion, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}
}

// SendAgentShutdown sends a request to shut down the agent.
// It calls the SetAgentShutdown method of the SdkClient to set the agent's shutdown state.
// If an error occurs during the shutdown process, it logs the error and sends an agent error message.
func SendAgentShutdown() {
	_, err := SdkClient.Agents.SetAgentShutdown(Context, shared.State.AgentID)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error notifying server of task shutdown", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error notifying server of task shutdown, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}
}

// AbandonTask abandons the given task.
// If the task is nil, it logs an error and returns.
// Otherwise, it notifies the server that the task has been abandoned.
// If there is an error notifying the server, it logs the error and sends an agent error.
func AbandonTask(task *components.Task) {
	if task == nil {
		shared.Logger.Error("Task is nil")
		return
	}

	_, err := SdkClient.Tasks.SetTaskAbandoned(Context, task.GetID())
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			shared.Logger.Error("Error notifying server of task abandonment", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityCritical)
			return
		}
		var er *sdkerrors.SetTaskAbandonedResponseBody
		if errors.As(err, &er) {
			// The task could not be updated properly on the server to be abandoned
			shared.Logger.Error("Notified server of task abandonment, but it could not update the task properly", "error", er.State)
			SendAgentError(er.Error(), nil, operations.SeverityWarning)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error notifying server of task abandonment, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}
}

// sendCrackedHash sends a cracked hash to the server.
// It takes a `hashcat.Result` object representing the cracked hash,
// and a pointer to a `components.Task` object representing the task.
// It logs the cracked hash and plaintext, and sends the cracked hash to the server.
// If there is an error sending the cracked hash, it logs the error and sends an agent error.
// If the response status code is `http.StatusNoContent`, it logs that the hashlist is completed.
func sendCrackedHash(hash hashcat.Result, task *components.Task) {
	hashcatResult := &components.HashcatResult{
		Timestamp: hash.Timestamp,
		Hash:      hash.Hash,
		PlainText: hash.Plaintext,
	}

	if task == nil {
		shared.Logger.Error("Task is nil")
		return
	}

	shared.Logger.Info("Cracked hash", "hash", hash.Hash, "plaintext", hash.Plaintext)

	response, err := SdkClient.Tasks.SendCrack(Context, task.GetID(), hashcatResult)
	if err != nil {
		var eo *sdkerrors.ErrorObject
		if errors.As(err, &eo) {
			// There is only one error that can happen here:
			// 404	Task not found
			shared.Logger.Error("Error notifying server of cracked hash, task not found", "error", eo.Error())
			SendAgentError(eo.Error(), nil, operations.SeverityMajor)
			return
		}
		var se *sdkerrors.SDKError
		if errors.As(err, &se) {
			shared.Logger.Error("Error sending cracked hash to server, unexpected error",
				"status_code", se.StatusCode,
				"message", se.Message)
			SendAgentError(se.Error(), nil, operations.SeverityCritical)
			return
		}
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
		return
	}

	if shared.State.WriteZapsToFile {
		// Write the cracked hash to a file
		hashOut := fmt.Sprintf("%s:%s\n", hash.Hash, hash.Plaintext)
		hashFile := path.Join(shared.State.ZapsPath, fmt.Sprintf("%d_clientout.zap", task.GetID()))
		err := fileutil.WriteStringToFile(hashFile, hashOut, true)
		if err != nil {
			shared.Logger.Error("Error writing cracked hash to file", "error", err)
			SendAgentError(err.Error(), nil, operations.SeverityCritical)
		}
	}

	shared.Logger.Debug("Cracked hash sent")
	if response.StatusCode == http.StatusNoContent {
		shared.Logger.Info("Hashlist completed", "hash", hash.Hash)
	}
}
