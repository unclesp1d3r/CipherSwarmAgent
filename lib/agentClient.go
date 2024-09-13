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

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/pointer"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/viper"
	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

var (
	agentPlatform string                   // agentPlatform represents the platform on which the agent is running.
	Configuration agentConfiguration       // Configuration represents the configuration of the agent.
	Context       context.Context          // Context represents the context of the agent.
	SdkClient     *sdk.CipherSwarmAgentSDK // SdkClient is the client for interacting with the CipherSwarm API.
)

// AuthenticateAgent authenticates the agent with the CipherSwarm API.
// It sends an authentication request to the API and checks the response status.
// If the authentication is successful, it sets the agent ID in the shared state.
// If the authentication fails, it returns an error.
// The function returns an error if there is an error connecting to the API or if the response status is not OK.
func AuthenticateAgent() error {
	response, err := SdkClient.Client.Authenticate(Context)
	if err != nil {
		return handleAuthenticationError(err)
	}

	if response.Object == nil || !response.GetObject().Authenticated {
		shared.Logger.Error("Failed to authenticate with the CipherSwarm API")

		return errors.New("failed to authenticate with the CipherSwarm API")
	}

	shared.State.AgentID = response.GetObject().AgentID

	return nil
}

func handleAuthenticationError(err error) error {
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

func GetAgentConfiguration() error {
	response, err := SdkClient.Client.GetConfiguration(Context)
	if err != nil {
		return handleConfigurationError(err)
	}

	if response.Object == nil {
		shared.Logger.Error("Error getting agent configuration")

		return errors.New("failed to get agent configuration")
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

func handleConfigurationError(err error) error {
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

func setNativeHashcatPath() error {
	shared.Logger.Debug("Using native Hashcat")
	binPath, err := exec.LookPath("hashcat")
	if err != nil {
		shared.Logger.Error("Error finding hashcat binary: ", err)
		SendAgentError(err.Error(), nil, operations.SeverityCritical)

		return err
	}
	shared.Logger.Info("Found Hashcat binary", "path", binPath)
	viper.Set("hashcat_path", binPath)

	return viper.WriteConfig()
}

func UpdateAgentMetadata() error {
	info, err := host.Info()
	if err != nil {
		return logAndSendError("Error getting host info", err, operations.SeverityCritical, nil)
	}

	clientSignature := fmt.Sprintf("CipherSwarm Agent/%s %s/%s", AgentVersion, info.OS, info.KernelArch)

	devices, err := getDevicesList()
	if err != nil {
		return logAndSendError("Error getting devices", err, operations.SeverityCritical, nil)
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
		handleAPIError("Error updating agent metadata", err, operations.SeverityCritical)

		return err
	}

	if response.Agent != nil {
		displayAgentMetadataUpdated(response)
	} else {
		shared.ErrorLogger.Error("bad response: %v", response.RawResponse.Status)

		return errors.New("bad response: " + response.RawResponse.Status)
	}

	return nil
}

func getDevicesList() ([]string, error) {
	if shared.State.UseLegacyDeviceIdentificationMethod {
		return arch.GetDevices()
	}

	return getDevices()
}

// getDevices retrieves the devices available for the agent.
// It creates a test hashcat session and runs the test task to get the devices.
// If the test task is successful, it returns the devices.
// Right now it just returns a slice of strings, but we could return more information about the devices in the future.
// Probably device_id, device_name, and device_type.
func getDevices() ([]string, error) {
	jobParams := hashcat.Params{
		AttackMode:     hashcat.AttackModeMask,
		AdditionalArgs: arch.GetAdditionalHashcatArgs(),
		HashFile:       "60b725f10c9c85c70d97880dfe8191b3", // "a"
		Mask:           "?l",
		OpenCLDevices:  "1,2,3",
	}

	sess, err := hashcat.NewHashcatSession("test", jobParams)
	if err != nil {
		return nil, logAndSendError("Failed to create test session", err, operations.SeverityMajor, nil)
	}

	testStatus, err := runTestTask(sess)
	if err != nil {
		return nil, logAndSendError("Error running test task", err, operations.SeverityFatal, nil)
	}

	return extractDeviceNames(testStatus.Devices), nil
}

func logAndSendError(message string, err error, severity operations.Severity, task *components.Task) error {
	shared.Logger.Error(message, "error", err)
	SendAgentError(err.Error(), task, severity)

	return err
}

func extractDeviceNames(deviceStatuses []hashcat.StatusDevice) []string {
	devices := make([]string, len(deviceStatuses))
	for i, device := range deviceStatuses {
		devices[i] = device.DeviceName
	}

	return devices
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
		handleAPIError("Error connecting to the CipherSwarm API", err, operations.SeverityCritical)

		return
	}

	if response.StatusCode == http.StatusNoContent {
		shared.Logger.Debug("No new cracker available")

		return
	}

	if response.StatusCode == http.StatusOK {
		update := response.GetCrackerUpdate()
		if update.GetAvailable() {
			_ = handleCrackerUpdate(update)
		} else {
			shared.Logger.Debug("No new cracker available", "latest_version", update.GetLatestVersion())
		}
	} else {
		shared.Logger.Error("Error checking for updated cracker", "CrackerUpdate", response.RawResponse.Status)
	}
}

func handleCrackerUpdate(update *components.CrackerUpdate) error {
	displayNewCrackerAvailable(update)

	tempDir, err := os.MkdirTemp("", "cipherswarm-*")
	if err != nil {
		return logAndSendError("Error creating temporary directory", err, operations.SeverityCritical, nil)
	}
	defer func(tempDir string) {
		_ = cleanupTempDir(tempDir)
	}(tempDir)

	tempArchivePath := path.Join(tempDir, "hashcat.7z")
	if err := downloadFile(*update.GetDownloadURL(), tempArchivePath, ""); err != nil {
		return logAndSendError("Error downloading cracker", err, operations.SeverityCritical, nil)
	}

	newArchivePath, err := moveArchiveFile(tempArchivePath)
	if err != nil {
		return logAndSendError("Error moving file", err, operations.SeverityCritical, nil)
	}

	hashcatDirectory, err := extractHashcatArchive(newArchivePath)
	if err != nil {
		return logAndSendError("Error extracting file", err, operations.SeverityCritical, nil)
	}

	if !validateHashcatDirectory(hashcatDirectory, *update.GetExecName()) {
		return nil
	}

	if err := os.Remove(newArchivePath); err != nil {
		_ = logAndSendError("Error removing 7z file", err, operations.SeverityWarning, nil)
	}

	viper.Set("hashcat_path", path.Join(shared.State.CrackersPath, "hashcat", *update.GetExecName()))
	_ = viper.WriteConfig()

	return nil
}

func cleanupTempDir(tempDir string) error {
	if err := os.RemoveAll(tempDir); err != nil {
		return logAndSendError("Error removing temporary directory", err, operations.SeverityCritical, nil)
	}

	return nil
}

func validateHashcatDirectory(hashcatDirectory, execName string) bool {
	if !fileutil.IsDir(hashcatDirectory) {
		shared.Logger.Error("New hashcat directory does not exist", "path", hashcatDirectory)

		return false
	}

	hashcatBinaryPath := path.Join(hashcatDirectory, execName)
	if !fileutil.IsExist(hashcatBinaryPath) {
		shared.Logger.Error("New hashcat binary does not exist", "path", hashcatBinaryPath)

		return false
	}

	return true
}

// GetNewTask retrieves a new task from the CipherSwarm API.
// It returns the new task if available, or nil if no new task is available.
// If there is an error connecting to the API, it logs the error and returns the error.
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

// GetAttackParameters retrieves the attack parameters for the specified attack ID.
// It makes a request to the CipherSwarm API using the SdkClient and returns the attack parameters if the request is successful.
// If there is an error connecting to the API or if the response status is not OK, an error is returned.
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

// sendBenchmarkResults sends benchmark results to the SDK client.
// It takes a slice of benchmarkResult as input and returns an error if any.
// The function iterates over the benchmark results and converts the necessary fields to their respective types.
// Then, it creates a HashcatBenchmark object and appends it to the results slice.
// Finally, it submits the benchmark results to the SDK client using the SdkClient.Agents.SubmitBenchmark method.
// If the submission is successful (HTTP status code 204), it returns nil.
// Otherwise, it returns an error with the corresponding status message.
func sendBenchmarkResults(benchmarkResults []benchmarkResult) error {
	var benchmarks []components.HashcatBenchmark //nolint:prealloc

	for _, result := range benchmarkResults {
		benchmark, err := createBenchmark(result)
		if err != nil {
			continue
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

func createBenchmark(result benchmarkResult) (components.HashcatBenchmark, error) {
	hashType, err := convertor.ToInt(result.HashType)
	if err != nil {
		return components.HashcatBenchmark{}, fmt.Errorf("failed to convert HashType: %w", err)
	}
	runtimeMs, err := convertor.ToInt(result.RuntimeMs)
	if err != nil {
		return components.HashcatBenchmark{}, fmt.Errorf("failed to convert RuntimeMs: %w", err)
	}
	speedHs, err := convertor.ToFloat(result.SpeedHs)
	if err != nil {
		return components.HashcatBenchmark{}, fmt.Errorf("failed to convert SpeedHs: %w", err)
	}
	device, err := convertor.ToInt(result.Device)
	if err != nil {
		return components.HashcatBenchmark{}, fmt.Errorf("failed to convert Device: %w", err)
	}

	return components.HashcatBenchmark{
		HashType:  hashType,
		Runtime:   runtimeMs,
		HashSpeed: speedHs,
		Device:    device,
	}, nil
}

// UpdateBenchmarks updates the benchmarks for the agent.
// It creates a new hashcat session for benchmarking and sends the benchmark results.
// If any error occurs during the process, it logs the error and sends an agent error.
func UpdateBenchmarks() error {
	jobParams := hashcat.Params{
		AttackMode:                hashcat.AttackBenchmark,
		AdditionalArgs:            arch.GetAdditionalHashcatArgs(),
		BackendDevices:            Configuration.Config.BackendDevices,
		OpenCLDevices:             Configuration.Config.OpenCLDevices,
		EnableAdditionalHashTypes: shared.State.EnableAdditionalHashTypes,
	}

	sess, err := hashcat.NewHashcatSession("benchmark", jobParams)
	if err != nil {
		return logAndSendError("Failed to create benchmark session", err, operations.SeverityMajor, nil)
	}
	shared.Logger.Debug("Starting benchmark session", "cmdline", sess.CmdLine())

	displayBenchmarkStarting()
	benchmarkResult, done := runBenchmarkTask(sess)
	if done {
		return nil
	}
	displayBenchmarksComplete(benchmarkResult)
	if err := sendBenchmarkResults(benchmarkResult); err != nil {
		return logAndSendError("Error updating benchmarks", err, operations.SeverityCritical, nil)
	}

	return nil
}

// DownloadFiles downloads the necessary files for the given attack.
// It downloads the hashlist, wordlists, and rulelists required for the attack.
// The downloaded files are saved to the specified file paths.
// If any error occurs during the download process, the function returns the error.
func DownloadFiles(attack *components.Attack) error {
	displayDownloadFileStart(attack)

	if err := downloadHashList(attack); err != nil {
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

func downloadResourceFile(resource *components.AttackResourceFile) error {
	if resource == nil {
		return nil
	}

	filePath := path.Join(shared.State.FilePath, resource.FileName)
	shared.Logger.Debug("Downloading resource file", "url", resource.GetDownloadURL(), "path", filePath)

	checksum := ""
	if !shared.State.AlwaysTrustFiles {
		checksum = base64ToHex(resource.GetChecksum())
	} else {
		shared.Logger.Debug("Skipping checksum verification")
	}

	if err := downloadFile(resource.GetDownloadURL(), filePath, checksum); err != nil {
		return logAndSendError("Error downloading attack resource", err, operations.SeverityCritical, nil)
	}

	if downloadSize, _ := fileutil.FileSize(filePath); downloadSize == 0 {
		return logAndSendError("Downloaded file is empty", nil, operations.SeverityCritical, nil)
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

func handleHeartbeatError(err error) {
	switch e := err.(type) {
	case *sdkerrors.ErrorObject:
		_ = logAndSendError("Error sending heartbeat", e, operations.SeverityCritical, nil)
	case *sdkerrors.SDKError:
		shared.Logger.Error("Error sending heartbeat, unexpected error",
			"status_code", e.StatusCode,
			"message", e.Message)
		SendAgentError(e.Error(), nil, operations.SeverityCritical)
	default:
		shared.ErrorLogger.Error("Error communicating with the CipherSwarm API", "error", err)
	}
}

func logHeartbeatSent() {
	if shared.State.ExtraDebugging {
		shared.Logger.Debug("Heartbeat sent")
	}
	shared.State.JobCheckingStopped = false
}

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

// RunTask executes a task using the provided attack parameters.
// It creates a hashcat session based on the attack parameters and runs the attack task.
// If the task is accepted, it displays a message indicating that the task has been accepted.
// After the attack task is completed, it displays a message indicating that the task has been completed.
// If any error occurs during the process, it logs the error and returns.
func RunTask(task *components.Task, attack *components.Attack) error {
	displayRunTaskStarting(task)

	if attack == nil {
		return logAndSendError("Attack is nil", errors.New("attack is nil"), operations.SeverityCritical, task)
	}

	jobParams := createJobParams(task, attack)
	sess, err := hashcat.NewHashcatSession(convertor.ToString(attack.GetID()), jobParams)
	if err != nil {
		return logAndSendError("Failed to create attack session", err, operations.SeverityCritical, task)
	}

	runAttackTask(sess, task)
	displayRunTaskCompleted()

	return nil
}

func createJobParams(task *components.Task, attack *components.Attack) hashcat.Params {
	return hashcat.Params{
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

func handleTaskNotFound(task *components.Task, sess *hashcat.Session) {
	shared.Logger.Error("Task not found", "task_id", task.GetID())
	shared.Logger.Info("Killing task", "task_id", task.GetID())
	shared.Logger.Info("It is possible that multiple errors appear as the task takes some time to kill. This is expected.")
	if err := sess.Kill(); err != nil {
		_ = logAndSendError("Error killing task", err, operations.SeverityCritical, task)
	}
	sess.Cleanup()
}

func handleTaskGone(task *components.Task, sess *hashcat.Session) {
	shared.Logger.Info("Pausing task", "task_id", task.GetID())
	if err := sess.Kill(); err != nil {
		_ = logAndSendError("Error pausing task", err, operations.SeverityFatal, task)
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

func removeExistingZapFile(zapFilePath string) error {
	if fileutil.IsExist(zapFilePath) {
		shared.Logger.Debug("Zap file already exists", "path", zapFilePath)

		return fileutil.RemoveFile(zapFilePath)
	}

	return nil
}

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

// AcceptTask accepts a task and returns a boolean indicating whether the task was accepted successfully.
// It takes a pointer to a `components.Task` as input.
// If the task is nil, it logs an error message and returns false.
// If there is an error while accepting the task, it checks the type of error and handles it accordingly:
// - If the error is of type `sdkerrors.ErrorObject`, it logs an error message, sends an agent error, and returns false.
// - If the error is of type `sdkerrors.SDKError`, it logs an error message, sends an agent error with severity set to "Critical", and returns false.
// If there are no errors, it logs a debug message and returns true.
func AcceptTask(task *components.Task) error {
	if task == nil {
		shared.Logger.Error("Task is nil")

		return errors.New("task is nil")
	}

	_, err := SdkClient.Tasks.SetTaskAccepted(Context, task.GetID())
	if err != nil {
		handleAcceptTaskError(err)

		return err
	}

	shared.Logger.Debug("Task accepted")

	return nil
}

func handleAcceptTaskError(err error) {
	switch e := err.(type) {
	case *sdkerrors.ErrorObject:
		// Handle specific error responses
		shared.Logger.Error("Error accepting task", "error", e.Error())
		SendAgentError(e.Error(), nil, operations.SeverityInfo)
	case *sdkerrors.SDKError:
		// Handle unexpected errors
		shared.Logger.Error("Error accepting task, unexpected error",
			"status_code", e.StatusCode,
			"message", e.Message)
		SendAgentError(e.Error(), nil, operations.SeverityCritical)
	default:
		// Handle critical communication errors
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
	}
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
		handleTaskError(err, "Error notifying server of task exhaustion")
	}
}

// SendAgentShutdown sends a request to shut down the agent.
// It calls the SetAgentShutdown method of the SdkClient to set the agent's shutdown state.
// If an error occurs during the shutdown process, it logs the error and sends an agent error message.
func SendAgentShutdown() {
	_, err := SdkClient.Agents.SetAgentShutdown(Context, shared.State.AgentID)
	if err != nil {
		handleAPIError("Error notifying server of agent shutdown", err, operations.SeverityCritical)
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
		handleTaskError(err, "Error notifying server of task abandonment")
	}
}

func handleTaskError(err error, message string) {
	switch e := err.(type) {
	case *sdkerrors.ErrorObject:
		shared.Logger.Error(message, "error", e.Error())
		SendAgentError(e.Error(), nil, operations.SeverityCritical)
	case *sdkerrors.SetTaskAbandonedResponseBody:
		shared.Logger.Error("Notified server of task abandonment, but it could not update the task properly", "error", e.State)
		SendAgentError(e.Error(), nil, operations.SeverityWarning)
	case *sdkerrors.SDKError:
		shared.Logger.Error(message, "status_code", e.StatusCode, "message", e.Message)
		SendAgentError(e.Error(), nil, operations.SeverityCritical)
	default:
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
	}
}

// sendCrackedHash sends a cracked hash to the server.
// It takes a `hashcat.Result` object representing the cracked hash,
// and a pointer to a `components.Task` object representing the task.
// It logs the cracked hash and plaintext, and sends the cracked hash to the server.
// If there is an error sending the cracked hash, it logs the error and sends an agent error.
// If the response status code is `http.StatusNoContent`, it logs that the hashlist is completed.
func sendCrackedHash(hash hashcat.Result, task *components.Task) {
	if task == nil {
		shared.Logger.Error("Task is nil")

		return
	}

	hashcatResult := &components.HashcatResult{
		Timestamp: hash.Timestamp,
		Hash:      hash.Hash,
		PlainText: hash.Plaintext,
	}

	shared.Logger.Info("Cracked hash", "hash", hash.Hash, "plaintext", hash.Plaintext)

	response, err := SdkClient.Tasks.SendCrack(Context, task.GetID(), hashcatResult)
	if err != nil {
		handleSendCrackError(err)

		return
	}

	if shared.State.WriteZapsToFile {
		_ = writeCrackedHashToFile(hash, task)
	}

	shared.Logger.Debug("Cracked hash sent")
	if response.StatusCode == http.StatusNoContent {
		shared.Logger.Info("Hashlist completed", "hash", hash.Hash)
	}
}

func handleSendCrackError(err error) {
	switch e := err.(type) {
	case *sdkerrors.ErrorObject:
		shared.Logger.Error("Error notifying server of cracked hash, task not found", "error", e.Error())
		SendAgentError(e.Error(), nil, operations.SeverityMajor)
	case *sdkerrors.SDKError:
		shared.Logger.Error("Error sending cracked hash to server, unexpected error",
			"status_code", e.StatusCode,
			"message", e.Message)
		SendAgentError(e.Error(), nil, operations.SeverityCritical)
	default:
		shared.ErrorLogger.Error("Critical error communicating with the CipherSwarm API", "error", err)
	}
}

func writeCrackedHashToFile(hash hashcat.Result, task *components.Task) error {
	hashOut := fmt.Sprintf("%s:%s\n", hash.Hash, hash.Plaintext)
	hashFile := path.Join(shared.State.ZapsPath, fmt.Sprintf("%d_clientout.zap", task.GetID()))
	err := fileutil.WriteStringToFile(hashFile, hashOut, true)
	if err != nil {
		return logAndSendError("Error writing cracked hash to file", err, operations.SeverityCritical, task)
	}

	return nil
}
