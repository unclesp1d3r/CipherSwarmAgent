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

// AuthenticateAgent authenticates the agent with the CipherSwarm API using the SDK client.
// It sends an authentication request to the API, processes the response, and updates the shared state.
// On error, it logs the error and returns it. If the response is nil or indicates a failed authentication,
// an error is logged and returned.
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

// handleAuthenticationError handles authentication errors from the CipherSwarm API.
// It logs detailed error information based on the type of error and returns the original error.
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

// GetAgentConfiguration retrieves the agent configuration from the CipherSwarm API and handles errors.
// It updates the global Configuration variable with the fetched configuration.
// If UseNativeHashcat is true in the configuration, it sets the native Hashcat path.
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

// handleConfigurationError processes configuration errors by logging them and sending critical error reports.
// If the error is an sdkerrors.ErrorObject, logs the error and sends a critical error report.
// If the error is an sdkerrors.SDKError, logs the error with status code and message, and sends a critical error report.
// For all other errors, logs a critical communication error with the CipherSwarm API.
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

// setNativeHashcatPath sets the path for the native Hashcat binary if it is found in the system, otherwise logs and reports error.
func setNativeHashcatPath() error {
	shared.Logger.Debug("Using native Hashcat")
	binPath, err := findHashcatBinary()
	if err != nil {
		shared.Logger.Error("Error finding hashcat binary: ", err)
		SendAgentError(err.Error(), nil, operations.SeverityCritical)

		return err
	}
	shared.Logger.Info("Found Hashcat binary", "path", binPath)
	viper.Set("hashcat_path", binPath)

	return viper.WriteConfig()
}

// UpdateAgentMetadata updates the agent's metadata and sends it to the CipherSwarm API.
// It retrieves host information, device list, constructs the agent update request body,
// and sends the updated metadata to the API. Logs relevant information and handles any API errors.
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

// getDevicesList retrieves a list of device names based on the configured device identification method.
// It checks the global state to determine if the legacy method should be used, then calls the appropriate function.
func getDevicesList() ([]string, error) {
	if shared.State.UseLegacyDeviceIdentificationMethod {
		return arch.GetDevices()
	}

	return getDevices()
}

// getDevices initializes a test Hashcat session and runs a test task, returning the names of available OpenCL devices.
// An error is logged and returned if the session creation or test task execution fails.
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

// logAndSendError logs the provided error message and sends an error report with the specified severity and task metadata.
// Parameters:
// - message: The error message to be logged.
// - err: The error object to be logged and reported.
// - severity: The severity level of the error being reported.
// - task: A pointer to the task associated with the error, can be nil.
// Returns the same error passed in.
func logAndSendError(message string, err error, severity operations.Severity, task *components.Task) error {
	shared.Logger.Error(message, "error", err)
	SendAgentError(err.Error(), task, severity)

	return err
}

// extractDeviceNames extracts the device names from a slice of hashcat.StatusDevice and returns them as a slice of strings.
func extractDeviceNames(deviceStatuses []hashcat.StatusDevice) []string {
	devices := make([]string, len(deviceStatuses))
	for i, device := range deviceStatuses {
		devices[i] = device.DeviceName
	}

	return devices
}

// UpdateCracker checks for updates to the cracker and applies them if available.
// It starts by logging the beginning of the update process and attempts to fetch the current version of Hashcat.
// It then calls the API to check if there are any updates available. Depending on the API response, it either handles
// the update process or logs the absence of any new updates. If any errors occur during these steps, they are logged and handled accordingly.
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

// cleanupTempDir removes the specified temporary directory and logs any errors encountered. Returns the error if removal fails.
func cleanupTempDir(tempDir string) error {
	if err := os.RemoveAll(tempDir); err != nil {
		return logAndSendError("Error removing temporary directory", err, operations.SeverityCritical, nil)
	}

	return nil
}

// validateHashcatDirectory checks if the given hashcat directory exists and contains the specified executable.
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

// sendBenchmarkResults sends the collected benchmark results to a server endpoint.
// It converts each benchmarkResult into a HashcatBenchmark and appends them to a slice.
// If the conversion fails for a result, it continues to the next result.
// Creates a SubmitBenchmarkRequestBody with the HashcatBenchmarks slice and submits it via SdkClient.
// Returns an error if submission or the response received is not successful.
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

// createBenchmark converts a benchmarkResult to a components.HashcatBenchmark struct.
// It handles the conversion of string fields in benchmarkResult to appropriate types.
// Returns a HashcatBenchmark instance and an error if any conversion fails.
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

// UpdateBenchmarks updates the benchmark metrics using Hashcat.
// Creates a Hashcat session with benchmark parameters and initiates the benchmarking process.
// Logs the session start, runs the benchmark task, and updates the results.
// If any errors occur during session creation or result sending, logs the errors and returns them.
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

// DownloadFiles downloads the necessary files for the provided attack.
// It performs the following steps:
// 1. Logs the start of the download process.
// 2. Downloads the hash list associated with the attack.
// 3. Iterates over resource files (word list, rule list, and mask list) and downloads each one.
// If any step encounters an error, the function returns that error.
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

// SendHeartBeat sends a heartbeat signal to the server and processes the server's response.
// It handles different response status codes and logs relevant messages.
// It returns the agent's state object or nil if an error occurs or if the response status is http.StatusNoContent.
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

// handleHeartbeatError processes and logs errors occurring during the heartbeat operation.
// It handles different types of errors and manages logging and reporting based on severity.
// - For *sdkerrors.ErrorObject: logs a critical error and sends a critical agent error message.
// - For *sdkerrors.SDKError: logs an unexpected error with status code and message, and sends a critical agent error message.
// - For all other errors: logs a critical communication error with the CipherSwarm API.
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

// RunTask performs a hashcat attack based on the provided task and attack objects.
// It initializes the task, creates job parameters, starts the hashcat session, and handles task completion or errors.
// Parameters:
//   - task: Pointer to the Task object to be run.
//   - attack: Pointer to the Attack object describing the specifics of the attack.
//
// Returns an error if the task could not be run or if the attack session could not be started.
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

// createJobParams creates hashcat parameters from the given Task and Attack objects.
// The function initializes a hashcat.Params struct by extracting and converting fields
// from the Task and Attack objects. It includes path settings for various resources
// like hash files, word lists, rule lists, and restore files.
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

// AcceptTask attempts to accept the given task identified by its ID.
// It logs an error and returns if the task is nil.
// If the task is successfully accepted, it logs a debug message indicating success.
// In case of an error during task acceptance, it handles the error and returns it.
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

// handleAcceptTaskError handles errors that occur when attempting to accept a task.
// It distinguishes between different error types and logs messages accordingly.
// For specific SDK errors, it logs the error and sends an info-severity agent error.
// For unexpected SDK errors, it logs the error including status code and message, and sends a critical-severity agent error.
// For all other errors, it logs a critical communication error.
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

// markTaskExhausted marks the given task as exhausted by notifying the server.
// Logs an error if the task is nil or if notifying the server fails.
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

// SendAgentShutdown notifies the server of the agent shutdown and handles any errors during the API call.
func SendAgentShutdown() {
	_, err := SdkClient.Agents.SetAgentShutdown(Context, shared.State.AgentID)
	if err != nil {
		handleAPIError("Error notifying server of agent shutdown", err, operations.SeverityCritical)
	}
}

// AbandonTask sets the given task to an abandoned state using the SdkClient and logs any errors that occur.
// If the task is nil, it logs an error and returns immediately.
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

// handleTaskError handles different types of errors encountered during task operations and logs appropriate messages.
// It sends error details to a centralized server based on the error's severity level.
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

// sendCrackedHash sends a cracked hash result to the task server and logs relevant information.
// If the task pointer is nil, it logs an error and returns early.
// Constructs a HashcatResult object and sends it to the server via the SDK client.
// Logs and handles any errors encountered during the sending process.
// If configured, writes the cracked hash to a file.
// Logs additional information based on the HTTP response status.
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

// handleSendCrackError processes different types of errors encountered when communicating with the CipherSwarm API.
// Logs errors based on their type and reports major or critical severity, or logs a critical error for unknown types.
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

// writeCrackedHashToFile writes a cracked hash and its plaintext to a specified file.
// It constructs the output string using the hash and plaintext, then writes it to a task-specific file in the ZapsPath.
// Returns an error if the file writing operation fails.
func writeCrackedHashToFile(hash hashcat.Result, task *components.Task) error {
	hashOut := fmt.Sprintf("%s:%s\n", hash.Hash, hash.Plaintext)
	hashFile := path.Join(shared.State.ZapsPath, fmt.Sprintf("%d_clientout.zap", task.GetID()))
	err := fileutil.WriteStringToFile(hashFile, hashOut, true)
	if err != nil {
		return logAndSendError("Error writing cracked hash to file", err, operations.SeverityCritical, task)
	}

	return nil
}
