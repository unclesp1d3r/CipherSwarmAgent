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

// AuthenticateAgent authenticates the agent with the CipherSwarm API and updates the shared state with the AgentID.
// It sends a request to the API client for authentication using the current context.
// If authentication fails, it logs an error and returns an appropriate error message.
// Upon successful authentication and verification of the response, it updates the agent's ID in the shared state.
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

// handleAuthenticationError handles different types of errors during authentication with the CipherSwarm API.
// Logs the error details using shared.Logger and shared.ErrorLogger based on error type and then returns the error.
// If error matches sdkerrors.ErrorObject, logs a general connection error.
// If error matches sdkerrors.SDKError, logs an error with status code and message.
// Otherwise, logs a critical communication error with the CipherSwarm API.
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

// GetAgentConfiguration retrieves the agent configuration from the server.
// It makes an API call to fetch the configuration and handles errors gracefully.
// If the configuration specifies using native Hashcat, it sets the path for the native binary.
// If the configuration retrieval is successful, it updates the global Configuration variable.
// Logs detailed debug information about the configuration.
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

// handleConfigurationError handles errors encountered during configuration retrieval.
// If the error is of type sdkerrors.ErrorObject, it logs the error and sends a critical error message.
// If the error is of type sdkerrors.SDKError, it logs detailed error information and sends a critical error message.
// For all other errors, it logs a critical error indicating issues with the CipherSwarm API.
// The function returns the error after logging and sending relevant error messages.
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

// mapConfiguration converts a GetConfigurationResponseBody into an agentConfiguration object.
// It initializes the agentConfiguration struct and agentConfig struct with values from the response body.
// For boolean and integer fields, it uses pointer.UnwrapOr to provide default values in case of nil pointers.
// Returns the populated agentConfiguration struct.
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

// setNativeHashcatPath attempts to set the path of the native Hashcat binary.
// Logs debug information and errors if the binary is not found. Updates configuration with the found binary path.
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

// UpdateAgentMetadata updates the agent's metadata by performing the following steps:
// 1. Retrieves the host information and constructs the client's signature.
// 2. Fetches the list of devices associated with the agent.
// 3. Constructs an UpdateAgentRequestBody with relevant metadata.
// 4. Logs the updating action and sends an update request to the server.
// 5. Handles the response by displaying the updated metadata or logging an error.
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

// getDevicesList retrieves a list of device names.
// It checks the shared.State.UseLegacyDeviceIdentificationMethod flag to determine which method to use.
// If the flag is set, it uses the legacy method by calling arch.GetDevices.
// Otherwise, it calls the getDevices function to get the list.
func getDevicesList() ([]string, error) {
	if shared.State.UseLegacyDeviceIdentificationMethod {
		return arch.GetDevices()
	}

	return getDevices()
}

// getDevices retrieves available OpenCL devices by creating a test Hashcat session
// with predefined parameters, running a test task, and extracting the device names.
// If any step fails, it logs an error with the severity level and returns it.
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

// logAndSendError logs an error message and sends an agent error to the server.
// Parameters:
// - message: The error message to log.
// - err: The error object to log and send.
// - severity: The severity level of the error.
// - task: A pointer to the task associated with the error.
func logAndSendError(message string, err error, severity operations.Severity, task *components.Task) error {
	shared.Logger.Error(message, "error", err)
	SendAgentError(err.Error(), task, severity)

	return err
}

// extractDeviceNames extracts the device names from a slice of StatusDevice structs and returns them as a slice of strings.
// It iterates over each StatusDevice in the provided slice, retrieves the DeviceName field, and stores it in a new slice.
func extractDeviceNames(deviceStatuses []hashcat.StatusDevice) []string {
	devices := make([]string, len(deviceStatuses))
	for i, device := range deviceStatuses {
		devices[i] = device.DeviceName
	}

	return devices
}

// UpdateCracker checks if a new version of the cracker is available and updates it if necessary.
// It logs each step of the process, including errors encountered during the version check, API communication,
// and the update process itself.
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

// handleCrackerUpdate handles the process of downloading, moving, and extracting a new cracker update.
// It performs the following steps:
// 1. Displays information about the new cracker available.
// 2. Creates a temporary directory to store the downloaded archive.
// 3. Downloads the cracker archive to the temporary directory.
// 4. Moves the archive from the temporary directory to a new location within the CrackersPath.
// 5. Extracts the Hashcat archive to the CrackersPath.
// 6. Validates the extracted Hashcat directory and binary.
// 7. Removes the downloaded archive.
// 8. Updates the configuration to point to the new Hashcat executable path.
// If any step fails, an appropriate error is logged and returned.
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

// cleanupTempDir removes the specified temporary directory and handles any error by logging and sending an error report.
// It returns an error if the directory cannot be removed.
func cleanupTempDir(tempDir string) error {
	if err := os.RemoveAll(tempDir); err != nil {
		return logAndSendError("Error removing temporary directory", err, operations.SeverityCritical, nil)
	}

	return nil
}

// validateHashcatDirectory checks if the given hashcat directory and its executable exist.
// It logs an error if either the directory or the executable is missing and returns false.
// If both checks pass, it returns true.
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

// GetNewTask attempts to fetch a new task from the CipherSwarm API.
//
// It makes a request to the API and processes the response as follows:
// - If the response is successful (Status OK), it returns the new task.
// - If there is no new task available (Status No Content), it returns nil.
// - If an error occurs during the API request, it handles the error and returns it.
// - For any other response status, it returns a "bad response" error.
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

// GetAttackParameters retrieves the attack parameters using the provided attack ID.
// It interacts with the SdkClient to fetch the attack details.
// If there is an error during the API call, it handles the error and returns it.
// If the API responds with a status other than HTTP 200 OK, it returns a "bad response" error.
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

// handleAPIError handles errors returned from API calls.
// It logs the error, categorizing it based on its type, and sends an appropriate error message to the agent.
// Three types of errors are handled:
// - sdkerrors.ErrorObject: Logs the error and sends an agent error with the provided severity.
// - sdkerrors.SDKError: Logs the error with its status code and message, and sends an agent error with the provided severity.
// - default: Logs a critical error for any other type of error.
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

// sendBenchmarkResults submits the benchmark results to the server.
// It converts the given benchmark results into a slice of HashcatBenchmark.
// It creates a SubmitBenchmarkRequestBody with the converted benchmarks and submits it.
// If an error occurs while creating a benchmark, it skips that result.
// If the server returns a StatusNoContent, it returns nil, otherwise it returns an error.
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

// createBenchmark converts a benchmarkResult into a HashcatBenchmark.
// It attempts to convert each string field of benchmarkResult to the appropriate type.
// Returns a HashcatBenchmark and an error if any conversion fails.
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

// UpdateBenchmarks updates and sends benchmark results to the server.
// It creates a Hashcat session to perform benchmark tasks, runs the benchmark, and then sends the results.
// If errors occur during the creation of the session or sending results, they are logged and the function returns such errors.
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

// DownloadFiles downloads the necessary files for an attack.
//
// This function performs the following steps:
// 1. Displays the start of the file download process.
// 2. Downloads the hash list associated with the attack, returning an error if it fails.
// 3. Iterates over the attack's resource files (word list, rule list, mask list) and downloads each one.
// 4. Returns an error if any resource file download fails or nil if all downloads succeed.
//
// Parameters:
//   - attack (*components.Attack): A pointer to the Attack object containing details of the attack.
//
// Returns:
//   - error: An error object if any file download fails, otherwise nil.
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

// downloadResourceFile downloads the specified AttackResourceFile to a local path.
// If the file already exists and AlwaysTrustFiles is true, it skips the checksum verification.
// Otherwise, it verifies the checksum (if provided), downloads the file, and checks its size after download.
// Logs appropriate messages during the process and returns errors if any issues are encountered.
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

// SendHeartBeat sends a heartbeat signal to the CipherSwarm Agent server and handles the response.
// It logs the heartbeat status and processes the response based on the status code received.
//   - If the response status is NoContent, it logs the successful sending of the heartbeat.
//   - If the response status is OK, it logs the successful sending of the heartbeat and
//     processes the state returned in the response using handleStateResponse method.
//
// In case of an error during the heartbeat sending, it handles the error using handleHeartbeatError method.
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

// handleHeartbeatError handles errors that occur during the heartbeat process.
// It differentiates the error type and takes appropriate logging and error handling actions.
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

// logHeartbeatSent logs a "Heartbeat sent" message if extra debugging is enabled and marks job checking as active.
func logHeartbeatSent() {
	if shared.State.ExtraDebugging {
		shared.Logger.Debug("Heartbeat sent")
	}
	shared.State.JobCheckingStopped = false
}

// handleStateResponse processes the state response from the server and returns the current state.
// - It logs debug messages based on the state of the agent if extra debugging is enabled.
// - The agent states handled are pending, stopped, and error. Other states log an "Unknown agent state" message if extra debugging is enabled.
// - If the state response is nil, it returns nil. The function returns a pointer to the detected state.
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

// RunTask executes a given task with the associated attack parameters. It performs the following actions:
// 1. Displays a log indicating the start of the task.
// 2. Checks if attack parameter is nil and logs and returns a critical error if so.
// 3. Creates job parameters using the task and attack.
// 4. Initiates a new Hashcat session with given job parameters.
// 5. Runs the attack task and manages the session output, status updates, and errors.
// 6. Displays a completion log message.
//
// Parameters:
//   - task: A pointer to the task to be executed.
//   - attack: A pointer to the associated attack parameters.
//
// Returns:
//   - error: An error object if any step in executing the task fails.
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

// createJobParams generates Hashcat parameters from Task and Attack objects.
// It unwraps values using pointer functions and joins paths based on configuration settings.
// It sets attack mode, hash type, hash file, mask, increment modes, custom charsets, resource names,
// additional arguments, and device configurations.
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

// sendStatusUpdate sends the current status update to the server and handles the response.
// Ensures the update time is set to the current time if not already set.
// Converts the device statuses from `hashcat.Status` to `components.DeviceStatus`.
// Converts `hashcat.Status` to `components.TaskStatus`.
// Sends the status update to the server using `SdkClient.Tasks.SendStatus`.
// Handles any errors that occur during the send operation and calls `handleStatusUpdateError`.
// Manages different HTTP response codes:
// - `http.StatusNoContent`: Indicates the update was successfully sent.
// - `http.StatusAccepted`: Indicates the update was sent but is stale, triggering a call to `getZaps()`.
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

// handleStatusUpdateError handles errors that occur during a status update for a task within a hashcat session.
// If the error is a sdkerrors.ErrorObject, it logs and sends a critical error message.
// If the error is a sdkerrors.SDKError, it delegates handling to the handleSDKError function.
// For other errors, it logs a critical error indicating issues communicating with the CipherSwarm API.
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

// handleSDKError handles different SDK errors and performs specific actions based on the error type.
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

// handleTaskNotFound handles scenarios where a task is not found in the session.
// It logs an error about the missing task and makes attempts to properly terminate and clean up the session.
// The function logs relevant information and potential errors occurring during session termination and cleanup.
func handleTaskNotFound(task *components.Task, sess *hashcat.Session) {
	shared.Logger.Error("Task not found", "task_id", task.GetID())
	shared.Logger.Info("Killing task", "task_id", task.GetID())
	shared.Logger.Info("It is possible that multiple errors appear as the task takes some time to kill. This is expected.")
	if err := sess.Kill(); err != nil {
		_ = logAndSendError("Error killing task", err, operations.SeverityCritical, task)
	}
	sess.Cleanup()
}

// handleTaskGone pauses the given task and attempts to kill the associated hashcat session.
// First, it logs the information that the task is being paused.
// Then, it calls the Kill method on the session.
// If an error occurs during this operation, it logs and sends the error with a fatal severity.
func handleTaskGone(task *components.Task, sess *hashcat.Session) {
	shared.Logger.Info("Pausing task", "task_id", task.GetID())
	if err := sess.Kill(); err != nil {
		_ = logAndSendError("Error pausing task", err, operations.SeverityFatal, task)
	}
}

// getZaps downloads and processes cracked hashes for a given Task.
// It logs errors if the Task is nil or if any issues occur while fetching zaps.
// If zaps exist, handles the response stream and processes the cracked hashes.
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

// handleGetZapsError processes errors encountered when fetching zaps.
// It logs the error and sends a critical severity agent error report.
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

// handleResponseStream processes the response stream for a given task.
// It creates a Zap file that contains a list of all cracked hashes and their plain text values.
// First, it tries to remove any existing zap file for the specified task.
// It then creates and writes the new zap file from the response stream.
// Logs and sends critical errors if any step fails.
//
// Parameters:
//   - task: A pointer to the Task object being processed.
//   - responseStream: An io.Reader containing the data to write to the zap file.
//
// Returns an error if critical issues are encountered during file operations.
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

// removeExistingZapFile removes a zap file if it already exists at the given path. Logs a debug message if the file exists.
func removeExistingZapFile(zapFilePath string) error {
	if fileutil.IsExist(zapFilePath) {
		shared.Logger.Debug("Zap file already exists", "path", zapFilePath)

		return fileutil.RemoveFile(zapFilePath)
	}

	return nil
}

// createAndWriteZapFile creates a new zap file at the specified path and writes the provided data from the responseStream.
// If the file creation or writing fails, an error is logged and sent with severity critical, and the error is returned.
// Parameters:
// - zapFilePath: The file path where the zap file will be created.
// - responseStream: An io.Reader containing the data to be written to the zap file.
// - task: A pointer to the task associated with the operation.
// Returns an error if unable to create, write, or close the zap file properly.
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

// SendAgentError sends an error message to the agent server with relevant metadata and severity level.
// Parameters:
// - stdErrLine: The error message string to be sent.
// - task: A pointer to the task associated with the error, can be nil.
// - severity: The severity level of the error being reported.
//
// The function constructs metadata with the current timestamp, platform, and version information.
// It creates an error request body and sends it using the SDK client.
// If there is an error in sending the error report, handleSendError is called to manage it.
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

// handleSendError handles different types of errors encountered during sending
// operations by logging and sending a critical agent error message.
// Parameters:
//   - err: error object, can be of type *sdkerrors.ErrorObject, *sdkerrors.SDKError, or any other error type.
//
// Actions:
//   - If the error is of type *sdkerrors.ErrorObject: logs a critical error and sends a critical agent error message.
//   - If the error is of type *sdkerrors.SDKError: logs an unexpected error with status code and message, and sends a critical agent error message.
//   - For all other errors: logs a critical communication error with the CipherSwarm API.
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

// AcceptTask attempts to accept the given task using the SdkClient.
// If the task is nil, it logs an error and returns a "task is nil" error.
// It then calls SdkClient.Tasks.SetTaskAccepted with the task's ID and context.
// If the API call is successful, it logs a debug message and returns nil.
// If the API call fails, it invokes handleAcceptTaskError and returns the error.
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

// handleAcceptTaskError handles various task acceptance errors by logging them and sending appropriate agent error messages.
// Parameters:
//   - err: error object, can be of type *sdkerrors.ErrorObject, *sdkerrors.SDKError, or any other error type.
//
// Actions:
//   - If the error is of type *sdkerrors.ErrorObject: logs the error and sends an informational agent error message.
//   - If the error is of type *sdkerrors.SDKError: logs the error with status code and message, and sends a critical agent error message.
//   - For all other errors: logs a critical communication error with the CipherSwarm API.
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

// markTaskExhausted marks the provided task as exhausted using the SdkClient to notify the server.
// If the task is nil, it logs an error message and returns.
// If an error occurs while notifying the server, it handles the error explicitly.
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

// SendAgentShutdown notifies the server of an agent shutdown event. It sends the shutdown signal using the SdkClient's Agents.SetAgentShutdown method.
// If the API call returns an error, it handles the error by logging it and classifying it as a critical error using the handleAPIError function.
func SendAgentShutdown() {
	_, err := SdkClient.Agents.SetAgentShutdown(Context, shared.State.AgentID)
	if err != nil {
		handleAPIError("Error notifying server of agent shutdown", err, operations.SeverityCritical)
	}
}

// AbandonTask marks a given task as abandoned by making an API call to notify the server.
// If the task is nil, it logs an error and returns immediately.
// Otherwise, it attempts to set the task as abandoned using the SdkClient.
// If the API call fails, it handles the error by invoking handleTaskError.
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

// sendCrackedHash sends a cracked hash to the task server and handles logging and error management.
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

// handleSendCrackError handles different types of errors encountered while sending cracked hash to the server.
// Parameters:
// - err: error object, which can be of type *sdkerrors.ErrorObject, *sdkerrors.SDKError, or any generic error.
//
// Actions:
// - If the error is of type *sdkerrors.ErrorObject: logs an error indicating the task was not found and sends a major agent error.
// - If the error is of type *sdkerrors.SDKError: logs an unexpected error with status code and message, and sends a critical agent error.
// - For all other errors: logs a critical communication Error with the CipherSwarm API.
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

// writeCrackedHashToFile writes a cracked hash result to a file in a specified format.
// It constructs the file path using task details and attempts to write the hash result string to the file.
// If an error occurs during writing, it logs and sends this error with critical severity, associating it with the task.
func writeCrackedHashToFile(hash hashcat.Result, task *components.Task) error {
	hashOut := fmt.Sprintf("%s:%s\n", hash.Hash, hash.Plaintext)
	hashFile := path.Join(shared.State.ZapsPath, fmt.Sprintf("%d_clientout.zap", task.GetID()))
	err := fileutil.WriteStringToFile(hashFile, hashOut, true)
	if err != nil {
		return logAndSendError("Error writing cracked hash to file", err, operations.SeverityCritical, task)
	}

	return nil
}
