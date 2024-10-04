package lib

import (
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

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

// cleanupTempDir removes the specified temporary directory and logs any errors encountered. Returns the error if removal fails.
func cleanupTempDir(tempDir string) error {
	if err := os.RemoveAll(tempDir); err != nil {
		return logAndSendError("Error removing temporary directory", err, operations.SeverityCritical, nil)
	}

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

// extractDeviceNames extracts the device names from a slice of hashcat.StatusDevice and returns them as a slice of strings.
func extractDeviceNames(deviceStatuses []hashcat.StatusDevice) []string {
	devices := make([]string, len(deviceStatuses))
	for i, device := range deviceStatuses {
		devices[i] = device.DeviceName
	}

	return devices
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
