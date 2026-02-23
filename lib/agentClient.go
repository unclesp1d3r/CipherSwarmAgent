// Package lib provides core functionality for the CipherSwarm agent.
package lib

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	cserrors "github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
)

const (
	defaultAgentUpdateInterval = 300 // Default agent update interval in seconds
)

var (
	// Configuration represents the configuration of the agent.
	Configuration agentConfiguration //nolint:gochecknoglobals // Global agent configuration

	// setNativeHashcatPathFn allows stubbing setNativeHashcatPath for testing.
	// TODO: Replace with interface-based dependency injection when lib/ is decomposed.
	setNativeHashcatPathFn = setNativeHashcatPath //nolint:gochecknoglobals // Used for testing
	// getDevicesListFn allows stubbing getDevicesList for testing.
	// TODO: Replace with interface-based dependency injection when lib/ is decomposed.
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
func AuthenticateAgent(ctx context.Context) error {
	// Set agent version in shared state so cserrors.SendAgentError can include it in error reports.
	agentstate.State.AgentVersion = AgentVersion

	response, err := agentstate.State.APIClient.Auth().Authenticate(ctx)
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
func GetAgentConfiguration(ctx context.Context) error {
	response, err := agentstate.State.APIClient.Auth().GetConfiguration(ctx)
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
			UseNativeHashcat:    unwrapOr(config.UseNativeHashcat, false),
			AgentUpdateInterval: int64(unwrapOr(config.AgentUpdateInterval, defaultAgentUpdateInterval)),
			BackendDevices:      unwrapOr(config.BackendDevice, ""),
			OpenCLDevices:       unwrapOr(config.OpenclDevices, ""),
		},
	}

	return agentConfig
}

// unwrapOr returns the dereferenced pointer value, or the given default if the pointer is nil.
func unwrapOr[T any](ptr *T, defaultVal T) T {
	if ptr != nil {
		return *ptr
	}

	return defaultVal
}

// UpdateAgentMetadata updates the agent's metadata and sends it to the CipherSwarm API.
// It retrieves host information, device list, constructs the agent update request body,
// and sends the updated metadata to the API. Logs relevant information and handles any API errors.
func UpdateAgentMetadata(ctx context.Context) error {
	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return cserrors.LogAndSendError("Error getting host info", err, api.SeverityCritical, nil)
	}

	clientSignature := fmt.Sprintf("CipherSwarm Agent/%s %s/%s", AgentVersion, info.OS, info.KernelArch)

	devices, err := getDevicesListFn(ctx)
	if err != nil {
		return cserrors.LogAndSendError("Error getting devices", err, api.SeverityCritical, nil)
	}

	agentstate.State.Platform = info.OS
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
		ctx,
		agentstate.State.AgentID,
		agentUpdate,
	)
	if err != nil {
		handleAPIError("Error updating agent metadata", err)

		return err
	}

	if response.JSON200 != nil {
		display.AgentMetadataUpdated(response)
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

// SendHeartBeat sends a heartbeat signal to the server and processes the server's response.
// It handles different response status codes and logs relevant messages.
// It returns the agent's state object (or nil for no state change) and an error if the heartbeat failed.
func SendHeartBeat(ctx context.Context) (*api.SendHeartbeat200State, error) {
	activity := string(agentstate.State.GetCurrentActivity())
	resp, err := agentstate.State.APIClient.Agents().SendHeartbeat(ctx, agentstate.State.AgentID, activity)
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

	return nil, fmt.Errorf("%w: heartbeat returned status %d", ErrBadResponse, resp.StatusCode())
}

// logHeartbeatSent logs a debug message indicating a heartbeat was sent if extra debugging is enabled.
// It also sets the JobCheckingStopped state to false.
func logHeartbeatSent() {
	if agentstate.State.ExtraDebugging {
		agentstate.Logger.Debug("Heartbeat sent")
	}

	agentstate.State.SetJobCheckingStopped(false)
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

// SendAgentShutdown notifies the server of the agent shutdown and handles any errors during the API call.
func SendAgentShutdown() {
	_, err := agentstate.State.APIClient.Agents().SetAgentShutdown(context.Background(), agentstate.State.AgentID)
	if err != nil {
		handleAPIError("Error notifying server of agent shutdown", err)
	}
}
