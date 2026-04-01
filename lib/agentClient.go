// Package lib provides core functionality for the CipherSwarm agent.
package lib

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/config"
	cserrors "github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/devices"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
)

const (
	defaultAgentUpdateInterval = 300 // Default agent update interval in seconds
)

var (
	// configuration stores the agent configuration atomically for safe concurrent access.
	// Use GetConfiguration() and SetConfiguration() — never access directly.
	configuration atomic.Value //nolint:gochecknoglobals // Global agent configuration

	// setNativeHashcatPathFn allows stubbing setNativeHashcatPath for testing.
	// TODO: Replace with interface-based dependency injection when lib/ is decomposed.
	setNativeHashcatPathFn = setNativeHashcatPath //nolint:gochecknoglobals // Used for testing
	// getDevicesListFn allows stubbing getDevicesList for testing.
	// TODO: Replace with interface-based dependency injection when lib/ is decomposed.
	getDevicesListFn = func(ctx context.Context) ([]string, error) { //nolint:gochecknoglobals // Used for testing
		return getDevicesList(ctx, nil)
	}
)

func init() {
	configuration.Store(agentConfiguration{})
}

// GetConfiguration returns a shallow copy of the current agent configuration.
// Value-type fields are safe to use without synchronization. Pointer fields
// (RecommendedTimeouts, RecommendedRetry, RecommendedCircuitBreaker) are shared
// with the stored value — callers must not mutate through them.
// Safe for concurrent use from any goroutine.
//
//nolint:revive // unexported-return: agentConfiguration is internal; callers are all within lib/ and lib/agent/
func GetConfiguration() agentConfiguration {
	cfg, ok := configuration.Load().(agentConfiguration)
	if !ok {
		agentstate.Logger.Error("configuration type assertion failed, returning zero-value config")
	}

	return cfg
}

// SetConfiguration atomically replaces the entire agent configuration.
func SetConfiguration(cfg agentConfiguration) {
	configuration.Store(cfg)
}

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

	response, err := agentstate.State.GetAPIClient().Auth().Authenticate(ctx)
	if err != nil {
		return handleAuthenticationError(ctx, err)
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
	response, err := agentstate.State.GetAPIClient().Auth().GetConfiguration(ctx)
	if err != nil {
		return handleConfigurationError(ctx, err)
	}

	if response.JSON200 == nil {
		agentstate.Logger.Error("Error getting agent configuration")

		return ErrConfigurationFailed
	}

	// Extract server-recommended settings from the configuration response.
	var recTimeouts *RecommendedTimeouts
	rt := response.JSON200.RecommendedTimeouts
	if rt.ConnectTimeout > 0 || rt.ReadTimeout > 0 || rt.WriteTimeout > 0 || rt.RequestTimeout > 0 {
		recTimeouts = &RecommendedTimeouts{
			ConnectTimeout: rt.ConnectTimeout,
			ReadTimeout:    rt.ReadTimeout,
			WriteTimeout:   rt.WriteTimeout,
			RequestTimeout: rt.RequestTimeout,
		}
	}

	var recRetry *RecommendedRetry
	rr := response.JSON200.RecommendedRetry
	if rr.MaxAttempts > 0 {
		recRetry = &RecommendedRetry{
			MaxAttempts:  rr.MaxAttempts,
			InitialDelay: rr.InitialDelay,
			MaxDelay:     rr.MaxDelay,
		}
	}

	var recCB *RecommendedCircuitBreaker
	rcb := response.JSON200.RecommendedCircuitBreaker
	if rcb.FailureThreshold > 0 {
		recCB = &RecommendedCircuitBreaker{
			FailureThreshold: rcb.FailureThreshold,
			Timeout:          rcb.Timeout,
		}
	}

	agentConfig := mapConfiguration(
		response.JSON200.ApiVersion,
		response.JSON200.Config,
		response.JSON200.BenchmarksNeeded,
		recTimeouts,
		recRetry,
		recCB,
	)

	applyRecommendedSettings(agentConfig)

	if agentConfig.Config.UseNativeHashcat {
		if err := setNativeHashcatPathFn(ctx); err != nil {
			return err
		}
	} else {
		agentstate.Logger.Debug("Using server-provided Hashcat binary")
	}

	SetConfiguration(agentConfig)
	agentstate.Logger.Debug("Agent configuration", "config", agentConfig)

	return nil
}

// mapConfiguration converts the API configuration response into an agentConfiguration for use within the agent.
func mapConfiguration(
	apiVersion int,
	agentCfg api.AdvancedAgentConfiguration,
	benchmarksNeeded bool,
	timeouts *RecommendedTimeouts,
	retry *RecommendedRetry,
	circuitBreaker *RecommendedCircuitBreaker,
) agentConfiguration {
	return agentConfiguration{
		APIVersion:       int64(apiVersion),
		BenchmarksNeeded: benchmarksNeeded,
		Config: agentConfig{
			UseNativeHashcat:    UnwrapOr(agentCfg.UseNativeHashcat, false),
			AgentUpdateInterval: int64(UnwrapOr(agentCfg.AgentUpdateInterval, defaultAgentUpdateInterval)),
			BackendDevices:      UnwrapOr(agentCfg.BackendDevice, ""),
			OpenCLDevices:       UnwrapOr(agentCfg.OpenclDevices, ""),
		},
		RecommendedTimeouts:       timeouts,
		RecommendedRetry:          retry,
		RecommendedCircuitBreaker: circuitBreaker,
	}
}

// applyRecommendedSettings overrides agentstate timeout/retry/circuit-breaker
// values with server-recommended settings when present. Server values are in
// seconds and are converted to time.Duration.
func applyRecommendedSettings(cfg agentConfiguration) {
	if t := cfg.RecommendedTimeouts; t != nil {
		maxTimeout := config.MaxReasonableTimeout
		agentstate.State.ConnectTimeout = config.ClampDuration(
			"connect_timeout", time.Duration(t.ConnectTimeout)*time.Second,
			maxTimeout, agentstate.State.ConnectTimeout)
		agentstate.State.ReadTimeout = config.ClampDuration(
			"read_timeout", time.Duration(t.ReadTimeout)*time.Second,
			maxTimeout, agentstate.State.ReadTimeout)
		agentstate.State.WriteTimeout = config.ClampDuration(
			"write_timeout", time.Duration(t.WriteTimeout)*time.Second,
			maxTimeout, agentstate.State.WriteTimeout)
		agentstate.State.RequestTimeout = config.ClampDuration(
			"request_timeout", time.Duration(t.RequestTimeout)*time.Second,
			maxTimeout, agentstate.State.RequestTimeout)
		agentstate.Logger.Info("Applied server-recommended timeouts",
			"connect", agentstate.State.ConnectTimeout,
			"read", agentstate.State.ReadTimeout,
			"write", agentstate.State.WriteTimeout,
			"request", agentstate.State.RequestTimeout)
	}

	if r := cfg.RecommendedRetry; r != nil {
		agentstate.State.APIMaxRetries = config.ClampInt(
			"max_attempts", r.MaxAttempts, 1, config.MaxReasonableRetries,
			agentstate.State.APIMaxRetries)
		agentstate.State.APIRetryInitialDelay = config.ClampDuration(
			"initial_delay", time.Duration(r.InitialDelay)*time.Second,
			config.MaxReasonableTimeout, agentstate.State.APIRetryInitialDelay)
		agentstate.State.APIRetryMaxDelay = config.ClampDuration(
			"max_delay", time.Duration(r.MaxDelay)*time.Second,
			config.MaxReasonableTimeout, agentstate.State.APIRetryMaxDelay)
		agentstate.Logger.Info("Applied server-recommended retry settings",
			"max_attempts", agentstate.State.APIMaxRetries,
			"initial_delay", agentstate.State.APIRetryInitialDelay,
			"max_delay", agentstate.State.APIRetryMaxDelay)
	}

	if cb := cfg.RecommendedCircuitBreaker; cb != nil {
		agentstate.State.CircuitBreakerFailureThreshold = config.ClampInt(
			"failure_threshold", cb.FailureThreshold, 1, config.MaxReasonableRetries,
			agentstate.State.CircuitBreakerFailureThreshold)
		agentstate.State.CircuitBreakerTimeout = config.ClampDuration(
			"circuit_breaker_timeout", time.Duration(cb.Timeout)*time.Second,
			config.MaxReasonableTimeout, agentstate.State.CircuitBreakerTimeout)
		agentstate.Logger.Info("Applied server-recommended circuit breaker settings",
			"failure_threshold", agentstate.State.CircuitBreakerFailureThreshold,
			"timeout", agentstate.State.CircuitBreakerTimeout)
	}
}

// UnwrapOr returns the dereferenced pointer value, or the given default if the pointer is nil.
func UnwrapOr[T any](ptr *T, defaultVal T) T {
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
		return cserrors.LogAndSendError(ctx, "Error getting host info", err, api.SeverityCritical, nil)
	}

	clientSignature := fmt.Sprintf("CipherSwarm Agent/%s %s/%s", AgentVersion, info.OS, info.KernelArch)

	deviceNames, err := getDevicesListFn(ctx)
	if err != nil {
		return cserrors.LogAndSendError(ctx, "Error getting devices", err, api.SeverityCritical, nil)
	}

	agentstate.State.Platform = info.OS
	agentUpdate := api.UpdateAgentJSONRequestBody{
		Id:              agentstate.State.AgentID,
		HostName:        info.Hostname,
		ClientSignature: clientSignature,
		OperatingSystem: info.OS,
		Devices:         deviceNames,
	}

	// Debug logging for troubleshooting credentials issue
	agentstate.Logger.Debug("Preparing agent metadata update",
		"agent_id", agentstate.State.AgentID,
		"hostname", info.Hostname,
		"client_signature", clientSignature,
		"os", info.OS,
		"devices", deviceNames,
		"api_url", agentstate.State.URL,
		"has_token", agentstate.State.APIToken != "")

	response, err := agentstate.State.GetAPIClient().Agents().UpdateAgent(
		ctx,
		agentstate.State.AgentID,
		agentUpdate,
	)
	if err != nil {
		handleAPIError(ctx, "Error updating agent metadata", err)

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

// SetDevicesListManager wires the enumerated DeviceManager into getDevicesListFn.
// Called by StartAgent and handleReload after device enumeration completes.
func SetDevicesListManager(dm *devices.DeviceManager) {
	getDevicesListFn = func(ctx context.Context) ([]string, error) {
		return getDevicesList(ctx, dm)
	}
}

// getDevicesList retrieves a list of device names from the pre-enumerated DeviceManager.
// When dm is non-nil the device names come from the DeviceManager; when dm is nil (enumeration
// failed or hashcat unavailable) an empty slice is returned so metadata submission succeeds with no devices.
func getDevicesList(_ context.Context, dm *devices.DeviceManager) ([]string, error) {
	if dm == nil {
		agentstate.Logger.Debug("DeviceManager is nil, reporting empty device list")

		return []string{}, nil
	}

	all := dm.GetAllDevices()
	names := make([]string, len(all))
	for i, d := range all {
		names[i] = d.Name
	}

	return names, nil
}

// SendHeartBeat sends a heartbeat signal to the server and processes the server's response.
// It handles different response status codes and logs relevant messages.
// It returns the agent's state object (or nil for no state change) and an error if the heartbeat failed.
func SendHeartBeat(ctx context.Context) (*api.State, error) {
	activity := string(agentstate.State.GetCurrentActivity())
	resp, err := agentstate.State.GetAPIClient().Agents().SendHeartbeat(ctx, agentstate.State.AgentID, activity)
	if err != nil {
		handleHeartbeatError(ctx, err)

		return nil, err
	}

	if resp.StatusCode() == http.StatusNoContent {
		logHeartbeatSent()

		return nil, nil //nolint:nilnil // nil state with nil error means successful heartbeat with no state change
	}

	if resp.StatusCode() == http.StatusOK {
		if resp.JSON200 == nil {
			agentstate.Logger.Warn("Heartbeat returned HTTP 200 but JSON body was nil or unparseable")

			return nil, fmt.Errorf("%w: heartbeat returned HTTP 200 with nil JSON body", ErrBadResponse)
		}

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
func handleStateResponse(stateResponse *api.HeartbeatResponse) *api.State {
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
// Callers control context: pass context.Background() for shutdown notifications that must complete.
func SendAgentShutdown(ctx context.Context) {
	_, err := agentstate.State.GetAPIClient().Agents().SetAgentShutdown(ctx, agentstate.State.AgentID)
	if err != nil {
		handleAPIError(ctx, "Error notifying server of agent shutdown", err)
	}
}
