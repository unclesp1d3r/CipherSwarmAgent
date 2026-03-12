package agent

import (
	"log/slog"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// rebuildAPIClient recreates the API client using updated agentstate values.
// Call this after server-recommended settings are applied so the transport chain
// uses the new timeout/retry/circuit-breaker configuration.
func rebuildAPIClient() error {
	apiClient, err := api.NewAgentClient(
		agentstate.State.URL,
		agentstate.State.APIToken,
		transportConfigFromState(),
	)
	if err != nil {
		return err
	}
	agentstate.State.APIClient = apiClient
	agentstate.Logger.Info("Rebuilt API client with server-recommended transport settings")
	return nil
}

// transportConfigFromState builds an api.TransportConfig from the current agentstate values.
func transportConfigFromState() api.TransportConfig {
	var logger *slog.Logger
	if agentstate.State.Debug {
		logger = slog.Default()
	}

	return api.TransportConfig{
		ConnectTimeout: agentstate.State.ConnectTimeout,
		ReadTimeout:    agentstate.State.ReadTimeout,
		WriteTimeout:   agentstate.State.WriteTimeout,
		RequestTimeout: agentstate.State.RequestTimeout,

		MaxRetries:        agentstate.State.APIMaxRetries,
		RetryInitialDelay: agentstate.State.APIRetryInitialDelay,
		RetryMaxDelay:     agentstate.State.APIRetryMaxDelay,

		CircuitBreakerFailureThreshold: agentstate.State.CircuitBreakerFailureThreshold,
		CircuitBreakerTimeout:          agentstate.State.CircuitBreakerTimeout,

		Logger: logger,
	}
}
