package agent

import (
	"log/slog"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// circuitBreaker is the shared circuit breaker instance that survives client rebuilds.
// Written once in StartAgent, then reused in rebuildAPIClient. Only accessed from
// the agent-loop goroutine (same single-goroutine invariant as benchmarkMgr/taskMgr).
//
//nolint:gochecknoglobals // Package-level shared state, initialized in StartAgent
var circuitBreaker *api.CircuitBreaker

// rebuildAPIClient recreates the API client using updated agentstate values.
// Call this after server-recommended settings are applied so the transport chain
// uses the new timeout/retry/circuit-breaker configuration.
// The shared circuit breaker is preserved across rebuilds to retain failure history.
func rebuildAPIClient() error {
	apiClient, err := api.NewAgentClient(
		agentstate.State.URL,
		agentstate.State.APIToken,
		transportConfigFromState(),
	)
	if err != nil {
		return err
	}
	agentstate.State.SetAPIClient(apiClient)
	agentstate.Logger.Info("Rebuilt API client with server-recommended transport settings")
	return nil
}

// transportConfigFromState builds an api.TransportConfig from the current agentstate values.
// When circuitBreaker is non-nil (set during initial client creation), it is reused
// so that failure history survives client rebuilds.
func transportConfigFromState() api.TransportConfig {
	var logger *slog.Logger
	if agentstate.State.Debug {
		logger = slog.Default()
	}

	return api.TransportConfig{
		ConnectTimeout: agentstate.State.ConnectTimeout,
		ReadTimeout:    agentstate.State.ReadTimeout,
		RequestTimeout: agentstate.State.RequestTimeout,

		MaxAttempts:       agentstate.State.APIMaxRetries,
		RetryInitialDelay: agentstate.State.APIRetryInitialDelay,
		RetryMaxDelay:     agentstate.State.APIRetryMaxDelay,

		CircuitBreakerFailureThreshold: agentstate.State.CircuitBreakerFailureThreshold,
		CircuitBreakerTimeout:          agentstate.State.CircuitBreakerTimeout,

		CircuitBreaker: circuitBreaker,
		Logger:         logger,
	}
}
