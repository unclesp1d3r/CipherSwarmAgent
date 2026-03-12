package agent

import (
	"log/slog"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

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
