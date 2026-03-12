package api

import (
	"fmt"
	"log/slog"
	"net/http"
)

// CircuitTransport wraps an http.RoundTripper with circuit breaker logic.
// When the circuit is open, requests are rejected immediately with ErrCircuitOpen.
type CircuitTransport struct {
	Base    http.RoundTripper
	Breaker *CircuitBreaker
	Logger  *slog.Logger // Optional structured logger; nil disables logging.
}

// RoundTrip implements http.RoundTripper with circuit breaker protection.
func (ct *CircuitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !ct.Breaker.Allow() {
		if ct.Logger != nil {
			ct.Logger.Warn("Circuit breaker is open, rejecting API request",
				"url", req.URL.String())
		}
		return nil, fmt.Errorf("%w: server appears unresponsive", ErrCircuitOpen)
	}

	resp, err := ct.Base.RoundTrip(req)
	if err != nil {
		ct.Breaker.RecordFailure()
		return nil, err
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		ct.Breaker.RecordFailure()
	} else {
		ct.Breaker.RecordSuccess()
	}

	return resp, nil
}
