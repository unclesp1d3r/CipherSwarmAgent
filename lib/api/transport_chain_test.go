package api

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestTransportChain_RetryTriggersCircuitBreaker verifies that the full transport
// chain (RetryTransport -> CircuitTransport -> base) works end-to-end: retries
// accumulate circuit breaker failures, and once the breaker opens the retry
// transport short-circuits immediately.
func TestTransportChain_RetryTriggersCircuitBreaker(t *testing.T) {
	var calls atomic.Int32
	failBase := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("connection refused")
	})

	cb := NewCircuitBreaker(3, 5*time.Second)

	chain := &RetryTransport{
		Base: &CircuitTransport{
			Base:    failBase,
			Breaker: cb,
		},
		MaxAttempts:  5,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req := mustNewRequest(context.Background(), t)
	_, err := chain.RoundTrip(req) //nolint:bodyclose // error path, no body

	require.Error(t, err)
	// Circuit breaker should have opened after 3 failures, causing retry to
	// short-circuit on ErrCircuitOpen rather than burning all 5 attempts.
	require.ErrorIs(t, err, ErrCircuitOpen)
	// Base was called exactly failureThreshold times before circuit opened
	require.Equal(t, int32(3), calls.Load())
}

// TestTransportChain_SuccessAfterRetry verifies the chain recovers when a
// transient failure is followed by success.
func TestTransportChain_SuccessAfterRetry(t *testing.T) {
	var calls atomic.Int32
	base := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		if n < 3 {
			return nil, errors.New("temporary failure")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})

	cb := NewCircuitBreaker(5, 5*time.Second)

	chain := &RetryTransport{
		Base: &CircuitTransport{
			Base:    base,
			Breaker: cb,
		},
		MaxAttempts:  5,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req := mustNewRequest(context.Background(), t)
	resp, err := chain.RoundTrip(req) //nolint:bodyclose // http.NoBody

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(3), calls.Load())
}

// TestTransportChain_5xxCountsAsCircuitFailure verifies that 5xx responses
// from the base transport are recorded as circuit breaker failures.
func TestTransportChain_5xxCountsAsCircuitFailure(t *testing.T) {
	var calls atomic.Int32
	base := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusBadGateway, Body: http.NoBody}, nil
	})

	cb := NewCircuitBreaker(2, 5*time.Second)

	chain := &RetryTransport{
		Base: &CircuitTransport{
			Base:    base,
			Breaker: cb,
		},
		MaxAttempts:  5,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req := mustNewRequest(context.Background(), t)
	_, err := chain.RoundTrip(req) //nolint:bodyclose // error path / http.NoBody

	// After 2 failures the circuit opens; retry sees ErrCircuitOpen and stops
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCircuitOpen)
	// 2 actual calls to base, then circuit opened
	require.Equal(t, int32(2), calls.Load())
}

// TestTransportChain_ContextCancelledDuringBackoff verifies the chain aborts
// promptly when the context is cancelled during the backoff sleep between retries.
func TestTransportChain_ContextCancelledDuringBackoff(t *testing.T) {
	var calls atomic.Int32
	base := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("connection refused")
	})

	cb := NewCircuitBreaker(10, 5*time.Second) // High threshold so circuit stays closed

	chain := &RetryTransport{
		Base: &CircuitTransport{
			Base:    base,
			Breaker: cb,
		},
		MaxAttempts:  5,
		InitialDelay: 5 * time.Second, // Long delay — context cancel should preempt
		MaxDelay:     10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after the first attempt fails and backoff begins
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	req := mustNewRequest(ctx, t)
	_, err := chain.RoundTrip(req) //nolint:bodyclose // error path, no body

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	// Should have made exactly 1 call before the backoff sleep was interrupted
	require.Equal(t, int32(1), calls.Load())
}
