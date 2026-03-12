package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestCircuitTransport(base http.RoundTripper, threshold int) *CircuitTransport {
	return &CircuitTransport{
		Base:    base,
		Breaker: NewCircuitBreaker(threshold, 50*time.Millisecond),
	}
}

// mustNewCircuitReq creates an HTTP request for circuit transport tests.
func mustNewCircuitReq(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)
	return req
}

func TestCircuitTransport_ForwardsSuccessfulRequest(t *testing.T) {
	ct := newTestCircuitTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}), 3)

	req := mustNewCircuitReq(t)
	resp, err := ct.RoundTrip(req) //nolint:bodyclose // http.NoBody
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestCircuitTransport_RecordsFailureOnNetworkError(t *testing.T) {
	ct := newTestCircuitTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	}), 2)

	req := mustNewCircuitReq(t)

	_, err := ct.RoundTrip(req) //nolint:bodyclose // error path
	require.Error(t, err)

	_, err = ct.RoundTrip(req) //nolint:bodyclose // error path
	require.Error(t, err)

	// Circuit should now be open
	_, err = ct.RoundTrip(req) //nolint:bodyclose // error path
	require.ErrorIs(t, err, ErrCircuitOpen)
}

func TestCircuitTransport_RecordsFailureOn5xx(t *testing.T) {
	ct := newTestCircuitTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: http.NoBody}, nil
	}), 2)

	req := mustNewCircuitReq(t)

	resp, err := ct.RoundTrip(req) //nolint:bodyclose // http.NoBody
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	resp, err = ct.RoundTrip(req) //nolint:bodyclose // http.NoBody
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	// Circuit should now be open
	_, err = ct.RoundTrip(req) //nolint:bodyclose // error path
	require.ErrorIs(t, err, ErrCircuitOpen)
}

func TestCircuitTransport_RecordsSuccessOnNon5xx(t *testing.T) {
	ct := newTestCircuitTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}), 2)

	req := mustNewCircuitReq(t)

	// Record a failure first
	ct.Breaker.RecordFailure()

	// Successful request should reset
	resp, err := ct.RoundTrip(req) //nolint:bodyclose // http.NoBody
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Another failure shouldn't open (count reset by success)
	ct.Breaker.RecordFailure()
	require.True(t, ct.Breaker.Allow())
}

func TestCircuitTransport_RejectsWhenOpen(t *testing.T) {
	ct := newTestCircuitTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}), 1)

	req := mustNewCircuitReq(t)

	// Trip the breaker
	ct.Breaker.RecordFailure()

	_, err := ct.RoundTrip(req) //nolint:bodyclose // error path
	require.ErrorIs(t, err, ErrCircuitOpen)
}

func TestCircuitTransport_AllowsProbeInHalfOpen(t *testing.T) {
	ct := newTestCircuitTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}), 1)

	req := mustNewCircuitReq(t)

	// Trip the breaker
	ct.Breaker.RecordFailure()
	require.False(t, ct.Breaker.Allow())

	// Wait for half-open
	time.Sleep(60 * time.Millisecond)

	// Probe should succeed and close circuit
	resp, err := ct.RoundTrip(req) //nolint:bodyclose // http.NoBody
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Should be closed again
	require.True(t, ct.Breaker.Allow())
}
