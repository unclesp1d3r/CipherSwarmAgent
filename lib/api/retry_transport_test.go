package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// roundTripFunc adapts a function to http.RoundTripper for testing.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestRetryTransport(base http.RoundTripper) *RetryTransport {
	return &RetryTransport{
		Base:         base,
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}
}

func TestRetryTransport_SuccessOnFirstAttempt(t *testing.T) {
	var calls atomic.Int32
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(1), calls.Load())
}

func TestRetryTransport_RetriesOnNetworkError(t *testing.T) {
	var calls atomic.Int32
	errNetwork := errors.New("connection refused")
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		if n < 3 {
			return nil, errNetwork
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(3), calls.Load())
}

func TestRetryTransport_RetriesOn5xx(t *testing.T) {
	var calls atomic.Int32
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		if n < 3 {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Body:       io.NopCloser(strings.NewReader("bad gateway")),
			}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(3), calls.Load())
}

func TestRetryTransport_DoesNotRetry4xx(t *testing.T) {
	var calls atomic.Int32
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody}, nil
	}))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.Equal(t, int32(1), calls.Load())
}

func TestRetryTransport_ReturnsLast5xxAfterExhaustion(t *testing.T) {
	var calls atomic.Int32
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader("unavailable")),
		}, nil
	}))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, int32(3), calls.Load())
}

func TestRetryTransport_ReturnsErrorAfterExhaustion(t *testing.T) {
	errNetwork := errors.New("connection refused")
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errNetwork
	}))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	require.Nil(t, resp)
	require.Error(t, err)
	require.ErrorIs(t, err, errNetwork)
	require.Contains(t, err.Error(), "all 3 API request attempts failed")
}

func TestRetryTransport_RespectsContextCancellation(t *testing.T) {
	var calls atomic.Int32
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("fail")
	}))

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after first attempt's backoff starts
	go func() {
		time.Sleep(500 * time.Microsecond)
		cancel()
	}()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	_, err := rt.RoundTrip(req)

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRetryTransport_MaxAttemptsZeroDefaultsToOne(t *testing.T) {
	var calls atomic.Int32
	rt := &RetryTransport{
		Base: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
		MaxAttempts: 0,
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(1), calls.Load())
}

func TestBackoffDelay_ExponentialWithCap(t *testing.T) {
	rt := &RetryTransport{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     500 * time.Millisecond,
	}

	require.Equal(t, 100*time.Millisecond, rt.backoffDelay(1))
	require.Equal(t, 200*time.Millisecond, rt.backoffDelay(2))
	require.Equal(t, 400*time.Millisecond, rt.backoffDelay(3))
	require.Equal(t, 500*time.Millisecond, rt.backoffDelay(4)) // capped
	require.Equal(t, 500*time.Millisecond, rt.backoffDelay(5)) // still capped
}

func TestSleepWithRequestContext_CompletesNormally(t *testing.T) {
	err := sleepWithRequestContext(context.Background(), 1*time.Millisecond)
	require.NoError(t, err)
}

func TestSleepWithRequestContext_CancelledEarly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sleepWithRequestContext(ctx, 10*time.Second)
	require.ErrorIs(t, err, context.Canceled)
}
