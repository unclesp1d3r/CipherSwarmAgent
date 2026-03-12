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

// mustNewRequest creates an HTTP request or fails the test.
func mustNewRequest(ctx context.Context, t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)
	return req
}

func TestRetryTransport_SuccessOnFirstAttempt(t *testing.T) {
	var calls atomic.Int32
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}))

	req := mustNewRequest(context.Background(), t)
	resp, err := rt.RoundTrip(req) //nolint:bodyclose // http.NoBody

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

	req := mustNewRequest(context.Background(), t)
	resp, err := rt.RoundTrip(req) //nolint:bodyclose // http.NoBody

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

	req := mustNewRequest(context.Background(), t)
	resp, err := rt.RoundTrip(req) //nolint:bodyclose // http.NoBody

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

	req := mustNewRequest(context.Background(), t)
	resp, err := rt.RoundTrip(req) //nolint:bodyclose // http.NoBody

	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.Equal(t, int32(1), calls.Load())
}

func TestRetryTransport_ReturnsErrorAfter5xxExhaustion(t *testing.T) {
	var calls atomic.Int32
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader("unavailable")),
		}, nil
	}))

	req := mustNewRequest(context.Background(), t)
	resp, err := rt.RoundTrip(req) //nolint:bodyclose // error path, resp is nil

	require.Nil(t, resp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "all 3 API request attempts failed")
	require.Contains(t, err.Error(), "server error")
	require.Equal(t, int32(3), calls.Load())
}

func TestRetryTransport_ReturnsErrorAfterExhaustion(t *testing.T) {
	errNetwork := errors.New("connection refused")
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errNetwork
	}))

	req := mustNewRequest(context.Background(), t)
	resp, err := rt.RoundTrip(req) //nolint:bodyclose // error path, resp is nil

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

	req := mustNewRequest(ctx, t)
	_, err := rt.RoundTrip(req) //nolint:bodyclose // error path, no body

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

	req := mustNewRequest(context.Background(), t)
	resp, err := rt.RoundTrip(req) //nolint:bodyclose // http.NoBody

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(1), calls.Load())
}

func TestBackoffDelay_ExponentialWithCapAndJitter(t *testing.T) {
	rt := &RetryTransport{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     500 * time.Millisecond,
	}

	// Jitter returns [base/2, base], so we check ranges.
	tests := []struct {
		attempt int
		minD    time.Duration // base/2
		maxD    time.Duration // base (or cap)
	}{
		{1, 50 * time.Millisecond, 100 * time.Millisecond},
		{2, 100 * time.Millisecond, 200 * time.Millisecond},
		{3, 200 * time.Millisecond, 400 * time.Millisecond},
		{4, 250 * time.Millisecond, 500 * time.Millisecond}, // capped at MaxDelay
		{5, 250 * time.Millisecond, 500 * time.Millisecond}, // still capped
	}

	for _, tt := range tests {
		delay := rt.backoffDelay(tt.attempt)
		require.GreaterOrEqual(t, delay, tt.minD, "attempt %d", tt.attempt)
		require.LessOrEqual(t, delay, tt.maxD, "attempt %d", tt.attempt)
	}
}

func TestBackoffDelay_ZeroMaxDelayReturnsInitialDelay(t *testing.T) {
	rt := &RetryTransport{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     0,
	}
	delay := rt.backoffDelay(1)
	require.Equal(t, 100*time.Millisecond, delay)
}

func TestRetryTransport_ShortCircuitsOnErrCircuitOpen(t *testing.T) {
	var calls atomic.Int32
	rt := &RetryTransport{
		Base: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, ErrCircuitOpen
		}),
		MaxAttempts:  5,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req := mustNewRequest(context.Background(), t)
	_, err := rt.RoundTrip(req) //nolint:bodyclose // error path, no body

	require.Error(t, err)
	require.ErrorIs(t, err, ErrCircuitOpen)
	// Must be called exactly once — no retries on circuit open
	require.Equal(t, int32(1), calls.Load())
}

func TestRetryTransport_ResetsRequestBodyOnRetry(t *testing.T) {
	var calls atomic.Int32
	var bodies []string

	rt := &RetryTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			n := calls.Add(1)
			// Read the body to verify it's present
			bodyBytes, readErr := io.ReadAll(req.Body)
			if readErr != nil {
				return nil, readErr
			}
			bodies = append(bodies, string(bodyBytes))
			if n < 3 {
				return nil, errors.New("temporary failure")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"http://example.com",
		strings.NewReader(`{"test":"data"}`),
	)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req) //nolint:bodyclose // http.NoBody
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(3), calls.Load())

	// All 3 attempts should have received the full body
	for i, body := range bodies {
		require.JSONEq(t, `{"test":"data"}`, body, "attempt %d had wrong body", i+1)
	}
}

func TestBackoffDelay_OverflowProtection(t *testing.T) {
	tests := []struct {
		name         string
		attempt      int
		initialDelay time.Duration
		maxDelay     time.Duration
		wantCapped   bool // true if result should be <= maxDelay
	}{
		{
			name:         "large attempt exercises maxBackoffShift",
			attempt:      100,
			initialDelay: 1 * time.Millisecond,
			maxDelay:     1 * time.Second,
			wantCapped:   true,
		},
		{
			name:         "extreme attempt value",
			attempt:      1000,
			initialDelay: 1 * time.Millisecond,
			maxDelay:     1 * time.Second,
			wantCapped:   true,
		},
		{
			name:         "zero InitialDelay returns zero",
			attempt:      5,
			initialDelay: 0,
			maxDelay:     1 * time.Second,
			wantCapped:   true,
		},
		{
			name:         "large InitialDelay exercises overflow guard",
			attempt:      3,
			initialDelay: time.Duration(1<<60) * time.Nanosecond,
			maxDelay:     time.Duration(1<<62) * time.Nanosecond,
			wantCapped:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &RetryTransport{
				InitialDelay: tt.initialDelay,
				MaxDelay:     tt.maxDelay,
			}
			delay := rt.backoffDelay(tt.attempt)
			require.GreaterOrEqual(t, delay, time.Duration(0), "delay must be non-negative")
			if tt.wantCapped {
				require.LessOrEqual(t, delay, tt.maxDelay, "delay must not exceed MaxDelay")
			}
		})
	}
}

func TestRetryTransport_RetriesOn429(t *testing.T) {
	var calls atomic.Int32
	rt := newTestRetryTransport(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		if n < 3 {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(strings.NewReader("rate limited")),
			}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}))

	req := mustNewRequest(context.Background(), t)
	resp, err := rt.RoundTrip(req) //nolint:bodyclose // http.NoBody

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(3), calls.Load())
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
