package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// RetryTransport wraps an http.RoundTripper with retry logic using exponential backoff.
// It retries on network errors and 5xx responses, but not on 4xx client errors.
type RetryTransport struct {
	Base         http.RoundTripper // Underlying transport
	MaxAttempts  int               // Total attempts (1 = no retry)
	InitialDelay time.Duration     // First retry delay
	MaxDelay     time.Duration     // Cap for exponential backoff
	Logger       *slog.Logger      // Optional structured logger; nil disables logging.
}

// RoundTrip implements http.RoundTripper with retry logic.
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	maxAttempts := max(t.MaxAttempts, 1)

	var lastErr error
	var lastResp *http.Response

	for attempt := range maxAttempts {
		if attempt > 0 {
			delay := t.backoffDelay(attempt)
			if err := sleepWithRequestContext(req.Context(), delay); err != nil {
				if lastErr != nil {
					return nil, fmt.Errorf(
						"request cancelled after %d attempt(s) (last error: %w): %w",
						attempt, lastErr, err)
				}
				return nil, fmt.Errorf("request cancelled: %w", err)
			}
		}

		resp, err := t.Base.RoundTrip(req)
		if err != nil {
			// Circuit breaker open — retrying is pointless, fail immediately
			if errors.Is(err, ErrCircuitOpen) {
				return nil, err
			}
			lastErr = err
			if t.Logger != nil {
				t.Logger.Debug("API request failed, will retry",
					"attempt", attempt+1, "max", maxAttempts, "error", err)
			}
			continue
		}

		// Don't retry 4xx errors — those are client-side issues
		if resp.StatusCode < http.StatusInternalServerError {
			return resp, nil
		}

		// 5xx: close body before retry to avoid leaking connections
		if t.Logger != nil {
			t.Logger.Debug("API request returned server error, will retry",
				"attempt", attempt+1, "max", maxAttempts, "status", resp.StatusCode)
		}
		lastResp = resp
		if resp.Body != nil {
			//nolint:errcheck // draining body before close; errors are not actionable
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all %d API request attempts failed: %w", maxAttempts, lastErr)
	}

	// Return last 5xx response if all retries exhausted
	return lastResp, nil
}

// maxBackoffShift is the maximum bit shift for exponential backoff to prevent integer overflow.
const maxBackoffShift = 62

// backoffDelay computes exponential backoff: initialDelay * 2^(attempt-1), capped at maxDelay.
// Guards against integer overflow from both large shift values and large InitialDelay.
func (t *RetryTransport) backoffDelay(attempt int) time.Duration {
	shift := min(attempt-1, maxBackoffShift)
	multiplier := int64(1) << shift
	// Guard against multiplication overflow: if the multiplier alone would
	// exceed MaxDelay/InitialDelay, skip the multiplication entirely.
	if t.InitialDelay > 0 && multiplier > int64(t.MaxDelay/t.InitialDelay) {
		return t.MaxDelay
	}
	delay := t.InitialDelay * time.Duration(multiplier)
	return min(delay, t.MaxDelay)
}

// sleepWithRequestContext blocks for the given duration or until the context is cancelled.
// Returns the context error if cancelled.
func sleepWithRequestContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
