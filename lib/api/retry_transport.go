package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"
)

// RetryTransport wraps an http.RoundTripper with retry logic using exponential backoff
// with jitter. It retries on network errors, 5xx responses, and 429 Too Many Requests,
// but not on other 4xx client errors.
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
	var lastStatusCode int

	for attempt := range maxAttempts {
		if attempt > 0 {
			// Reset request body for retries — POST/PUT bodies are consumed by RoundTrip.
			if err := resetRequestBody(req); err != nil {
				return nil, fmt.Errorf("failed to reset request body for retry: %w", err)
			}

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

		// Retry 429 Too Many Requests and 5xx server errors; return all others.
		if resp.StatusCode != http.StatusTooManyRequests &&
			resp.StatusCode < http.StatusInternalServerError {
			return resp, nil
		}

		// Retryable status: drain and close body before retry to avoid leaking connections
		if t.Logger != nil {
			t.Logger.Debug("API request returned retryable status, will retry",
				"attempt", attempt+1, "max", maxAttempts, "status", resp.StatusCode)
		}
		lastStatusCode = resp.StatusCode
		if resp.Body != nil {
			//nolint:errcheck // draining body before close; errors not actionable
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		lastErr = fmt.Errorf("%w: server returned %d", errRetryableStatus, lastStatusCode)
	}

	return nil, fmt.Errorf("all %d API request attempts failed: %w", maxAttempts, lastErr)
}

// errRetryableStatus is a sentinel for retryable HTTP responses (5xx, 429) after retry exhaustion.
var errRetryableStatus = errors.New("server error")

// resetRequestBody resets req.Body from req.GetBody so that POST/PUT requests
// can be retried with the full body. http.NewRequest sets GetBody for common
// body types (bytes.Reader, strings.Reader, bytes.Buffer).
func resetRequestBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil // GET or bodyless request — nothing to reset
	}
	if req.GetBody == nil {
		return errors.New("request body is not re-readable (GetBody is nil)")
	}
	body, err := req.GetBody()
	if err != nil {
		return err
	}
	req.Body = body
	return nil
}

// Compile-time interface compliance.
var (
	_ http.RoundTripper = (*RetryTransport)(nil)
	_ http.RoundTripper = (*CircuitTransport)(nil)
)

// maxBackoffShift is the maximum bit shift for exponential backoff to prevent integer overflow.
const maxBackoffShift = 62

// jitterDivisor controls the jitter range: delay is randomized to [delay/jitterDivisor, delay].
const jitterDivisor = 2

// backoffDelay computes exponential backoff with jitter:
// base = initialDelay * 2^(attempt-1), capped at maxDelay, then jittered to [base/2, base].
// Guards against integer overflow from both large shift values and large InitialDelay.
// When MaxDelay is zero, returns InitialDelay as a safe fallback.
func (t *RetryTransport) backoffDelay(attempt int) time.Duration {
	if t.MaxDelay <= 0 {
		return t.InitialDelay
	}

	shift := min(attempt-1, maxBackoffShift)
	multiplier := int64(1) << shift
	// Guard against multiplication overflow: if the multiplier alone would
	// exceed MaxDelay/InitialDelay, skip the multiplication entirely.
	if t.InitialDelay > 0 && multiplier > int64(t.MaxDelay/t.InitialDelay) {
		return addJitter(t.MaxDelay)
	}
	delay := t.InitialDelay * time.Duration(multiplier)
	return addJitter(min(delay, t.MaxDelay))
}

// addJitter applies random jitter to a delay, returning a value in [delay/2, delay].
// This prevents thundering herd when multiple agents retry against the same server.
func addJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := d / jitterDivisor
	//nolint:gosec // G404 - jitter does not need cryptographic randomness
	return half + time.Duration(rand.Int64N(int64(half)+1))
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
