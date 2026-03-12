package api

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCircuitBreaker_StartsInClosedState(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)
	require.True(t, cb.Allow())
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()
	require.True(t, cb.Allow()) // 2 failures, threshold is 3

	cb.RecordFailure()
	require.False(t, cb.Allow()) // 3 failures, circuit opens
}

func TestCircuitBreaker_HalfOpensAfterTimeout(t *testing.T) {
	cb := NewCircuitBreaker(2, 10*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()
	require.False(t, cb.Allow()) // open

	time.Sleep(15 * time.Millisecond) // wait for timeout
	require.True(t, cb.Allow())       // half-open: allows one probe
	require.False(t, cb.Allow())      // still half-open, no second probe
}

func TestCircuitBreaker_ClosesAfterSuccessInHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(2, 10*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()

	time.Sleep(15 * time.Millisecond) // half-open
	require.True(t, cb.Allow())
	cb.RecordSuccess() // close circuit

	require.True(t, cb.Allow()) // back to closed
}

func TestCircuitBreaker_ReopensOnFailureInHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(2, 10*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()

	time.Sleep(15 * time.Millisecond) // half-open
	require.True(t, cb.Allow())
	cb.RecordFailure() // trip again

	require.False(t, cb.Allow()) // back to open
}

func TestCircuitBreaker_ResetClearsState(t *testing.T) {
	cb := NewCircuitBreaker(2, 100*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()
	require.False(t, cb.Allow())

	cb.Reset()
	require.True(t, cb.Allow())
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // reset
	cb.RecordFailure()
	cb.RecordFailure()
	require.True(t, cb.Allow()) // only 2 consecutive failures since last success
}

func TestCircuitBreaker_ErrCircuitOpen(t *testing.T) {
	require.True(t, errors.Is(ErrCircuitOpen, ErrCircuitOpen))
}
