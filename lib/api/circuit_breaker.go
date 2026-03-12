package api

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the circuit breaker is open and not allowing requests.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// circuitState represents the state of a circuit breaker.
type circuitState int

const (
	stateClosed   circuitState = iota // Normal operation
	stateOpen                         // Failing, rejecting requests
	stateHalfOpen                     // Testing if service has recovered
)

// CircuitBreaker implements the circuit breaker pattern for API resilience.
// It tracks consecutive failures and opens the circuit when a threshold is reached,
// preventing further requests until a timeout expires and a probe request succeeds.
//
// Thread-safe: all methods use a mutex for synchronization.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            circuitState
	failures         int
	failureThreshold int
	timeout          time.Duration
	lastFailureTime  time.Time
}

// NewCircuitBreaker creates a circuit breaker with the given failure threshold and timeout.
func NewCircuitBreaker(failureThreshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		timeout:          timeout,
		state:            stateClosed,
	}
}

// Allow returns true if the circuit breaker allows a request to proceed.
// In closed state, always allows. In open state, allows only after the timeout
// has elapsed (transitions to half-open for a single probe request).
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case stateClosed:
		return true
	case stateOpen:
		if time.Since(cb.lastFailureTime) >= cb.timeout {
			cb.state = stateHalfOpen
			return true
		}
		return false
	case stateHalfOpen:
		return false // Only one probe request at a time
	}

	return false
}

// RecordSuccess records a successful request. Resets failure count and closes the circuit.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = stateClosed
}

// RecordFailure records a failed request. Increments failure count and opens the
// circuit if the threshold is reached. In half-open state, immediately reopens.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.state == stateHalfOpen || cb.failures >= cb.failureThreshold {
		cb.state = stateOpen
	}
}

// Reset clears the circuit breaker state back to closed with zero failures.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = stateClosed
	cb.lastFailureTime = time.Time{}
}
