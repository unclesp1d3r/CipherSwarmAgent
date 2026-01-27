package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/charmbracelet/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// saveAndRestoreState saves the current agentstate and returns a cleanup function.
func saveAndRestoreState(t *testing.T) func() {
	t.Helper()
	original := agentstate.State

	return func() {
		agentstate.State = original
	}
}

func TestCleanupLockFile_Success(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "test.pid")

	// Create the PID file
	err := os.WriteFile(pidFile, []byte("12345"), 0o600)
	require.NoError(t, err)

	// Verify file exists
	assert.FileExists(t, pidFile)

	// Cleanup should remove the file
	cleanupLockFile(pidFile)

	// Verify file was removed
	assert.NoFileExists(t, pidFile)
}

func TestInitLogger_DebugMode(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Save original logger state
	originalLevel := agentstate.Logger.GetLevel()
	originalReportCaller := false // Can't easily check this, but we verify it doesn't panic

	defer func() {
		agentstate.Logger.SetLevel(originalLevel)
		agentstate.Logger.SetReportCaller(originalReportCaller)
	}()

	agentstate.State.Debug = true

	initLogger()

	assert.Equal(t, log.DebugLevel, agentstate.Logger.GetLevel())
}

func TestInitLogger_NormalMode(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Save original logger state
	originalLevel := agentstate.Logger.GetLevel()

	defer func() {
		agentstate.Logger.SetLevel(originalLevel)
	}()

	agentstate.State.Debug = false

	initLogger()

	assert.Equal(t, log.InfoLevel, agentstate.Logger.GetLevel())
}

func TestHandleNewTask_BenchmarksNotSubmitted(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	agentstate.State.BenchmarksSubmitted = false

	// This should return early without error
	handleNewTask()

	// No assertion needed - just verifying it doesn't panic
	assert.False(t, agentstate.State.BenchmarksSubmitted)
}

func TestActivityConstants_AreValid(t *testing.T) {
	assert.NotEmpty(t, string(agentstate.CurrentActivityUpdating))
	assert.NotEmpty(t, string(agentstate.CurrentActivityStarting))
}

func TestAgentActivityTransitions(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Test that activity transitions are valid
	t.Run("Starting", func(t *testing.T) {
		agentstate.State.CurrentActivity = agentstate.CurrentActivityStarting
		assert.Equal(t, agentstate.CurrentActivityStarting, agentstate.State.CurrentActivity)
	})

	t.Run("Benchmarking", func(t *testing.T) {
		agentstate.State.CurrentActivity = agentstate.CurrentActivityBenchmarking
		assert.Equal(t, agentstate.CurrentActivityBenchmarking, agentstate.State.CurrentActivity)
	})

	t.Run("Updating", func(t *testing.T) {
		agentstate.State.CurrentActivity = agentstate.CurrentActivityUpdating
		assert.Equal(t, agentstate.CurrentActivityUpdating, agentstate.State.CurrentActivity)
	})

	t.Run("Waiting", func(t *testing.T) {
		agentstate.State.CurrentActivity = agentstate.CurrentActivityWaiting
		assert.Equal(t, agentstate.CurrentActivityWaiting, agentstate.State.CurrentActivity)
	})

	t.Run("Cracking", func(t *testing.T) {
		agentstate.State.CurrentActivity = agentstate.CurrentActivityCracking
		assert.Equal(t, agentstate.CurrentActivityCracking, agentstate.State.CurrentActivity)
	})

	t.Run("Stopping", func(t *testing.T) {
		agentstate.State.CurrentActivity = agentstate.CurrentActivityStopping
		assert.Equal(t, agentstate.CurrentActivityStopping, agentstate.State.CurrentActivity)
	})
}

func TestJobCheckingStoppedFlag(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Initial state
	agentstate.State.JobCheckingStopped = false

	// Set to true
	agentstate.State.JobCheckingStopped = true
	assert.True(t, agentstate.State.JobCheckingStopped)

	// Set back to false
	agentstate.State.JobCheckingStopped = false
	assert.False(t, agentstate.State.JobCheckingStopped)
}

func TestReloadFlag(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Initial state
	agentstate.State.Reload = false

	// Set to true
	agentstate.State.Reload = true
	assert.True(t, agentstate.State.Reload)

	// Set back to false
	agentstate.State.Reload = false
	assert.False(t, agentstate.State.Reload)
}

func TestExtraDebuggingFlag(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	defer cleanupState()

	// Mock heartbeat response so we don't hit the network
	testhelpers.MockHeartbeatNoContent(123)

	var buf bytes.Buffer
	originalLevel := agentstate.Logger.GetLevel()
	agentstate.Logger.SetLevel(log.DebugLevel)
	agentstate.Logger.SetOutput(&buf)
	defer func() {
		agentstate.Logger.SetLevel(originalLevel)
		agentstate.Logger.SetOutput(os.Stdout)
	}()

	signChan := make(chan os.Signal, 1)

	agentstate.State.ExtraDebugging = true
	err := heartbeat(signChan)
	require.NoError(t, err)
	logOutput := buf.String()
	assert.Contains(t, logOutput, "Sending heartbeat")
	assert.Contains(t, logOutput, "Heartbeat sent")

	buf.Reset()
	agentstate.State.ExtraDebugging = false
	err = heartbeat(signChan)
	require.NoError(t, err)
	logOutput = buf.String()
	assert.NotContains(t, logOutput, "Sending heartbeat")
	assert.NotContains(t, logOutput, "Heartbeat sent")
}

// TestCalculateHeartbeatBackoff tests the exponential backoff calculation
// used by the heartbeat loop circuit breaker pattern.
func TestCalculateHeartbeatBackoff(t *testing.T) {
	baseInterval := 10 * time.Second

	tests := []struct {
		name                 string
		consecutiveFailures  int
		maxBackoffMultiplier int
		expectedBackoff      time.Duration
	}{
		{
			name:                 "first failure doubles interval",
			consecutiveFailures:  1,
			maxBackoffMultiplier: 6,
			expectedBackoff:      20 * time.Second, // 10 * 2^1 = 20
		},
		{
			name:                 "second failure quadruples interval",
			consecutiveFailures:  2,
			maxBackoffMultiplier: 6,
			expectedBackoff:      40 * time.Second, // 10 * 2^2 = 40
		},
		{
			name:                 "third failure 8x interval",
			consecutiveFailures:  3,
			maxBackoffMultiplier: 6,
			expectedBackoff:      80 * time.Second, // 10 * 2^3 = 80
		},
		{
			name:                 "failures at max multiplier cap",
			consecutiveFailures:  6,
			maxBackoffMultiplier: 6,
			expectedBackoff:      640 * time.Second,
		},
		{
			name:                 "failures exceed max multiplier - capped",
			consecutiveFailures:  10,
			maxBackoffMultiplier: 6,
			expectedBackoff:      640 * time.Second,
		},
		{
			name:                 "zero failures returns base interval",
			consecutiveFailures:  0,
			maxBackoffMultiplier: 6,
			expectedBackoff:      10 * time.Second, // 10 * 2^0 = 10
		},
		{
			name:                 "max multiplier of 1 caps early",
			consecutiveFailures:  5,
			maxBackoffMultiplier: 1,
			expectedBackoff:      20 * time.Second, // capped at 10 * 2^1 = 20
		},
		{
			name:                 "max multiplier of 0 means no exponential growth",
			consecutiveFailures:  5,
			maxBackoffMultiplier: 0,
			expectedBackoff:      10 * time.Second, // capped at 10 * 2^0 = 10
		},
		{
			name:                 "negative failures treated as zero",
			consecutiveFailures:  -5,
			maxBackoffMultiplier: 6,
			expectedBackoff:      10 * time.Second, // -5 -> 0, so 10 * 2^0 = 10
		},
		{
			name:                 "negative maxMultiplier treated as zero",
			consecutiveFailures:  3,
			maxBackoffMultiplier: -1,
			expectedBackoff:      10 * time.Second, // -1 -> 0, capped at 2^0
		},
		{
			name:                 "both negative treated as zero",
			consecutiveFailures:  -1,
			maxBackoffMultiplier: -1,
			expectedBackoff:      10 * time.Second, // both -> 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateHeartbeatBackoff(baseInterval, tt.consecutiveFailures, tt.maxBackoffMultiplier)
			assert.Equal(t, tt.expectedBackoff, result,
				"calculateHeartbeatBackoff(%v, %d, %d) = %v, want %v",
				baseInterval, tt.consecutiveFailures, tt.maxBackoffMultiplier, result, tt.expectedBackoff)
		})
	}
}

// TestCalculateHeartbeatBackoff_DifferentBaseIntervals verifies the formula
// works correctly with various base intervals.
func TestCalculateHeartbeatBackoff_DifferentBaseIntervals(t *testing.T) {
	tests := []struct {
		name            string
		baseInterval    time.Duration
		failures        int
		maxMultiplier   int
		expectedBackoff time.Duration
	}{
		{
			name:            "1 second base with 3 failures",
			baseInterval:    1 * time.Second,
			failures:        3,
			maxMultiplier:   6,
			expectedBackoff: 8 * time.Second, // 1 * 2^3 = 8
		},
		{
			name:            "5 second base with 2 failures",
			baseInterval:    5 * time.Second,
			failures:        2,
			maxMultiplier:   6,
			expectedBackoff: 20 * time.Second, // 5 * 2^2 = 20
		},
		{
			name:            "30 second base with 4 failures",
			baseInterval:    30 * time.Second,
			failures:        4,
			maxMultiplier:   6,
			expectedBackoff: 480 * time.Second, // 30 * 2^4 = 480 (8 minutes)
		},
		{
			name:            "100ms base for fast retry scenarios",
			baseInterval:    100 * time.Millisecond,
			failures:        3,
			maxMultiplier:   6,
			expectedBackoff: 800 * time.Millisecond, // 100ms * 2^3 = 800ms
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateHeartbeatBackoff(tt.baseInterval, tt.failures, tt.maxMultiplier)
			assert.Equal(t, tt.expectedBackoff, result)
		})
	}
}

// TestCalculateHeartbeatBackoff_DefaultConfig verifies the backoff calculation
// works correctly with the default configuration values (max_heartbeat_backoff=6).
func TestCalculateHeartbeatBackoff_DefaultConfig(t *testing.T) {
	// Default config: max_heartbeat_backoff = 6
	// Default heartbeat_interval = 10 seconds
	baseInterval := 10 * time.Second
	maxBackoff := 6

	// Verify the progression: 20s, 40s, 80s, 160s, 320s, 640s, 640s (capped)
	expectedProgression := []time.Duration{
		10 * time.Second,  // 0 failures (not really used, but formula gives base)
		20 * time.Second,  // 1 failure
		40 * time.Second,  // 2 failures
		80 * time.Second,  // 3 failures
		160 * time.Second, // 4 failures
		320 * time.Second, // 5 failures
		640 * time.Second, // 6 failures (max)
		640 * time.Second, // 7 failures (capped)
		640 * time.Second, // 8 failures (capped)
	}

	for failures, expected := range expectedProgression {
		result := calculateHeartbeatBackoff(baseInterval, failures, maxBackoff)
		assert.Equal(t, expected, result,
			"failure %d: expected %v, got %v", failures, expected, result)
	}
}
