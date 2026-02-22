package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// saveAndRestoreState saves the current agentstate fields and returns a cleanup function
// that restores them. Uses per-field save/restore to avoid copying sync primitives.
func saveAndRestoreState(t *testing.T) func() {
	t.Helper()
	// Save plain (non-synchronized) fields
	origDebug := agentstate.State.Debug
	origExtraDebugging := agentstate.State.ExtraDebugging
	origAgentID := agentstate.State.AgentID
	origURL := agentstate.State.URL
	origAPIToken := agentstate.State.APIToken
	origAPIClient := agentstate.State.APIClient

	// Save synchronized fields via getters
	origReload := agentstate.State.GetReload()
	origJobCheckingStopped := agentstate.State.GetJobCheckingStopped()
	origBenchmarksSubmitted := agentstate.State.GetBenchmarksSubmitted()
	origCurrentActivity := agentstate.State.GetCurrentActivity()

	return func() {
		agentstate.State.Debug = origDebug
		agentstate.State.ExtraDebugging = origExtraDebugging
		agentstate.State.AgentID = origAgentID
		agentstate.State.URL = origURL
		agentstate.State.APIToken = origAPIToken
		agentstate.State.APIClient = origAPIClient

		agentstate.State.SetReload(origReload)
		agentstate.State.SetJobCheckingStopped(origJobCheckingStopped)
		agentstate.State.SetBenchmarksSubmitted(origBenchmarksSubmitted)
		agentstate.State.SetCurrentActivity(origCurrentActivity)
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

	defer func() {
		agentstate.Logger.SetLevel(originalLevel)
		agentstate.Logger.SetReportCaller(false)
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

	agentstate.State.SetBenchmarksSubmitted(false)

	// This should return early without error
	handleNewTask(context.Background())

	// No assertion needed - just verifying it doesn't panic
	assert.False(t, agentstate.State.GetBenchmarksSubmitted())
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
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStarting)
		assert.Equal(t, agentstate.CurrentActivityStarting, agentstate.State.GetCurrentActivity())
	})

	t.Run("Benchmarking", func(t *testing.T) {
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityBenchmarking)
		assert.Equal(t, agentstate.CurrentActivityBenchmarking, agentstate.State.GetCurrentActivity())
	})

	t.Run("Updating", func(t *testing.T) {
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityUpdating)
		assert.Equal(t, agentstate.CurrentActivityUpdating, agentstate.State.GetCurrentActivity())
	})

	t.Run("Waiting", func(t *testing.T) {
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
		assert.Equal(t, agentstate.CurrentActivityWaiting, agentstate.State.GetCurrentActivity())
	})

	t.Run("Cracking", func(t *testing.T) {
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityCracking)
		assert.Equal(t, agentstate.CurrentActivityCracking, agentstate.State.GetCurrentActivity())
	})

	t.Run("Stopping", func(t *testing.T) {
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStopping)
		assert.Equal(t, agentstate.CurrentActivityStopping, agentstate.State.GetCurrentActivity())
	})
}

func TestJobCheckingStoppedFlag(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Initial state
	agentstate.State.SetJobCheckingStopped(false)

	// Set to true
	agentstate.State.SetJobCheckingStopped(true)
	assert.True(t, agentstate.State.GetJobCheckingStopped())

	// Set back to false
	agentstate.State.SetJobCheckingStopped(false)
	assert.False(t, agentstate.State.GetJobCheckingStopped())
}

func TestReloadFlag(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Initial state
	agentstate.State.SetReload(false)

	// Set to true
	agentstate.State.SetReload(true)
	assert.True(t, agentstate.State.GetReload())

	// Set back to false
	agentstate.State.SetReload(false)
	assert.False(t, agentstate.State.GetReload())
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
	err := heartbeat(context.Background(), signChan)
	require.NoError(t, err)
	logOutput := buf.String()
	assert.Contains(t, logOutput, "Sending heartbeat")
	assert.Contains(t, logOutput, "Heartbeat sent")

	buf.Reset()
	agentstate.State.ExtraDebugging = false
	err = heartbeat(context.Background(), signChan)
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

// TestCleanupLockFile_NonexistentFile verifies that cleaning up a nonexistent
// file does not panic or produce errors (idempotent operation).
func TestCleanupLockFile_NonexistentFile(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "nonexistent.pid")

	// Should not panic
	cleanupLockFile(pidFile)

	// File should still not exist
	assert.NoFileExists(t, pidFile)
}

// TestCleanupLockFile_EmptyPath verifies that cleaning up with an empty path
// does not panic.
func TestCleanupLockFile_EmptyPath(_ *testing.T) {
	// Should not panic
	cleanupLockFile("")
}

// TestHeartbeat_StatePending verifies that a StatePending heartbeat response
// sets the Reload flag when the agent is not benchmarking.
func TestHeartbeat_StatePending(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	defer cleanupState()

	testhelpers.MockHeartbeatResponse(123, api.StatePending)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
	agentstate.State.SetReload(false)

	signChan := make(chan os.Signal, 1)
	err := heartbeat(context.Background(), signChan)
	require.NoError(t, err)
	assert.True(t, agentstate.State.GetReload(), "StatePending should set Reload=true")
}

// TestHeartbeat_StatePending_WhileBenchmarking verifies that a StatePending
// heartbeat response does NOT set Reload when the agent is benchmarking.
func TestHeartbeat_StatePending_WhileBenchmarking(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	defer cleanupState()

	testhelpers.MockHeartbeatResponse(123, api.StatePending)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityBenchmarking)
	agentstate.State.SetReload(false)

	signChan := make(chan os.Signal, 1)
	err := heartbeat(context.Background(), signChan)
	require.NoError(t, err)
	assert.False(t, agentstate.State.GetReload(), "StatePending during benchmarking should NOT set Reload")
}

// TestHeartbeat_StateStopped verifies that a StateStopped heartbeat response
// sets JobCheckingStopped and changes activity to Stopping.
func TestHeartbeat_StateStopped(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	defer cleanupState()

	testhelpers.MockHeartbeatResponse(123, api.StateStopped)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
	agentstate.State.SetJobCheckingStopped(false)

	signChan := make(chan os.Signal, 1)
	err := heartbeat(context.Background(), signChan)
	require.NoError(t, err)
	assert.True(t, agentstate.State.GetJobCheckingStopped(), "StateStopped should set JobCheckingStopped=true")
	assert.Equal(t, agentstate.CurrentActivityStopping, agentstate.State.GetCurrentActivity())
}

// TestHeartbeat_StateStopped_WhileCracking verifies that a StateStopped
// heartbeat response does NOT change state when the agent is cracking.
func TestHeartbeat_StateStopped_WhileCracking(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	defer cleanupState()

	testhelpers.MockHeartbeatResponse(123, api.StateStopped)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityCracking)
	agentstate.State.SetJobCheckingStopped(false)

	signChan := make(chan os.Signal, 1)
	err := heartbeat(context.Background(), signChan)
	require.NoError(t, err)
	assert.False(
		t,
		agentstate.State.GetJobCheckingStopped(),
		"StateStopped during cracking should NOT set JobCheckingStopped",
	)
	assert.Equal(t, agentstate.CurrentActivityCracking, agentstate.State.GetCurrentActivity())
}

// TestHeartbeat_StateError verifies that a StateError heartbeat response
// sends a SIGTERM signal to the signal channel.
func TestHeartbeat_StateError(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	defer cleanupState()

	testhelpers.MockHeartbeatResponse(123, api.StateError)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)

	signChan := make(chan os.Signal, 1)
	err := heartbeat(context.Background(), signChan)
	require.NoError(t, err)

	// Verify SIGTERM was sent to the channel
	select {
	case sig := <-signChan:
		assert.Equal(t, syscall.SIGTERM, sig, "StateError should send SIGTERM")
	default:
		t.Fatal("expected SIGTERM signal on signChan, but channel was empty")
	}
}

// TestHeartbeat_NoContent verifies that a 204 No Content heartbeat response
// returns nil state and nil error without modifying agent state.
func TestHeartbeat_NoContent(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
	defer cleanupState()

	testhelpers.MockHeartbeatNoContent(123)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
	agentstate.State.SetReload(false)
	agentstate.State.SetJobCheckingStopped(false)

	signChan := make(chan os.Signal, 1)
	err := heartbeat(context.Background(), signChan)
	require.NoError(t, err)

	// State should be unchanged
	assert.False(t, agentstate.State.GetReload())
	assert.False(t, agentstate.State.GetJobCheckingStopped())
	assert.Equal(t, agentstate.CurrentActivityWaiting, agentstate.State.GetCurrentActivity())
}
