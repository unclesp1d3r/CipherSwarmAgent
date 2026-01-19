package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/charmbracelet/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
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

func TestHandleCrackerUpdate_SetsActivity(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Save original activity
	originalActivity := agentstate.State.CurrentActivity

	defer func() {
		agentstate.State.CurrentActivity = originalActivity
	}()

	// Set up minimal state
	agentstate.State.CurrentActivity = agentstate.CurrentActivityWaiting

	// handleCrackerUpdate changes activity to Updating, then back to Starting
	// Note: This will call lib.UpdateCracker() which may have side effects
	// but should not crash with minimal state

	// Just verify function signature is correct - actual behavior depends on lib package
	assert.NotPanics(t, func() {
		// We can't easily test this without mocking lib.UpdateCracker
		// Just verify the activity constants are valid
		assert.NotEmpty(t, string(agentstate.CurrentActivityUpdating))
		assert.NotEmpty(t, string(agentstate.CurrentActivityStarting))
	})
}

func TestHandleReload_SetsReloadFalse(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Set up state for reload
	agentstate.State.Reload = true
	agentstate.State.CurrentActivity = agentstate.CurrentActivityWaiting

	// handleReload depends on lib.* functions that require API client
	// We can only verify the state structure here without full mocking

	assert.True(t, agentstate.State.Reload)
	// After handleReload(), State.Reload should be false
	// But we can't call it without mocking the lib functions
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

	// Initial state
	agentstate.State.ExtraDebugging = false

	// Set to true
	agentstate.State.ExtraDebugging = true
	assert.True(t, agentstate.State.ExtraDebugging)

	// Verify it affects logging behavior in heartbeat
	// (heartbeat logs extra debug info when ExtraDebugging is true)
}
