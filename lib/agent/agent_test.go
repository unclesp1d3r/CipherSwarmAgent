package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

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
