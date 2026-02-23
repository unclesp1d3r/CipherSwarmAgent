package hashcat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// setupSessionTestState sets up minimal agentstate paths for session tests
// and returns a cleanup function. Uses t.TempDir() for automatic cleanup.
func setupSessionTestState(t *testing.T) {
	t.Helper()
	tempDir := t.TempDir()

	savedZapsPath := agentstate.State.ZapsPath
	savedRetain := agentstate.State.RetainZapsOnCompletion

	agentstate.State.ZapsPath = filepath.Join(tempDir, "zaps")
	agentstate.State.RetainZapsOnCompletion = true // Avoid removing zaps dir during tests

	t.Cleanup(func() {
		agentstate.State.ZapsPath = savedZapsPath
		agentstate.State.RetainZapsOnCompletion = savedRetain
	})
}

// TestCleanup_RemovesRestoreFile verifies that Session.Cleanup removes the restore file.
func TestCleanup_RemovesRestoreFile(t *testing.T) {
	setupSessionTestState(t)

	restoreFile := filepath.Join(t.TempDir(), "test.restore")
	require.NoError(t, os.WriteFile(restoreFile, []byte("restore-data"), 0o600))

	sess := &Session{
		RestoreFilePath: restoreFile,
	}

	sess.Cleanup()

	_, err := os.Stat(restoreFile)
	assert.True(t, os.IsNotExist(err), "restore file should be removed after Cleanup")
}

// TestCleanup_SkipsMissingRestoreFile verifies that Cleanup does not error
// when the restore file does not exist.
func TestCleanup_SkipsMissingRestoreFile(t *testing.T) {
	setupSessionTestState(t)

	sess := &Session{
		RestoreFilePath: filepath.Join(t.TempDir(), "nonexistent.restore"),
	}

	// Should not panic
	sess.Cleanup()
}

// TestCleanup_SkipsEmptyRestoreFilePath verifies that Cleanup handles
// an empty RestoreFilePath gracefully.
func TestCleanup_SkipsEmptyRestoreFilePath(t *testing.T) {
	setupSessionTestState(t)

	sess := &Session{
		RestoreFilePath: "",
	}

	// Should not panic
	sess.Cleanup()
}
