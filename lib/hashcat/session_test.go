package hashcat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// TestCleanup_RemovesRestoreFile verifies that Session.Cleanup removes the restore file.
func TestCleanup_RemovesRestoreFile(t *testing.T) {
	tempDir := t.TempDir()
	agentstate.State.ZapsPath = filepath.Join(tempDir, "zaps")

	restoreFile := filepath.Join(tempDir, "test.restore")
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
	tempDir := t.TempDir()
	agentstate.State.ZapsPath = filepath.Join(tempDir, "zaps")

	sess := &Session{
		RestoreFilePath: filepath.Join(tempDir, "nonexistent.restore"),
	}

	// Should not panic
	sess.Cleanup()
}

// TestCleanup_SkipsEmptyRestoreFilePath verifies that Cleanup handles
// an empty RestoreFilePath gracefully.
func TestCleanup_SkipsEmptyRestoreFilePath(t *testing.T) {
	tempDir := t.TempDir()
	agentstate.State.ZapsPath = filepath.Join(tempDir, "zaps")

	sess := &Session{
		RestoreFilePath: "",
	}

	// Should not panic
	sess.Cleanup()
}
