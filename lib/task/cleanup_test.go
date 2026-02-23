package task

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// TestCleanupTaskFiles_RemovesHashFile verifies that CleanupTaskFiles
// removes the hash file for the given attack ID.
func TestCleanupTaskFiles_RemovesHashFile(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(1)
	t.Cleanup(cleanupState)

	var attackID int64 = 42
	hashFile := filepath.Join(agentstate.State.HashlistPath, "42.hsh")
	require.NoError(t, os.MkdirAll(filepath.Dir(hashFile), 0o750))
	require.NoError(t, os.WriteFile(hashFile, []byte("hashes"), 0o600))

	CleanupTaskFiles(attackID)

	_, err := os.Stat(hashFile)
	require.True(t, os.IsNotExist(err), "hash file should be removed")
}

// TestCleanupTaskFiles_RemovesRestoreFile verifies that CleanupTaskFiles
// removes the restore file for the given attack ID.
func TestCleanupTaskFiles_RemovesRestoreFile(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(1)
	t.Cleanup(cleanupState)

	var attackID int64 = 42
	restoreFile := filepath.Join(agentstate.State.RestoreFilePath, "42.restore")
	require.NoError(t, os.MkdirAll(filepath.Dir(restoreFile), 0o750))
	require.NoError(t, os.WriteFile(restoreFile, []byte("data"), 0o600))

	CleanupTaskFiles(attackID)

	_, err := os.Stat(restoreFile)
	require.True(t, os.IsNotExist(err), "restore file should be removed")
}

// TestCleanupTaskFiles_HandlesNonexistentFiles verifies that CleanupTaskFiles
// does not panic or error when files do not exist.
func TestCleanupTaskFiles_HandlesNonexistentFiles(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(1)
	t.Cleanup(cleanupState)

	// Should not panic with a nonexistent attack ID
	CleanupTaskFiles(99999)
}

// TestCleanupTaskFiles_RemovesBothFiles verifies that both hash and restore
// files are removed in a single call.
func TestCleanupTaskFiles_RemovesBothFiles(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(1)
	t.Cleanup(cleanupState)

	var attackID int64 = 99
	hashFile := filepath.Join(agentstate.State.HashlistPath, "99.hsh")
	restoreFile := filepath.Join(agentstate.State.RestoreFilePath, "99.restore")

	require.NoError(t, os.MkdirAll(filepath.Dir(hashFile), 0o750))
	require.NoError(t, os.MkdirAll(filepath.Dir(restoreFile), 0o750))
	require.NoError(t, os.WriteFile(hashFile, []byte("hashes"), 0o600))
	require.NoError(t, os.WriteFile(restoreFile, []byte("data"), 0o600))

	CleanupTaskFiles(attackID)

	_, hashErr := os.Stat(hashFile)
	require.True(t, os.IsNotExist(hashErr), "hash file should be removed")

	_, restoreErr := os.Stat(restoreFile)
	require.True(t, os.IsNotExist(restoreErr), "restore file should be removed")
}
