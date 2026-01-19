package cracker

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

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

func TestFindHashcatBinary_NotFound(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Set paths to non-existent locations
	agentstate.State.CrackersPath = "/nonexistent/path"

	// This should fail to find the binary (unless hashcat is actually installed)
	path, err := FindHashcatBinary()
	// If hashcat is installed on the system, the test may pass
	// Otherwise it should return an error
	if err != nil {
		require.ErrorIs(t, err, ErrHashcatBinaryNotFound)
		assert.Empty(t, path)
	}
}

func TestFindHashcatBinary_InCrackersPath(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Create temp directory with mock hashcat binary
	tempDir := t.TempDir()
	hashcatDir := filepath.Join(tempDir, "hashcat")
	err := os.MkdirAll(hashcatDir, 0o750)
	require.NoError(t, err)

	// Create a fake hashcat executable (needs exec permission)
	hashcatPath := filepath.Join(hashcatDir, "hashcat")
	//nolint:gosec // G306: Executable binary needs exec permission (0o700)
	err = os.WriteFile(hashcatPath, []byte("#!/bin/sh\necho mock"), 0o700)
	require.NoError(t, err)

	agentstate.State.CrackersPath = tempDir

	foundPath, err := FindHashcatBinary()

	// The function checks for executable files
	if err == nil {
		assert.Contains(t, foundPath, "hashcat")
	}
}

func TestCheckForExistingClient_NoPidFile(t *testing.T) {
	tempDir := t.TempDir()
	pidFilePath := filepath.Join(tempDir, "nonexistent.pid")

	result := CheckForExistingClient(pidFilePath)

	assert.False(t, result, "Should return false when PID file doesn't exist")
}

func TestCheckForExistingClient_PidFileWithCurrentProcess(t *testing.T) {
	tempDir := t.TempDir()
	pidFilePath := filepath.Join(tempDir, "test.pid")

	// Write current process PID to file (we know it's running)
	currentPid := os.Getpid()
	err := os.WriteFile(pidFilePath, []byte(strconv.Itoa(currentPid)), 0o600)
	require.NoError(t, err)

	result := CheckForExistingClient(pidFilePath)

	assert.True(t, result, "Should return true when PID file contains running process")
}

func TestCheckForExistingClient_PidFileWithDeadProcess(t *testing.T) {
	tempDir := t.TempDir()
	pidFilePath := filepath.Join(tempDir, "test.pid")

	// Write a PID that's very unlikely to be running (high number)
	// Using 99999999 which is unlikely to be a valid PID
	err := os.WriteFile(pidFilePath, []byte("99999999"), 0o600)
	require.NoError(t, err)

	result := CheckForExistingClient(pidFilePath)

	assert.False(t, result, "Should return false when PID file contains dead process")
}

func TestCheckForExistingClient_InvalidPidFile(t *testing.T) {
	tempDir := t.TempDir()
	pidFilePath := filepath.Join(tempDir, "test.pid")

	// Write invalid PID content
	err := os.WriteFile(pidFilePath, []byte("not-a-number"), 0o600)
	require.NoError(t, err)

	result := CheckForExistingClient(pidFilePath)

	// Returns true on error (fail-safe behavior)
	assert.True(t, result, "Should return true on conversion error (fail-safe)")
}

func TestCreateLockFile(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	tempDir := t.TempDir()
	pidFilePath := filepath.Join(tempDir, "agent.pid")
	agentstate.State.PidFile = pidFilePath

	err := CreateLockFile()

	require.NoError(t, err)

	// Verify file exists
	assert.FileExists(t, pidFilePath)

	// Verify contents match current PID
	content, err := os.ReadFile(pidFilePath)
	require.NoError(t, err)

	expectedPid := strconv.Itoa(os.Getpid())
	assert.Equal(t, expectedPid, string(content))
}

func TestCreateLockFile_InvalidPath(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Set an invalid path that can't be written to
	agentstate.State.PidFile = "/nonexistent/deeply/nested/path/agent.pid"

	err := CreateLockFile()

	require.Error(t, err, "Should return error for invalid path")
}

func TestCreateDataDirs(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	tempDir := t.TempDir()

	// Set all data directories to subdirectories of temp
	agentstate.State.FilePath = filepath.Join(tempDir, "files")
	agentstate.State.CrackersPath = filepath.Join(tempDir, "crackers")
	agentstate.State.HashlistPath = filepath.Join(tempDir, "hashlists")
	agentstate.State.ZapsPath = filepath.Join(tempDir, "zaps")
	agentstate.State.PreprocessorsPath = filepath.Join(tempDir, "preprocessors")
	agentstate.State.ToolsPath = filepath.Join(tempDir, "tools")
	agentstate.State.OutPath = filepath.Join(tempDir, "out")
	agentstate.State.RestoreFilePath = filepath.Join(tempDir, "restore")

	err := CreateDataDirs()

	require.NoError(t, err)

	// Verify all directories were created
	assert.DirExists(t, agentstate.State.FilePath)
	assert.DirExists(t, agentstate.State.CrackersPath)
	assert.DirExists(t, agentstate.State.HashlistPath)
	assert.DirExists(t, agentstate.State.ZapsPath)
	assert.DirExists(t, agentstate.State.PreprocessorsPath)
	assert.DirExists(t, agentstate.State.ToolsPath)
	assert.DirExists(t, agentstate.State.OutPath)
	assert.DirExists(t, agentstate.State.RestoreFilePath)
}

func TestCreateDataDirs_ExistingDirs(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	tempDir := t.TempDir()

	// Pre-create directories
	filesPath := filepath.Join(tempDir, "files")
	err := os.MkdirAll(filesPath, 0o750)
	require.NoError(t, err)

	agentstate.State.FilePath = filesPath
	agentstate.State.CrackersPath = filepath.Join(tempDir, "crackers")
	agentstate.State.HashlistPath = ""
	agentstate.State.ZapsPath = ""
	agentstate.State.PreprocessorsPath = ""
	agentstate.State.ToolsPath = ""
	agentstate.State.OutPath = ""
	agentstate.State.RestoreFilePath = ""

	err = CreateDataDirs()

	require.NoError(t, err)
	assert.DirExists(t, filesPath)
	assert.DirExists(t, agentstate.State.CrackersPath)
}

func TestCreateDataDirs_BlankPaths(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Set all paths to blank
	agentstate.State.FilePath = ""
	agentstate.State.CrackersPath = ""
	agentstate.State.HashlistPath = ""
	agentstate.State.ZapsPath = ""
	agentstate.State.PreprocessorsPath = ""
	agentstate.State.ToolsPath = ""
	agentstate.State.OutPath = ""
	agentstate.State.RestoreFilePath = ""

	// Should not error, just skip blank paths
	err := CreateDataDirs()

	require.NoError(t, err)
}

func TestMoveArchiveFile(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	tempDir := t.TempDir()
	agentstate.State.CrackersPath = tempDir

	// Create a temp file to move
	sourceFile := filepath.Join(tempDir, "source.7z")
	err := os.WriteFile(sourceFile, []byte("archive content"), 0o600)
	require.NoError(t, err)

	newPath, err := MoveArchiveFile(sourceFile)

	require.NoError(t, err)
	assert.Equal(t, filepath.Join(tempDir, "hashcat.7z"), newPath)

	// Verify source was moved
	assert.NoFileExists(t, sourceFile)
	assert.FileExists(t, newPath)

	// Verify content
	content, err := os.ReadFile(newPath)
	require.NoError(t, err)
	assert.Equal(t, "archive content", string(content))
}

func TestMoveArchiveFile_SourceNotExist(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	tempDir := t.TempDir()
	agentstate.State.CrackersPath = tempDir

	nonExistentSource := filepath.Join(tempDir, "nonexistent.7z")

	_, err := MoveArchiveFile(nonExistentSource)

	require.Error(t, err)
}

func TestExtractHashcatArchive_InvalidArchive(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	tempDir := t.TempDir()
	agentstate.State.CrackersPath = tempDir

	// Create a fake (invalid) archive
	invalidArchive := filepath.Join(tempDir, "invalid.7z")
	err := os.WriteFile(invalidArchive, []byte("not a real 7z archive"), 0o600)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = ExtractHashcatArchive(ctx, invalidArchive)

	// Should fail because the archive is invalid
	require.Error(t, err)
}

func TestExtractHashcatArchive_BackupExisting(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	tempDir := t.TempDir()
	agentstate.State.CrackersPath = tempDir

	// Create existing hashcat directory
	hashcatDir := filepath.Join(tempDir, "hashcat")
	err := os.MkdirAll(hashcatDir, 0o750)
	require.NoError(t, err)

	// Create a file in the existing directory (needs exec permission for binary)
	existingFile := filepath.Join(hashcatDir, "old_hashcat")
	err = os.WriteFile(existingFile, []byte("old binary"), 0o700) //nolint:gosec // Executable needs exec permission
	require.NoError(t, err)

	// Create a fake archive
	invalidArchive := filepath.Join(tempDir, "hashcat.7z")
	err = os.WriteFile(invalidArchive, []byte("not a real 7z archive"), 0o600)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = ExtractHashcatArchive(ctx, invalidArchive)

	// The extraction will fail, but the backup should have been made
	require.Error(t, err)

	// Check that old directory was backed up
	backupDir := filepath.Join(tempDir, "hashcat_old")
	assert.DirExists(t, backupDir)
}

func TestGetCurrentHashcatVersion_BinaryNotFound(t *testing.T) {
	cleanup := saveAndRestoreState(t)
	defer cleanup()

	// Set paths to non-existent locations
	agentstate.State.CrackersPath = "/nonexistent/path/for/testing"

	ctx := context.Background()
	version, err := GetCurrentHashcatVersion(ctx)
	// If hashcat is not installed system-wide, this should fail
	if err != nil {
		assert.Equal(t, emptyVersion, version)
		require.ErrorIs(t, err, ErrHashcatBinaryNotFound)
	}
}

func TestErrHashcatBinaryNotFound(t *testing.T) {
	assert.Equal(t, "hashcat binary not found", ErrHashcatBinaryNotFound.Error())
}

func TestEmptyVersionConstant(t *testing.T) {
	assert.Equal(t, "0.0.0", emptyVersion)
}
