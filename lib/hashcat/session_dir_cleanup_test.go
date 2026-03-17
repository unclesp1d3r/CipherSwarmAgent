package hashcat

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanupOrphanedInDir_RemovesMatchingFiles(t *testing.T) {
	dir := t.TempDir()

	// Create attack-* session files
	require.NoError(t, os.WriteFile(filepath.Join(dir, "attack-1.log"), []byte("log"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "attack-2.pid"), []byte("123"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "attack-42.log"), []byte("log"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "attack-42.pid"), []byte("456"), 0o600))

	cleanupOrphanedInDir(dir)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries, "all attack-* .log and .pid files should be removed")
}

func TestCleanupOrphanedInDir_IgnoresNonAttackFiles(t *testing.T) {
	dir := t.TempDir()

	// Create non-attack session files
	require.NoError(t, os.WriteFile(filepath.Join(dir, "benchmark.log"), []byte("log"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.pid"), []byte("123"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hashcat.log"), []byte("log"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.restore"), []byte("data"), 0o600))

	cleanupOrphanedInDir(dir)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 4, "non-attack files should not be removed")
}

func TestCleanupOrphanedInDir_SkipsRestoreFiles(t *testing.T) {
	dir := t.TempDir()

	// Create attack-* files including .restore (should NOT be removed)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "attack-1.log"), []byte("log"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "attack-1.pid"), []byte("123"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "attack-1.restore"), []byte("data"), 0o600))

	cleanupOrphanedInDir(dir)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only .restore file should remain")
	require.Equal(t, "attack-1.restore", entries[0].Name())
}

func TestCleanupOrphanedInDir_SkipsSymlinks(t *testing.T) {
	if runtime.GOOS == windowsOS {
		t.Skip("os.Symlink requires elevated privileges on Windows")
	}

	dir := t.TempDir()

	// Create a real file and a symlink matching the pattern
	targetFile := filepath.Join(dir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("important"), 0o600))
	require.NoError(t, os.Symlink(targetFile, filepath.Join(dir, "attack-evil.log")))

	// Also create a regular attack file that should be removed
	require.NoError(t, os.WriteFile(filepath.Join(dir, "attack-1.log"), []byte("log"), 0o600))

	cleanupOrphanedInDir(dir)

	// Symlink should still exist
	_, err := os.Lstat(filepath.Join(dir, "attack-evil.log"))
	require.NoError(t, err, "symlink should not be removed")

	// Target file should still exist
	_, err = os.Stat(targetFile)
	require.NoError(t, err, "target file should not be affected")

	// Regular attack file should be removed
	_, err = os.Stat(filepath.Join(dir, "attack-1.log"))
	require.True(t, os.IsNotExist(err), "regular attack file should be removed")
}

func TestCleanupOrphanedInDir_HandlesEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	// Should not panic or error
	cleanupOrphanedInDir(dir)
}

func TestCleanupOrphanedInDir_HandlesMissingDirectory(t *testing.T) {
	// Should not panic or error
	cleanupOrphanedInDir(filepath.Join(t.TempDir(), "nonexistent"))
}

func TestCleanupOrphanedInDir_MixedFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a mix of files
	attackFiles := []string{"attack-1.log", "attack-2.pid", "attack-99.log"}
	keepFiles := []string{"benchmark.log", "hashcat.pid", "attack-1.restore", "notes.txt"}

	for _, f := range attackFiles {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("data"), 0o600))
	}
	for _, f := range keepFiles {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("data"), 0o600))
	}

	cleanupOrphanedInDir(dir)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, len(keepFiles), "only non-attack files should remain")

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	for _, f := range keepFiles {
		require.Contains(t, names, f, "kept file %s should still exist", f)
	}
}

func TestCleanupOrphanedInDir_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()

	// Create a directory matching the pattern (should not be removed)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "attack-subdir.log"), 0o750))

	cleanupOrphanedInDir(dir)

	_, err := os.Stat(filepath.Join(dir, "attack-subdir.log"))
	require.NoError(t, err, "directory matching pattern should not be removed")
}
