package arch

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateExecutablePath_AbsoluteFilePass(t *testing.T) {
	// Use the test binary itself as a known-good absolute executable path.
	self, err := os.Executable()
	require.NoError(t, err)

	err = ValidateExecutablePath(self)
	require.NoError(t, err)
}

func TestValidateExecutablePath_RelativePath(t *testing.T) {
	err := ValidateExecutablePath("relative/path/to/binary")
	require.ErrorIs(t, err, ErrRelativePath)
}

func TestValidateExecutablePath_NonExistent(t *testing.T) {
	// Use an absolute path that works on all platforms.
	// On Windows, /nonexistent is not absolute (needs drive letter).
	nonexistent := filepath.Join(t.TempDir(), "nonexistent", "binary")
	err := ValidateExecutablePath(nonexistent)
	require.ErrorIs(t, err, ErrPathNotFound)
}

func TestValidateExecutablePath_IsDirectory(t *testing.T) {
	dir := t.TempDir()
	err := ValidateExecutablePath(dir)
	require.ErrorIs(t, err, ErrPathIsDirectory)
}

func TestValidateArchivePaths_ValidPaths(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "test.7z")
	require.NoError(t, os.WriteFile(srcFile, []byte("fake archive"), 0o600))

	err := ValidateArchivePaths(srcFile, dir)
	require.NoError(t, err)
}

func TestValidateArchivePaths_SrcNotFound(t *testing.T) {
	dir := t.TempDir()
	nonexistent := filepath.Join(dir, "nonexistent", "archive.7z")
	err := ValidateArchivePaths(nonexistent, dir)
	require.ErrorIs(t, err, ErrPathNotFound)
}

func TestValidateArchivePaths_SrcIsDirectory(t *testing.T) {
	dir := t.TempDir()
	err := ValidateArchivePaths(dir, dir)
	require.ErrorIs(t, err, ErrPathIsDirectory)
}

func TestValidateArchivePaths_DstNotFound(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "test.7z")
	require.NoError(t, os.WriteFile(srcFile, []byte("fake archive"), 0o600))

	nonexistentDst := filepath.Join(dir, "nonexistent", "destination")
	err := ValidateArchivePaths(srcFile, nonexistentDst)
	require.ErrorIs(t, err, ErrPathNotFound)
}

func TestValidateArchivePaths_DstNotDirectory(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "test.7z")
	dstFile := filepath.Join(dir, "notadir.txt")
	require.NoError(t, os.WriteFile(srcFile, []byte("fake archive"), 0o600))
	require.NoError(t, os.WriteFile(dstFile, []byte("not a dir"), 0o600))

	err := ValidateArchivePaths(srcFile, dstFile)
	require.ErrorIs(t, err, ErrPathNotDirectory)
}

func TestValidateExecutablePath_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Symlink requires elevated privileges on Windows")
	}

	dir := t.TempDir()
	realBin := filepath.Join(dir, "real")
	//nolint:gosec // G306 - test needs executable permission to validate
	require.NoError(t, os.WriteFile(realBin, []byte("#!/bin/sh"), 0o755))

	linkPath := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(realBin, linkPath))

	// Symlinks to valid executables should pass
	err := ValidateExecutablePath(linkPath)
	require.NoError(t, err)
}
