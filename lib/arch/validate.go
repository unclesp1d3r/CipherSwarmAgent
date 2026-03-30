// Package arch provides architecture-specific functionality.
// This file contains cross-platform path validation for exec.CommandContext calls.
package arch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	// ErrRelativePath indicates a path is not absolute.
	ErrRelativePath = errors.New("path must be absolute")
	// ErrPathNotFound indicates a path does not exist on disk.
	ErrPathNotFound = errors.New("path does not exist")
	// ErrPathIsDirectory indicates a path points to a directory, not a file.
	ErrPathIsDirectory = errors.New("path is a directory, expected a file")
	// ErrPathNotDirectory indicates a path does not point to a directory.
	ErrPathNotDirectory = errors.New("path is not a directory")
)

// ValidateExecutablePath checks that a binary path is absolute, exists, and is not a directory.
// This is a defense-in-depth check before passing paths to exec.CommandContext.
func ValidateExecutablePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %s", ErrRelativePath, path)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrPathNotFound, path)
	}

	if info.IsDir() {
		return fmt.Errorf("%w: %s", ErrPathIsDirectory, path)
	}

	return nil
}

// ValidateArchivePaths checks that srcFile exists and is a regular file,
// and that destDir exists and is a directory.
func ValidateArchivePaths(srcFile, destDir string) error {
	srcInfo, err := os.Stat(srcFile)
	if err != nil {
		return fmt.Errorf("archive %w: %s", ErrPathNotFound, srcFile)
	}

	if srcInfo.IsDir() {
		return fmt.Errorf("archive %w: %s", ErrPathIsDirectory, srcFile)
	}

	destInfo, err := os.Stat(destDir)
	if err != nil {
		return fmt.Errorf("destination %w: %s", ErrPathNotFound, destDir)
	}

	if !destInfo.IsDir() {
		return fmt.Errorf("destination %w: %s", ErrPathNotDirectory, destDir)
	}

	return nil
}
