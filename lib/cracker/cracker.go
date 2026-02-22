// Package cracker provides hashcat binary management and process control utilities.
// It handles binary discovery, version checking, process lifecycle management,
// and archive extraction for distributed agent environments.
package cracker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
)

// ErrHashcatBinaryNotFound indicates the hashcat binary could not be located.
var ErrHashcatBinaryNotFound = errors.New("hashcat binary not found")

const emptyVersion = "0.0.0"

// FindHashcatBinary searches for the hashcat binary in multiple locations.
// It checks configuration paths, installation directories, and the system PATH.
// Returns the path to the first executable binary found, or an error if none exist.
func FindHashcatBinary() (string, error) {
	foundPath := ""

	possiblePaths := []string{
		viper.GetString("hashcat_path"),
		filepath.Join(agentstate.State.CrackersPath, "hashcat", arch.GetDefaultHashcatBinaryName()),
		filepath.Join(filepath.Dir(os.Args[0]), arch.GetDefaultHashcatBinaryName()),
		filepath.Join(agentstate.State.CrackersPath, "hashcat", "hashcat"),
		filepath.Join(filepath.Dir(os.Args[0]), "hashcat"),
		"/usr/bin/hashcat",
		"/usr/local/bin/hashcat",
	}

	for _, filePath := range possiblePaths {
		info, err := os.Stat(filePath) //nolint:gosec // G703 - paths from hardcoded list and internal config
		if err == nil && info.Mode()&0o111 != 0 {
			foundPath = filePath
			return foundPath, nil
		}
	}

	// Check system PATH for architecture-specific binary name
	if hashcatPath, err := exec.LookPath(arch.GetDefaultHashcatBinaryName()); err == nil {
		foundPath = hashcatPath
	}

	// Final fallback: check system PATH for generic "hashcat"
	if hashcatPath, err := exec.LookPath("hashcat"); err == nil {
		foundPath = hashcatPath
	}

	info, err := os.Stat(foundPath)
	if err == nil && info.Mode()&0o111 != 0 {
		return foundPath, nil
	}

	return "", ErrHashcatBinaryNotFound
}

// GetCurrentHashcatVersion retrieves the version string of the installed hashcat binary.
// It first locates the binary, then queries it for version information.
// Returns an empty version string if the binary cannot be found or queried.
func GetCurrentHashcatVersion(ctx context.Context) (string, error) {
	hashcatPath, err := FindHashcatBinary()
	if err != nil {
		return emptyVersion, err
	}

	version, err := arch.GetHashcatVersion(ctx, hashcatPath)
	if err != nil {
		return emptyVersion, err
	}

	return version, nil
}

// CheckForExistingClient checks if a hashcat process is already running.
// It reads the PID file and verifies if the process is still active.
// Returns true if a running process is found or if errors occur during checks.
func CheckForExistingClient(pidFilePath string) bool {
	if _, err := os.Stat(pidFilePath); err == nil {
		pidBytes, err := os.ReadFile(pidFilePath)
		if err != nil {
			agentstate.Logger.Error("Error reading PID file", "path", pidFilePath)

			return true
		}

		pidValue, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		if err != nil {
			agentstate.Logger.Error("Error converting PID to integer", "pid", string(pidBytes))

			return true
		}

		pidRunning, err := process.PidExistsWithContext(
			context.Background(),
			int32(pidValue), //nolint:gosec // G115 - PID from file
		)
		if err != nil {
			agentstate.Logger.Error("Error checking if process is running", "pid", pidValue)

			return true
		}

		agentstate.Logger.Warn("Existing lock file found", "path", pidFilePath, "pid", pidValue)

		if !pidRunning {
			agentstate.Logger.Warn("Existing process is not running, cleaning up file", "pid", pidValue)
		}

		return pidRunning
	}

	return false
}

// CreateLockFile creates a lock file containing the current process ID.
// This is used to prevent multiple hashcat instances from running simultaneously.
// Returns an error if the file cannot be written.
func CreateLockFile() error {
	lockFilePath := agentstate.State.PidFile

	pidValue := os.Getpid()
	pidString := strconv.Itoa(pidValue)

	//nolint:gosec // G306 - lock file, not sensitive
	err := os.WriteFile(lockFilePath, []byte(pidString), 0o644)
	if err != nil {
		agentstate.Logger.Error("Error writing PID to file", "path", lockFilePath)

		return err
	}

	return nil
}

// CreateDataDirs creates all required data directories for the agent.
// It ensures each configured directory path exists, creating it if necessary.
// Returns an error if any directory creation fails.
func CreateDataDirs() error {
	dataDirs := []string{
		agentstate.State.FilePath,
		agentstate.State.CrackersPath,
		agentstate.State.HashlistPath,
		agentstate.State.ZapsPath,
		agentstate.State.PreprocessorsPath,
		agentstate.State.ToolsPath,
		agentstate.State.OutPath,
		agentstate.State.RestoreFilePath,
	}

	for _, dir := range dataDirs {
		if strings.TrimSpace(dir) == "" {
			agentstate.Logger.Error("Data directory not set")

			continue
		}

		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				agentstate.Logger.Error("Error creating directory", "path", dir, "error", err)

				return err
			}

			agentstate.Logger.Info("Created directory", "path", dir)
		}
	}

	return nil
}

// ExtractHashcatArchive extracts a new hashcat archive with backup management.
// It removes any previous backup, backs up the current installation, and extracts
// the new archive. Returns the path to the newly extracted hashcat directory.
func ExtractHashcatArchive(ctx context.Context, newArchivePath string) (string, error) {
	hashcatDirectory := filepath.Join(agentstate.State.CrackersPath, "hashcat")
	hashcatBackupDirectory := hashcatDirectory + "_old"

	// Remove old backup directory if it exists
	err := os.RemoveAll(hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		agentstate.Logger.Error("Error removing old hashcat directory", "error", err)

		return "", err
	}

	// Back up current hashcat installation
	err = os.Rename(hashcatDirectory, hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		agentstate.Logger.Error("Error moving old hashcat directory", "error", err)

		return "", err
	}

	// Extract new hashcat archive
	err = arch.Extract7z(ctx, newArchivePath, agentstate.State.CrackersPath)
	if err != nil {
		agentstate.Logger.Error("Error extracting file", "error", err)

		return "", err
	}

	return hashcatDirectory, err
}

// MoveArchiveFile moves a temporary archive file to its final location.
// It relocates the archive to the crackers path with a standard name.
// Returns the new path or an error if the move fails.
func MoveArchiveFile(tempArchivePath string) (string, error) {
	newArchivePath := filepath.Join(agentstate.State.CrackersPath, "hashcat.7z")

	err := os.Rename(tempArchivePath, newArchivePath)
	if err != nil {
		agentstate.Logger.Error("Error moving file", "error", err)

		return "", err
	}

	agentstate.Logger.Debug("Moved file", "old_path", tempArchivePath, "new_path", newArchivePath)

	return newArchivePath, err
}
