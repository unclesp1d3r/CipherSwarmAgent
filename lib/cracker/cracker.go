// Package cracker provides hashcat binary management and process control utilities.
// It handles binary discovery, version checking, process lifecycle management,
// and archive extraction for distributed agent environments.
package cracker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/state"
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
		path.Join(state.State.CrackersPath, "hashcat", arch.GetDefaultHashcatBinaryName()),
		path.Join(filepath.Dir(os.Args[0]), arch.GetDefaultHashcatBinaryName()),
		path.Join(state.State.CrackersPath, "hashcat", "hashcat"),
		path.Join(filepath.Dir(os.Args[0]), "hashcat"),
		"/usr/bin/hashcat",
		"/usr/local/bin/hashcat",
	}

	for _, filePath := range possiblePaths {
		info, err := os.Stat(filePath)
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
	if fileutil.IsExist(pidFilePath) {
		pidString, err := fileutil.ReadFileToString(pidFilePath)
		if err != nil {
			state.Logger.Error("Error reading PID file", "path", pidFilePath)

			return true
		}

		pidValue, err := convertor.ToInt(strutil.Trim(pidString))
		if err != nil {
			state.Logger.Error("Error converting PID to integer", "pid", pidString)

			return true
		}

		pidRunning, err := process.PidExists(int32(pidValue)) //nolint:gosec // PID conversion from file is safe
		if err != nil {
			state.Logger.Error("Error checking if process is running", "pid", pidValue)

			return true
		}

		state.Logger.Warn("Existing lock file found", "path", pidFilePath, "pid", pidValue)

		if !pidRunning {
			state.Logger.Warn("Existing process is not running, cleaning up file", "pid", pidValue)
		}

		return pidRunning
	}

	return false
}

// CreateLockFile creates a lock file containing the current process ID.
// This is used to prevent multiple hashcat instances from running simultaneously.
// Returns an error if the file cannot be written.
func CreateLockFile() error {
	lockFilePath := state.State.PidFile

	pidValue := os.Getpid()
	pidString := convertor.ToString(pidValue)

	err := fileutil.WriteStringToFile(lockFilePath, pidString, false)
	if err != nil {
		state.Logger.Error("Error writing PID to file", "path", lockFilePath)

		return err
	}

	return nil
}

// CreateDataDirs creates all required data directories for the agent.
// It ensures each configured directory path exists, creating it if necessary.
// Returns an error if any directory creation fails.
func CreateDataDirs() error {
	dataDirs := []string{
		state.State.FilePath,
		state.State.CrackersPath,
		state.State.HashlistPath,
		state.State.ZapsPath,
		state.State.PreprocessorsPath,
		state.State.ToolsPath,
		state.State.OutPath,
		state.State.RestoreFilePath,
	}

	for _, dir := range dataDirs {
		if strutil.IsBlank(dir) {
			state.Logger.Error("Data directory not set")

			continue
		}

		if !fileutil.IsDir(dir) {
			if err := fileutil.CreateDir(dir); err != nil {
				state.Logger.Error("Error creating directory", "path", dir, "error", err)

				return err
			}

			state.Logger.Info("Created directory", "path", dir)
		}
	}

	return nil
}

// ExtractHashcatArchive extracts a new hashcat archive with backup management.
// It removes any previous backup, backs up the current installation, and extracts
// the new archive. Returns the path to the newly extracted hashcat directory.
func ExtractHashcatArchive(ctx context.Context, newArchivePath string) (string, error) {
	hashcatDirectory := path.Join(state.State.CrackersPath, "hashcat")
	hashcatBackupDirectory := hashcatDirectory + "_old"

	// Remove old backup directory if it exists
	err := os.RemoveAll(hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		state.Logger.Error("Error removing old hashcat directory", "error", err)

		return "", err
	}

	// Back up current hashcat installation
	err = os.Rename(hashcatDirectory, hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		state.Logger.Error("Error moving old hashcat directory", "error", err)

		return "", err
	}

	// Extract new hashcat archive
	err = arch.Extract7z(ctx, newArchivePath, state.State.CrackersPath)
	if err != nil {
		state.Logger.Error("Error extracting file", "error", err)

		return "", err
	}

	return hashcatDirectory, err
}

// MoveArchiveFile moves a temporary archive file to its final location.
// It relocates the archive to the crackers path with a standard name.
// Returns the new path or an error if the move fails.
func MoveArchiveFile(tempArchivePath string) (string, error) {
	newArchivePath := path.Join(state.State.CrackersPath, "hashcat.7z")

	err := os.Rename(tempArchivePath, newArchivePath)
	if err != nil {
		state.Logger.Error("Error moving file", err)

		return "", err
	}

	state.Logger.Debug("Moved file", "old_path", tempArchivePath, "new_path", newArchivePath)

	return newArchivePath, err
}
