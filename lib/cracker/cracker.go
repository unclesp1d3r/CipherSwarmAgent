// Package cracker provides hashcat binary management and execution utilities.
package cracker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// ErrHashcatBinaryNotFound is returned when the hashcat binary cannot be located.
var ErrHashcatBinaryNotFound = errors.New("hashcat binary not found")

const emptyVersion = "0.0.0"

// FindHashcatBinary searches for the Hashcat binary at several predefined locations and returns its path if found.
// It checks directories specified by configuration, default locations, and the system's PATH environment variable.
// The function returns an error if the binary is not found or not executable.
func FindHashcatBinary() (string, error) {
	foundPath := ""

	possiblePaths := []string{
		viper.GetString("hashcat_path"),
		path.Join(shared.State.CrackersPath, "hashcat", arch.GetDefaultHashcatBinaryName()),
		path.Join(filepath.Dir(os.Args[0]), arch.GetDefaultHashcatBinaryName()),
		path.Join(shared.State.CrackersPath, "hashcat", "hashcat"),
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

	// Didn't find it on the predefined locations. Checking the user's `$PATH` for the default name on this architecture.
	if hashcatPath, err := exec.LookPath(arch.GetDefaultHashcatBinaryName()); err == nil {
		foundPath = hashcatPath
	}

	// Last try we'll check for the default name of just hashcat within the user's filePath.
	if hashcatPath, err := exec.LookPath("hashcat"); err == nil {
		foundPath = hashcatPath
	}

	info, err := os.Stat(foundPath)
	if err == nil && info.Mode()&0o111 != 0 {
		return foundPath, nil
	}

	return "", ErrHashcatBinaryNotFound
}

// GetCurrentHashcatVersion attempts to find the Hashcat binary and retrieve its version.
// It first searches for the Hashcat binary using FindHashcatBinary. If found,
// it calls arch.GetHashcatVersion with the binary's path. If any step fails,
// it returns an empty version string and an error.
func GetCurrentHashcatVersion() (string, error) {
	hashcatPath, err := FindHashcatBinary()
	if err != nil {
		return emptyVersion, err
	}

	version, err := arch.GetHashcatVersion(context.Background(), hashcatPath)
	if err != nil {
		return emptyVersion, err
	}

	return version, nil
}

// CheckForExistingClient checks if a client process is already running by examining a PID file at the specified path.
// Returns true if the process is found or errors occur, otherwise false.
func CheckForExistingClient(pidFilePath string) bool {
	if fileutil.IsExist(pidFilePath) {
		pidString, err := fileutil.ReadFileToString(pidFilePath)
		if err != nil {
			shared.Logger.Error("Error reading PID file", "path", pidFilePath)

			return true
		}

		// Use strconv.ParseInt to safely convert the PID string to an int32
		pidInt64, err := strconv.ParseInt(strutil.Trim(pidString), 10, 32)
		if err != nil {
			shared.Logger.Error(
				"Error converting PID to integer, or PID is too large for int32",
				"pid",
				pidString,
				"error",
				err,
			)
			return true
		}
		pidValue := int32(pidInt64)

		pidRunning, err := process.PidExists(pidValue)
		if err != nil {
			shared.Logger.Error("Error checking if process is running", "pid", pidValue)

			return true
		}

		shared.Logger.Warn("Existing lock file found", "path", pidFilePath, "pid", pidValue)

		if !pidRunning {
			shared.Logger.Warn("Existing process is not running, cleaning up file", "pid", pidValue)
		}

		return pidRunning
	}

	return false
}

// CreateLockFile creates a lock file with the current process PID.
// Writes the PID to the designated lock file in the shared state.
// Logs an error and returns it if writing fails.
func CreateLockFile() error {
	lockFilePath := shared.State.PidFile

	pidValue := os.Getpid()
	pidString := convertor.ToString(pidValue)

	err := fileutil.WriteStringToFile(lockFilePath, pidString, false)
	if err != nil {
		shared.Logger.Error("Error writing PID to file", "path", lockFilePath)

		return err
	}

	return nil
}

// CreateDataDirs creates required directories based on the paths set in shared.State. It checks for each path's existence,
// ensures it's not blank, and creates the directory if it doesn't exist, logging any errors that occur. Returns an error
// if any directory creation fails.
func CreateDataDirs() error {
	dataDirs := []string{
		shared.State.FilePath,
		shared.State.CrackersPath,
		shared.State.HashlistPath,
		shared.State.ZapsPath,
		shared.State.PreprocessorsPath,
		shared.State.ToolsPath,
		shared.State.OutPath,
		shared.State.RestoreFilePath,
	}

	for _, dir := range dataDirs {
		if strutil.IsBlank(dir) {
			shared.Logger.Error("Data directory not set")

			continue
		}

		if !fileutil.IsDir(dir) {
			if err := fileutil.CreateDir(dir); err != nil {
				shared.Logger.Error("Error creating directory", "path", dir, "error", err)

				return err
			}

			shared.Logger.Info("Created directory", "path", dir)
		}
	}

	return nil
}

// ExtractHashcatArchive extracts a new Hashcat archive, backing up and removing any old versions.
// - Removes the previous backup directory if existent.
// - Renames the current Hashcat directory for backup.
// - Extracts the new Hashcat archive to the specified directory.
// Returns the path to the new Hashcat directory and any error encountered.
func ExtractHashcatArchive(newArchivePath string) (string, error) {
	hashcatDirectory := path.Join(shared.State.CrackersPath, "hashcat")
	hashcatBackupDirectory := hashcatDirectory + "_old"
	// Get rid of the old hashcat backup directory
	err := os.RemoveAll(hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		shared.Logger.Error("Error removing old hashcat directory: ", "error", err)

		return "", err // Don't continue if we can't remove the old directory
	}

	// Move the old hashcat directory to a backup location
	err = os.Rename(hashcatDirectory, hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		shared.Logger.Error("Error moving old hashcat directory: ", "error", err)

		return "", err // Don't continue if we can't move the old directory
	}

	// Extract the new hashcat directory using the 7z command
	err = arch.Extract7z(context.Background(), newArchivePath, shared.State.CrackersPath)
	if err != nil {
		shared.Logger.Error("Error extracting file: ", "error", err)

		return "", err // Don't continue if we can't extract the file
	}

	return hashcatDirectory, err
}

// MoveArchiveFile moves a temporary archive file to the designated CrackersPath directory and logs the operation.
// Parameters:
// - tempArchivePath: The path to the temporary archive file that needs to be moved.
// Returns the new path of the moved archive and any error encountered during the move operation.
func MoveArchiveFile(tempArchivePath string) (string, error) {
	newArchivePath := path.Join(shared.State.CrackersPath, "hashcat.7z")

	err := os.Rename(tempArchivePath, newArchivePath)
	if err != nil {
		shared.Logger.Error("Error moving file: ", err)

		return "", err
	}

	shared.Logger.Debug("Moved file", "old_path", tempArchivePath, "new_path", newArchivePath)

	return newArchivePath, err
}
