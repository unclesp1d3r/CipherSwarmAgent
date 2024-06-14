package lib

import (
	"errors"
	"os"
	"path"

	"github.com/duke-git/lancet/convertor"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/duke-git/lancet/fileutil"
	"github.com/unclesp1d3r/cipherswarmagent/shared"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
)

// GetCurrentHashcatVersion retrieves the current version of Hashcat.
// It checks if the Hashcat directory exists and then uses the arch.GetHashcatVersion
// function to get the version from the specified path.
// If the Hashcat directory does not exist, it returns "0.0.0" and an error.
// If there is an error retrieving the version, it also returns "0.0.0" and the error.
// Otherwise, it returns the Hashcat version and no error.
func GetCurrentHashcatVersion() (string, error) {
	// Check where the hashcat binary should be
	hashcatExists := fileutil.IsExist(viper.GetString("hashcat_path"))
	if !hashcatExists {
		shared.Logger.Error("Cannot find hashcat binary, checking fallback location.", "path", viper.GetString("hashcat_path"))

		// Check if the hashcat binary exists in the crackers directory
		fallbackPath := path.Join(
			shared.State.CrackersPath,
			"hashcat",
			arch.GetDefaultHashcatBinaryName(),
		)
		if fileutil.IsExist(fallbackPath) {
			shared.Logger.Debug("Using hashcat binary from crackers directory", "path", fallbackPath)
			viper.Set("hashcat_path", fallbackPath)
		} else {
			shared.Logger.Error("Hashcat binary does not exist", "path", fallbackPath)
		}
	}
	if !hashcatExists {
		shared.Logger.Error("Hashcat binary does not exist", "path", viper.GetString("hashcat_path"))
		return "0.0.0", errors.New("hashcat binary does not exist")
	}

	// Found the hashcat binary, get the version
	hashcatVersion, err := arch.GetHashcatVersion(viper.GetString("hashcat_path"))
	if err != nil {
		return "0.0.0", err
	}
	shared.Logger.Debug("Current hashcat version", "version", hashcatVersion)
	return hashcatVersion, nil
}

// CheckForExistingClient checks if there is an existing client running by checking the PID file.
// It reads the PID file and checks if the process with the specified PID is running.
// If the PID file does not exist, it returns false.
// If the PID file exists and the process is running, it returns true.
// If the PID file exists and the process is not running, it returns false.
// If there is an error reading the PID file or checking if the process is running, it returns true.
func CheckForExistingClient(pidFilePath string) bool {
	if fileutil.IsExist(pidFilePath) {
		pidString, err := fileutil.ReadFileToString(pidFilePath)
		if err != nil {
			shared.Logger.Error("Error reading PID file", "path", pidFilePath)
			return true
		}

		pidValue, err := convertor.ToInt(strutil.Trim(pidString))
		if err != nil {
			shared.Logger.Error("Error converting PID to integer", "pid", pidString)
			return true
		}

		pidRunning, err := process.PidExists(int32(pidValue))
		if err != nil {
			shared.Logger.Error("Error checking if process is running", "pid", pidValue)
			return true
		}

		shared.Logger.Warn("Existing lock file found", "path", pidFilePath, "pid", pidValue)
		if !pidRunning {
			shared.Logger.Warn("Existing process is not running, cleaning up file", "pid", pidValue)
		}
		return pidRunning
	} else {
		return false
	}
}

// CreateLockFile creates a lock file at the specified path using the configured PID file path.
// It returns the created file and any error encountered during the process.
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

// CreateDataDirs creates the necessary data directories for the CipherSwarmAgent.
// It checks if the directories already exist, and if not, it creates them.
// Returns an error if there was a problem creating the directories.
func CreateDataDirs() error {
	dataDirs := []string{
		shared.State.FilePath,
		shared.State.CrackersPath,
		shared.State.HashlistPath,
		shared.State.ZapsPath,
		shared.State.PreprocessorsPath,
		shared.State.ToolsPath,
		shared.State.OutPath,
	}
	for _, dir := range dataDirs {
		if dir == "" {
			shared.Logger.Error("Data directory not set")
		}

		if !fileutil.IsDir(dir) {
			err := fileutil.CreateDir(dir)
			if err != nil {
				return err
			}
			shared.Logger.Info("Created directory", "path", dir)
		}
	}
	return nil
}
