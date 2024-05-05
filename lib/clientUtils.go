package lib

import (
	"errors"
	"path"

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
			shared.SharedState.CrackersPath,
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

// GetPlatform returns the platform of the current system.
func GetPlatform() string {
	return arch.GetPlatform()
}

// CheckForExistingClient checks if the specified PID file exists.
// It returns true if the file exists, and false otherwise.
func CheckForExistingClient(pidFilePath string) bool {
	return fileutil.IsExist(pidFilePath)

}

// CreateLockFile creates a lock file at the specified path using the configured PID file path.
// It returns the created file and any error encountered during the process.
func CreateLockFile() error {
	lockFilePath := shared.SharedState.PidFile

	isCreated := fileutil.CreateFile(lockFilePath)
	if !isCreated {
		return errors.New("failed to create lock file")
	}
	return nil
}

// CreateDataDirs creates the necessary data directories for the CipherSwarmAgent.
// It checks if the directories already exist, and if not, it creates them.
// Returns an error if there was a problem creating the directories.
func CreateDataDirs() error {
	dataDirs := []string{
		shared.SharedState.FilePath,
		shared.SharedState.CrackersPath,
		shared.SharedState.HashlistPath,
		shared.SharedState.ZapsPath,
		shared.SharedState.PreprocessorsPath,
		shared.SharedState.ToolsPath,
		shared.SharedState.OutPath,
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
