package lib

import (
	"errors"
	"os"
	"strconv"
	"syscall"

	"github.com/charmbracelet/log"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
)

var AppFs = afero.NewOsFs()
var Logger = log.NewWithOptions(os.Stderr, log.Options{
	Prefix:          "cipherswarm-agent",
	Level:           log.InfoLevel,
	ReportTimestamp: true,
	ReportCaller:    true,
})

// UpdateClientConfig updates the client configuration settings.
// It sets the API version and advanced configuration settings based on the values in the Configuration struct.
// It then writes the updated configuration to the config file using viper.WriteConfig().
// If there is an error while writing the config file, it logs the error.
func UpdateClientConfig() {
	// These settings are mostly just placeholders for now
	viper.Set("api_version", Configuration.ApiVersion)
	viper.Set("advanced_config", Configuration.Config)
	err := viper.WriteConfig()
	if err != nil {
		log.Error("Error writing config file: ", err)
	}
}

// GetCurrentHashcatVersion retrieves the current version of Hashcat.
// It checks if the Hashcat directory exists and then uses the arch.GetHashcatVersion
// function to get the version from the specified path.
// If the Hashcat directory does not exist, it returns "0.0.0" and an error.
// If there is an error retrieving the version, it also returns "0.0.0" and the error.
// Otherwise, it returns the Hashcat version and no error.
func GetCurrentHashcatVersion() (string, error) {
	afs := &afero.Afero{Fs: AppFs}
	hashcatDirExists, _ := afs.DirExists(viper.GetString("hashcat_path"))
	if !hashcatDirExists {
		return "0.0.0", errors.New("hashcat directory does not exist")
	}
	hashcatVersion, err := arch.GetHashcatVersion(viper.GetString("hashcat_path"))
	if err != nil {
		return "0.0.0", err
	}
	return hashcatVersion, nil
}

// GetPlatform returns the platform of the current system.
func GetPlatform() string {
	return arch.GetPlatform()
}

// CleanUpDanglingProcess checks for dangling processes and performs cleanup if necessary.
// It takes a `pidFilePath` string parameter which specifies the path to the PID file.
// The `killIfFound` boolean parameter determines whether to kill the process if it is found.
// It returns a boolean value indicating whether the cleanup was performed successfully,
// and an error if any occurred during the cleanup process.
func CleanUpDanglingProcess(pidFilePath string, killIfFound bool) (bool, error) {
	logger.Info("Checking for dangling processes")
	pidExists, err := afero.Exists(AppFs, pidFilePath)
	if err != nil {
		return false, err
	}

	if pidExists {
		pidData, err := os.ReadFile(pidFilePath)
		if err != nil {
			return false, err
		}
		log.Debug("Read pid file", "pidData", pidData)

		pid := int(pidData[0])

		// Check if the process is running
		process, err := os.FindProcess(pid)
		if err != nil {
			// This error should never happen, but if it does, we should log it
			return false, err
		}

		err = process.Signal(syscall.Signal(0))
		if err != nil {
			log.Debug("Process is not running")
			err := os.Remove(pidFilePath)
			if err != nil {
				return false, err
			}
			// Process is not running, remove the pid file and return
		} else {
			log.Debug("Process is running")
			// Kill the process
			err = process.Kill()
			if err != nil {
				if err.Error() == "os: process already finished" {
					return false, err
				} else {
					return true, err
				}
			}
			return true, err
		}

		// Remove the pid file
		err = os.Remove(pidFilePath)
		if err != nil {
			return true, err
		}

		return true, err
	}
	return false, nil
}

// CreateLockFile creates a lock file at the specified path using the configured PID file path.
// It returns the created file and any error encountered during the process.
func CreateLockFile() (afero.File, error) {
	lockFilePath := viper.GetString("pid_file")
	currentPid := os.Getpid()

	pidFile, err := AppFs.Create(lockFilePath)

	if err != nil {
		logger.Fatal("Failed to create PID file", "error", lockFilePath)
	}
	defer func(pidFile afero.File) {
		err := pidFile.Close()
		if err != nil {
			logger.Fatal("Failed to close PID file", "error", err)
		}
	}(pidFile)
	_, err = pidFile.WriteString(strconv.Itoa(currentPid))
	logger.Debug("PID file created", "path", lockFilePath, "pid", currentPid)
	return pidFile, err
}
