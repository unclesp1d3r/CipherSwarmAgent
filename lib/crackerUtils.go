package lib

import (
	"context"
	"net/http"
	"os"
	"path"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
)

// setNativeHashcatPath sets the path for the native Hashcat binary if it is found in the system, otherwise logs and reports error.
func setNativeHashcatPath() error {
	agentstate.Logger.Debug("Using native Hashcat")

	binPath, err := cracker.FindHashcatBinary()
	if err != nil {
		agentstate.Logger.Error("Error finding hashcat binary: ", err)
		SendAgentError(err.Error(), nil, api.SeverityCritical)

		return err
	}

	agentstate.Logger.Info("Found Hashcat binary", "path", binPath)
	viper.Set("hashcat_path", binPath)

	if err := viper.WriteConfig(); err != nil {
		agentstate.Logger.Warn("Failed to persist hashcat path to config; path will be lost on restart",
			"error", err, "hashcat_path", binPath)
	}

	return nil
}

// UpdateCracker checks for updates to the cracker and applies them if available.
// It starts by logging the beginning of the update process and attempts to fetch the current version of Hashcat.
// It then calls the API to check if there are any updates available. Depending on the API response, it either handles
// the update process or logs the absence of any new updates. If any errors occur during these steps, they are logged and handled accordingly.
func UpdateCracker() {
	agentstate.Logger.Info("Checking for updated cracker")

	currentVersion, err := cracker.GetCurrentHashcatVersion(context.Background())
	if err != nil {
		agentstate.Logger.Error("Error getting current hashcat version", "error", err)

		return
	}

	response, err := agentstate.State.APIClient.Crackers().CheckForCrackerUpdate(
		context.Background(),
		&agentPlatform,
		&currentVersion,
	)
	if err != nil {
		handleAPIError("Error connecting to the CipherSwarm API", err)

		return
	}

	if response.StatusCode == http.StatusNoContent {
		agentstate.Logger.Debug("No new cracker available")

		return
	}

	if response.StatusCode == http.StatusOK {
		update := response.GetCrackerUpdate()
		if update == nil {
			agentstate.Logger.Warn("Cracker update response was 200 OK but contained no update data")

			return
		}
		if update.GetAvailable() {
			if err := handleCrackerUpdate(update); err != nil {
				agentstate.Logger.Error("Failed to apply cracker update", "error", err)
			}
		} else {
			agentstate.Logger.Debug("No new cracker available", "latest_version", update.GetLatestVersion())
		}
	} else {
		agentstate.Logger.Error("Error checking for updated cracker", "CrackerUpdate", response.Status())
	}
}

// validateHashcatDirectory checks if the given hashcat directory exists and contains the specified executable.
func validateHashcatDirectory(hashcatDirectory, execName string) bool {
	if fileInfo, err := os.Stat(hashcatDirectory); err != nil || !fileInfo.IsDir() {
		agentstate.Logger.Error("New hashcat directory does not exist", "path", hashcatDirectory)

		return false
	}

	hashcatBinaryPath := path.Join(hashcatDirectory, execName)

	fileInfo, err := os.Stat(hashcatBinaryPath)
	if err != nil || fileInfo.Mode()&0o111 == 0 {
		agentstate.Logger.Error("New hashcat binary does not exist or is not executable", "path", hashcatBinaryPath)

		return false
	}

	return true
}
