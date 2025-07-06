package lib

import (
	"context"
	"os"
	"path"

	"net/http"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// setNativeHashcatPath sets the path for the native Hashcat binary if it is found in the system, otherwise logs and reports error.
func setNativeHashcatPath() error {
	shared.Logger.Debug("Using native Hashcat")

	binPath, err := cracker.FindHashcatBinary()
	if err != nil {
		shared.Logger.Error("Error finding hashcat binary: ", err)
		SendAgentError(err.Error(), nil, operations.SeverityCritical)

		return err
	}

	shared.Logger.Info("Found Hashcat binary", "path", binPath)
	viper.Set("hashcat_path", binPath)

	return viper.WriteConfig()
}

// UpdateCracker checks for updates to the cracker and applies them if available.
// It starts by logging the beginning of the update process and attempts to fetch the current version of Hashcat.
// It then calls the API to check if there are any updates available. Depending on the API response, it either handles
// the update process or logs the absence of any new updates. If any errors occur during these steps, they are logged and handled accordingly.
func UpdateCracker() {
	shared.Logger.Info("Checking for updated cracker")

	currentVersion, err := cracker.GetCurrentHashcatVersion()
	if err != nil {
		shared.Logger.Error("Error getting current hashcat version", "error", err)

		return
	}

	response, err := shared.State.SdkClient.Crackers.CheckForCrackerUpdate(context.Background(), &agentPlatform, &currentVersion)
	if err != nil {
		handleAPIError("Error connecting to the CipherSwarm API", err)

		return
	}

	if response.StatusCode == http.StatusNoContent {
		shared.Logger.Debug("No new cracker available")

		return
	}

	if response.StatusCode == http.StatusOK {
		update := response.GetCrackerUpdate()
		if update.GetAvailable() {
			_ = handleCrackerUpdate(update) //nolint:errcheck // Error already logged in function
		} else {
			shared.Logger.Debug("No new cracker available", "latest_version", update.GetLatestVersion())
		}
	} else {
		shared.Logger.Error("Error checking for updated cracker", "CrackerUpdate", response.RawResponse.Status)
	}
}

// validateHashcatDirectory checks if the given hashcat directory exists and contains the specified executable.
func validateHashcatDirectory(hashcatDirectory, execName string) bool {
	if fileInfo, err := os.Stat(hashcatDirectory); err != nil || !fileInfo.IsDir() {
		shared.Logger.Error("New hashcat directory does not exist", "path", hashcatDirectory)

		return false
	}

	hashcatBinaryPath := path.Join(hashcatDirectory, execName)

	fileInfo, err := os.Stat(hashcatBinaryPath)
	if err != nil || fileInfo.Mode()&0o111 == 0 {
		shared.Logger.Error("New hashcat binary does not exist or is not executable", "path", hashcatBinaryPath)

		return false
	}

	return true
}
