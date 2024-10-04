package lib

import (
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
	"net/http"
	"path"
)

// setNativeHashcatPath sets the path for the native Hashcat binary if it is found in the system, otherwise logs and reports error.
func setNativeHashcatPath() error {
	shared.Logger.Debug("Using native Hashcat")
	binPath, err := findHashcatBinary()
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
	currentVersion, err := getCurrentHashcatVersion()
	if err != nil {
		shared.Logger.Error("Error getting current hashcat version", "error", err)

		return
	}

	response, err := SdkClient.Crackers.CheckForCrackerUpdate(Context, &agentPlatform, &currentVersion)
	if err != nil {
		handleAPIError("Error connecting to the CipherSwarm API", err, operations.SeverityCritical)

		return
	}

	if response.StatusCode == http.StatusNoContent {
		shared.Logger.Debug("No new cracker available")

		return
	}

	if response.StatusCode == http.StatusOK {
		update := response.GetCrackerUpdate()
		if update.GetAvailable() {
			_ = handleCrackerUpdate(update)
		} else {
			shared.Logger.Debug("No new cracker available", "latest_version", update.GetLatestVersion())
		}
	} else {
		shared.Logger.Error("Error checking for updated cracker", "CrackerUpdate", response.RawResponse.Status)
	}
}

// validateHashcatDirectory checks if the given hashcat directory exists and contains the specified executable.
func validateHashcatDirectory(hashcatDirectory, execName string) bool {
	if !fileutil.IsDir(hashcatDirectory) {
		shared.Logger.Error("New hashcat directory does not exist", "path", hashcatDirectory)

		return false
	}

	hashcatBinaryPath := path.Join(hashcatDirectory, execName)
	if !fileutil.IsExist(hashcatBinaryPath) {
		shared.Logger.Error("New hashcat binary does not exist", "path", hashcatBinaryPath)

		return false
	}

	return true
}
