package lib

import (
	"context"
	stderrors "errors"
	"net/http"
	"os"
	"path"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/downloader"
)

// setNativeHashcatPath sets the path for the native Hashcat binary if it is found in the system, otherwise logs and reports error.
func setNativeHashcatPath() error {
	agentstate.Logger.Debug("Using native Hashcat")

	binPath, err := cracker.FindHashcatBinary()
	if err != nil {
		agentstate.Logger.Error("Error finding hashcat binary: ", err)
		cserrors.SendAgentError(err.Error(), nil, api.SeverityCritical)

		return err
	}

	agentstate.Logger.Info("Found Hashcat binary", "path", binPath)
	agentstate.State.HashcatPath = binPath
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
func UpdateCracker(ctx context.Context) {
	agentstate.Logger.Info("Checking for updated cracker")

	currentVersion, err := cracker.GetCurrentHashcatVersion(ctx)
	if err != nil {
		agentstate.Logger.Error("Error getting current hashcat version", "error", err)

		return
	}

	response, err := agentstate.State.APIClient.Crackers().CheckForCrackerUpdate(
		ctx,
		&agentstate.State.Platform,
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
			if err := handleCrackerUpdate(ctx, update); err != nil {
				agentstate.Logger.Error("Failed to apply cracker update", "error", err)
			}
		} else {
			agentstate.Logger.Debug("No new cracker available", "latest_version", update.GetLatestVersion())
		}
	} else {
		agentstate.Logger.Error("Error checking for updated cracker", "CrackerUpdate", response.Status())
	}
}

// handleCrackerUpdate manages the process of updating the cracker tool.
// It follows these steps:
// 0. Validates that download URL and exec name are present.
// 1. Logs the new cracker update information.
// 2. Creates a temporary directory for download and extraction.
// 3. Downloads the cracker archive from the provided URL.
// 4. Moves the downloaded archive to a predefined location.
// 5. Extracts the archive to replace the old cracker directory.
// 6. Validates the new cracker directory and executable.
// 7. Updates the configuration with the new executable path.
// Returns an error if any step in the process fails.
func handleCrackerUpdate(ctx context.Context, update *api.CrackerUpdate) error {
	if update.GetDownloadURL() == nil || update.GetExecName() == nil {
		//nolint:contextcheck // LogAndSendError can't accept ctx (circular dependency)
		return cserrors.LogAndSendError(
			"Cracker update missing download URL or exec name",
			stderrors.New("incomplete cracker update response"),
			api.SeverityCritical,
			nil,
		)
	}

	display.NewCrackerAvailable(update)

	tempDir, err := os.MkdirTemp("", "cipherswarm-*")
	if err != nil {
		//nolint:contextcheck // LogAndSendError can't accept ctx (circular dependency)
		return cserrors.LogAndSendError(
			"Error creating temporary directory",
			err,
			api.SeverityCritical,
			nil,
		)
	}
	defer func(tempDir string) {
		_ = downloader.CleanupTempDir(tempDir) //nolint:errcheck // Cleanup in defer, error not critical
	}(tempDir)

	tempArchivePath := path.Join(tempDir, "hashcat.7z")
	if err := downloader.DownloadFile(ctx, *update.GetDownloadURL(), tempArchivePath, ""); err != nil {
		//nolint:contextcheck // LogAndSendError can't accept ctx (circular dependency)
		return cserrors.LogAndSendError(
			"Error downloading cracker",
			err,
			api.SeverityCritical,
			nil,
		)
	}

	newArchivePath, err := cracker.MoveArchiveFile(tempArchivePath)
	if err != nil {
		//nolint:contextcheck // LogAndSendError can't accept ctx (circular dependency)
		return cserrors.LogAndSendError("Error moving file", err, api.SeverityCritical, nil)
	}

	hashcatDirectory, err := cracker.ExtractHashcatArchive(ctx, newArchivePath)
	if err != nil {
		//nolint:contextcheck // LogAndSendError can't accept ctx (circular dependency)
		return cserrors.LogAndSendError("Error extracting file", err, api.SeverityCritical, nil)
	}

	if !validateHashcatDirectory(hashcatDirectory, *update.GetExecName()) {
		//nolint:contextcheck // LogAndSendError can't accept ctx (circular dependency)
		return cserrors.LogAndSendError(
			"Hashcat directory validation failed after extraction",
			stderrors.New("hashcat binary validation failed"),
			api.SeverityCritical,
			nil,
		)
	}

	if err := os.Remove(newArchivePath); err != nil {
		//nolint:errcheck,contextcheck // Error already being handled; LogAndSendError can't accept ctx
		_ = cserrors.LogAndSendError(
			"Error removing 7z file",
			err,
			api.SeverityWarning,
			nil,
		)
	}

	agentstate.State.HashcatPath = path.Join(agentstate.State.CrackersPath, "hashcat", *update.GetExecName())
	viper.Set("hashcat_path", agentstate.State.HashcatPath)
	if err := viper.WriteConfig(); err != nil {
		agentstate.Logger.Warn("Failed to persist hashcat path to config; update will be lost on restart",
			"error", err, "hashcat_path", agentstate.State.HashcatPath)
	}

	return nil
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
