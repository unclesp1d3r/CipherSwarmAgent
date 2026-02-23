package task

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/downloader"
)

// DownloadFiles downloads the necessary files for the provided attack.
// It performs the following steps:
// 1. Logs the start of the download process.
// 2. Downloads the hash list associated with the attack.
// 3. Iterates over resource files (word list, rule list, and mask list) and downloads each one.
// If any step encounters an error, the function returns that error.
func DownloadFiles(ctx context.Context, attack *api.Attack) error {
	display.DownloadFileStart(attack)

	if err := downloader.DownloadHashList(ctx, attack); err != nil {
		return err
	}

	resourceFiles := []*api.AttackResourceFile{
		attack.WordList,
		attack.RuleList,
		attack.MaskList,
	}

	for _, resource := range resourceFiles {
		if err := downloadResourceFile(ctx, resource); err != nil {
			return err
		}
	}

	return nil
}

// downloadResourceFile downloads a resource file if the provided resource is not nil.
// Constructs the file path based on the resource file name and logs the download action.
// If checksum verification is not always skipped, converts the checksum bytes to hex.
// Downloads the file using the resource's download URL, target file path, and checksum for verification.
// Logs and sends an error report if file download fails or if the downloaded file is empty.
func downloadResourceFile(ctx context.Context, resource *api.AttackResourceFile) error {
	if resource == nil {
		return nil
	}

	filePath := filepath.Join(agentstate.State.FilePath, resource.FileName)
	agentstate.Logger.Debug("Downloading resource file", "url", resource.DownloadUrl, "path", filePath)

	checksum := ""
	if !agentstate.State.AlwaysTrustFiles {
		checksum = hex.EncodeToString(resource.Checksum)
	} else {
		agentstate.Logger.Debug("Skipping checksum verification")
	}

	if err := downloader.DownloadFile(ctx, resource.DownloadUrl, filePath, checksum); err != nil {
		return cserrors.LogAndSendError(ctx, "Error downloading attack resource", err, api.SeverityCritical, nil)
	}

	fileInfo, statErr := os.Stat(filePath)
	if statErr != nil {
		return cserrors.LogAndSendError(ctx, "Error checking downloaded file", statErr, api.SeverityCritical, nil)
	}

	if fileInfo.Size() == 0 {
		return cserrors.LogAndSendError(
			ctx,
			"Downloaded file is empty: "+filePath,
			fmt.Errorf("file %s has zero bytes", filePath),
			api.SeverityCritical,
			nil,
		)
	}

	agentstate.Logger.Debug("Downloaded resource file", "path", filePath)

	return nil
}
