package lib

import (
	"context"
	"errors"
	"fmt"
	"github.com/duke-git/lancet/v2/cryptor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/duke-git/lancet/v2/validator"
	"github.com/hashicorp/go-getter"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/utils"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
	"os"
	"path"
)

// downloadFile downloads a file from a given URL and saves it to the specified path with optional checksum verification.
// If the URL is invalid, it returns an error. If the file already exists and the checksum matches, the download is skipped.
func downloadFile(url string, path string, checksum string) error {
	if !validator.IsUrl(url) {
		shared.Logger.Error("Invalid URL", "url", url)

		return errors.New("invalid URL")
	}

	if fileExistsAndValid(path, checksum) {
		shared.Logger.Info("Download already exists", "path", path)

		return nil
	}

	displayDownloadFile(url, path)
	if err := downloadAndVerifyFile(url, path, checksum); err != nil {
		return err
	}
	displayDownloadFileComplete(url, path)

	return nil
}

// fileExistsAndValid checks if a file exists at the given path and, if a checksum is provided, verifies its validity.
// The function returns true if the file exists and matches the given checksum, or if no checksum is provided.
// If the file does not exist or the checksum verification fails, appropriate error messages are logged.
func fileExistsAndValid(path string, checksum string) bool {
	if !fileutil.IsExist(path) {
		return false
	}

	if strutil.IsBlank(checksum) {
		return true
	}

	fileChecksum, err := cryptor.Md5File(path)
	if err != nil {
		shared.Logger.Error("Error calculating file checksum", "path", path, "error", err)

		return false
	}

	if fileChecksum == checksum {
		return true
	}

	shared.Logger.Warn("Checksums do not match", "path", path, "url_checksum", checksum, "file_checksum", fileChecksum)
	SendAgentError("Resource "+path+" exists, but checksums do not match", nil, operations.SeverityInfo)
	if err := os.Remove(path); err != nil {
		SendAgentError(err.Error(), nil, operations.SeverityMajor)
		shared.Logger.Error("Error removing file with mismatched checksum", "path", path, "error", err)
	}

	return false
}

// downloadAndVerifyFile downloads a file from the given URL and saves it to the specified path, verifying the checksum if provided.
// If a checksum is given, it is appended to the URL before download. The function then configures a client for secure file transfer.
// The file is downloaded using the configured client. After downloading, the file's checksum is verified, if provided, to ensure integrity.
// If the checksum does not match, an error is returned, indicating the downloaded file is corrupt.
func downloadAndVerifyFile(url string, path string, checksum string) error {
	if strutil.IsNotBlank(checksum) {
		var err error
		url, err = appendChecksumToURL(url, checksum)
		if err != nil {
			return err
		}
	}

	client := &getter.Client{
		Ctx:      context.Background(),
		Dst:      path,
		Src:      url,
		Pwd:      shared.State.CrackersPath,
		Insecure: true,
		Mode:     getter.ClientModeFile,
	}

	_ = client.Configure(
		getter.WithProgress(utils.DefaultProgressBar),
		getter.WithUmask(os.FileMode(0o022)),
	)

	if err := client.Get(); err != nil {
		shared.Logger.Debug("Error downloading file", "error", err)

		return err
	}

	if strutil.IsNotBlank(checksum) && !fileExistsAndValid(path, checksum) {
		return errors.New("downloaded file checksum does not match")
	}

	return nil
}

// cleanupTempDir removes the specified temporary directory and logs any errors encountered. Returns the error if removal fails.
func cleanupTempDir(tempDir string) error {
	if err := os.RemoveAll(tempDir); err != nil {
		return logAndSendError("Error removing temporary directory", err, operations.SeverityCritical, nil)
	}

	return nil
}

// writeCrackedHashToFile writes a cracked hash and its plaintext to a specified file.
// It constructs the output string using the hash and plaintext, then writes it to a task-specific file in the ZapsPath.
// Returns an error if the file writing operation fails.
func writeCrackedHashToFile(hash hashcat.Result, task *components.Task) error {
	hashOut := fmt.Sprintf("%s:%s\n", hash.Hash, hash.Plaintext)
	hashFile := path.Join(shared.State.ZapsPath, fmt.Sprintf("%d_clientout.zap", task.GetID()))
	err := fileutil.WriteStringToFile(hashFile, hashOut, true)
	if err != nil {
		return logAndSendError("Error writing cracked hash to file", err, operations.SeverityCritical, task)
	}

	return nil
}
