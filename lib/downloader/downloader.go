// Package downloader provides file download functionality for CipherSwarm resources.
package downloader

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/duke-git/lancet/v2/cryptor"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/hashicorp/go-getter"
	"github.com/pkg/errors"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarmagent/lib/progress"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

const (
	defaultUmask = 0o022 // Default umask for file permissions
)

// DownloadFile downloads a file from a given URL and saves it to the specified path with optional checksum verification.
// If the URL is invalid, it returns an error. If the file already exists and the checksum matches, the download is skipped.
func DownloadFile(fileURL, filePath, checksum string) error {
	parsedURL, err := url.Parse(fileURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		shared.Logger.Error("Invalid URL", "url", fileURL)
		return errors.New("invalid URL")
	}

	if FileExistsAndValid(filePath, checksum) {
		shared.Logger.Info("Download already exists", "path", filePath)
		return nil
	}

	if err := downloadAndVerifyFile(fileURL, filePath, checksum); err != nil {
		return err
	}

	return nil
}

// FileExistsAndValid checks if a file exists at the given path and, if a checksum is provided, verifies its validity.
// The function returns true if the file exists and matches the given checksum, or if no checksum is provided.
// If the file does not exist or the checksum verification fails, appropriate error messages are logged.
func FileExistsAndValid(filePath, checksum string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}

	if strutil.IsBlank(checksum) {
		return true
	}

	fileChecksum, err := cryptor.Md5File(filePath)
	if err != nil {
		shared.Logger.Error("Error calculating file checksum", "path", filePath, "error", err)

		return false
	}

	if fileChecksum == checksum {
		return true
	}

	shared.Logger.Warn(
		"Checksums do not match",
		"path",
		filePath,
		"url_checksum",
		checksum,
		"file_checksum",
		fileChecksum,
	)

	if err := os.Remove(filePath); err != nil {
		shared.Logger.Error("Error removing file with mismatched checksum", "path", filePath, "error", err)
	}

	return false
}

// downloadAndVerifyFile downloads a file from the given URL and saves it to the specified path, verifying the checksum if provided.
// If a checksum is given, it is appended to the URL before download. The function then configures a client for secure file transfer.
// The file is downloaded using the configured client. After downloading, the file's checksum is verified, if provided, to ensure integrity.
// If the checksum does not match, an error is returned, indicating the downloaded file is corrupt.
func downloadAndVerifyFile(fileURL, filePath, checksum string) error {
	if strutil.IsNotBlank(checksum) {
		var err error

		fileURL, err = appendChecksumToURL(fileURL, checksum)
		if err != nil {
			return err
		}
	}

	client := &getter.Client{
		Ctx:      context.Background(),
		Dst:      filePath,
		Src:      fileURL,
		Pwd:      shared.State.CrackersPath,
		Insecure: true,
		Mode:     getter.ClientModeFile,
	}

	_ = client.Configure( //nolint:errcheck // Client configuration errors are not critical
		getter.WithProgress(progress.DefaultProgressBar),
		getter.WithUmask(os.FileMode(defaultUmask)),
	)

	if err := client.Get(); err != nil {
		shared.Logger.Debug("Error downloading file", "error", err)

		return err
	}

	if strutil.IsNotBlank(checksum) && !FileExistsAndValid(filePath, checksum) {
		return errors.New("downloaded file checksum does not match")
	}

	return nil
}

// appendChecksumToURL appends a checksum to the URL query string.
// It returns the modified URL or an error if the URL is invalid.
func appendChecksumToURL(rawURL, checksum string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("checksum", "md5:"+checksum)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// DownloadHashList downloads the hash list for a given attack.
// It constructs the local path for the hash list file and attempts to remove any existing file at that location.
// The function makes an API call to fetch the hash list, checks the response status, and handles errors if the call fails.
// If the response stream is not nil, it writes the hash list to the file and verifies the file's validity.
// Logs relevant actions and errors encountered during the process and returns any errors that occur.
func DownloadHashList(attack *components.Attack) error {
	if attack == nil {
		return errors.New("attack is nil")
	}

	hashlistPath := path.Join(shared.State.HashlistPath, fmt.Sprintf("%d.hsh", attack.GetID()))
	shared.Logger.Debug("Downloading hash list", "url", attack.GetHashListURL(), "path", hashlistPath)

	if err := removeExistingFile(hashlistPath); err != nil {
		return err
	}

	response, err := shared.State.SdkClient.Attacks.GetHashList(context.Background(), attack.ID)
	if err != nil {
		return errors.Wrap(err, "error downloading hashlist from the CipherSwarm API")
	}

	if response.StatusCode != http.StatusOK {
		return errors.Errorf("error downloading hashlist: %s", response.RawResponse.Status)
	}

	if response.ResponseStream == nil {
		return errors.New("response stream is nil")
	}

	if err := writeResponseToFile(response.ResponseStream, hashlistPath); err != nil {
		return err
	}

	if downloadSize, _ := os.Stat(hashlistPath); downloadSize.Size() == 0 { //nolint:errcheck // File size check, error not critical
		return errors.New("downloaded hash list is empty")
	}

	shared.Logger.Debug("Downloaded hash list", "path", hashlistPath)

	return nil
}

// Base64ToHex converts a base64 encoded string to a hexadecimal string.
// It returns an empty string if the input is invalid.
func Base64ToHex(b64 string) string {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		shared.Logger.Error("Error decoding base64 string", "error", err)

		return ""
	}

	return hex.EncodeToString(data)
}

// removeExistingFile removes the file specified by filePath if it exists, logging and reporting an error if removal fails.
// Parameters:
// - filePath: The path to the file that needs to be removed.
// Returns an error if file removal fails, otherwise returns nil.
func removeExistingFile(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if err := os.Remove(filePath); err != nil {
			return errors.Wrap(err, "error removing old file")
		}
	}

	return nil
}

// writeResponseToFile writes the data from an io.Reader (responseStream) to a file specified by the filePath.
// Creates a new file at the given path, writes the response stream to it, and handles errors accordingly.
func writeResponseToFile(responseStream io.Reader, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return errors.Wrap(err, "error creating file")
	}
	defer func(f *os.File) {
		if err := f.Close(); err != nil {
			shared.Logger.Error("Error closing file", "error", err)
		}
	}(file)

	if _, err := io.Copy(file, responseStream); err != nil {
		return errors.Wrap(err, "error writing file")
	}

	return nil
}

// CleanupTempDir removes the specified temporary directory and its contents.
// It logs any errors encountered during the removal process.
func CleanupTempDir(tempDir string) error {
	if err := os.RemoveAll(tempDir); err != nil {
		shared.Logger.Error("Error removing temporary directory", "path", tempDir, "error", err)
		return err
	}

	return nil
}
