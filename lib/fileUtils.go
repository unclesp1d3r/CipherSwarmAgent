package lib

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	url2 "net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/cryptor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/duke-git/lancet/v2/validator"
	"github.com/hashicorp/go-getter"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/utils"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

const emptyVersion = "0.0.0"

// findHashcatBinary searches for the Hashcat binary at several predefined locations and returns its path if found.
// It checks directories specified by configuration, default locations, and the system's PATH environment variable.
// The function returns an error if the binary is not found or not executable.
func findHashcatBinary() (string, error) {
	var foundPath = ""
	possiblePaths := []string{
		viper.GetString("hashcat_path"),
		path.Join(shared.State.CrackersPath, "hashcat", arch.GetDefaultHashcatBinaryName()),
		path.Join(filepath.Dir(fileutil.CurrentPath()), arch.GetDefaultHashcatBinaryName()),
		path.Join(shared.State.CrackersPath, "hashcat", "hashcat"),
		path.Join(filepath.Dir(fileutil.CurrentPath()), "hashcat"),
		"/usr/bin/hashcat",
		"/usr/local/bin/hashcat",
	}

	for _, filePath := range possiblePaths {
		if fileutil.IsExist(filePath) && isExecAny(filePath) {
			foundPath = filePath
			return foundPath, nil
		}
	}

	// Didn't find it on the predefined locations. Checking the user's `$PATH` for the default name on this architecture.
	if hashcatPath, err := exec.LookPath(arch.GetDefaultHashcatBinaryName()); err == nil {
		foundPath = hashcatPath
	}

	// Last try we'll check for the default name of just hashcat within the user's filePath.
	if hashcatPath, err := exec.LookPath("hashcat"); err == nil {
		foundPath = hashcatPath
	}

	if strutil.IsNotBlank(foundPath) && fileutil.IsExist(foundPath) && isExecAny(foundPath) {
		return foundPath, nil
	}

	return "", errors.New("hashcat binary not found")
}

// isExecAny checks if the file at the given filePath has any executable permissions (user, group, or others).
func isExecAny(filePath string) bool {
	info, _ := os.Stat(filePath)
	mode := info.Mode()
	return mode&0111 != 0
}

// getCurrentHashcatVersion attempts to find the Hashcat binary and retrieve its version.
// It first searches for the Hashcat binary using findHashcatBinary. If found,
// it calls arch.GetHashcatVersion with the binary's path. If any step fails,
// it returns an empty version string and an error.
func getCurrentHashcatVersion() (string, error) {
	hashcatPath, err := findHashcatBinary()
	if err != nil {
		return emptyVersion, err
	}

	version, err := arch.GetHashcatVersion(hashcatPath)
	if err != nil {
		return emptyVersion, err
	}

	return version, nil
}

// removeExistingFile removes the file specified by filePath if it exists, logging and reporting an error if removal fails.
// Parameters:
// - filePath: The path to the file that needs to be removed.
// Returns an error if file removal fails, otherwise returns nil.
func removeExistingFile(filePath string) error {
	if fileutil.IsExist(filePath) {
		if err := os.Remove(filePath); err != nil {
			return logAndSendError("Error removing old hashlist", err, operations.SeverityCritical, nil)
		}
	}

	return nil
}

// writeResponseToFile writes the data from an io.Reader (responseStream) to a file specified by the filePath.
// Creates a new file at the given path, writes the response stream to it, and handles errors accordingly.
func writeResponseToFile(responseStream io.Reader, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return logAndSendError("Error creating hashlist file", err, operations.SeverityCritical, nil)
	}
	defer func(f *os.File) {
		if err := f.Close(); err != nil {
			shared.Logger.Error("Error closing hashlist file", "error", err)
		}
	}(file)

	if _, err := io.Copy(file, responseStream); err != nil {
		return logAndSendError("Error writing hashlist file", err, operations.SeverityCritical, nil)
	}

	return nil
}

// appendChecksumToURL appends the given checksum as a query parameter to the provided URL and returns the updated URL.
// If there is an error parsing the URL, it logs the error and returns an empty string and the error.
func appendChecksumToURL(url string, checksum string) (string, error) {
	urlA, err := url2.Parse(url)
	if err != nil {
		shared.Logger.Error("Error parsing URL", "error", err)

		return "", err
	}
	values := urlA.Query()
	values.Add("checksum", checksum)
	urlA.RawQuery = values.Encode()

	return urlA.String(), nil
}

// extractHashcatArchive extracts a new Hashcat archive, backing up and removing any old versions.
// - Removes the previous backup directory if existent.
// - Renames the current Hashcat directory for backup.
// - Extracts the new Hashcat archive to the specified directory.
// Returns the path to the new Hashcat directory and any error encountered.
func extractHashcatArchive(newArchivePath string) (string, error) {
	hashcatDirectory := path.Join(shared.State.CrackersPath, "hashcat")
	hashcatBackupDirectory := hashcatDirectory + "_old"
	// Get rid of the old hashcat backup directory
	err := os.RemoveAll(hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		shared.Logger.Error("Error removing old hashcat directory: ", "error", err)
		SendAgentError(err.Error(), nil, operations.SeverityCritical)

		return "", err // Don't continue if we can't remove the old directory
	}

	// Move the old hashcat directory to a backup location
	err = os.Rename(hashcatDirectory, hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		shared.Logger.Error("Error moving old hashcat directory: ", "error", err)
		SendAgentError(err.Error(), nil, operations.SeverityCritical)

		return "", err // Don't continue if we can't move the old directory
	}

	// Extract the new hashcat directory using the 7z command
	err = arch.Extract7z(newArchivePath, shared.State.CrackersPath)
	if err != nil {
		shared.Logger.Error("Error extracting file: ", "error", err)
		SendAgentError(err.Error(), nil, operations.SeverityCritical)

		return "", err // Don't continue if we can't extract the file
	}

	return hashcatDirectory, err
}

// moveArchiveFile moves a temporary archive file to the designated CrackersPath directory and logs the operation.
// Parameters:
// - tempArchivePath: The path to the temporary archive file that needs to be moved.
// Returns the new path of the moved archive and any error encountered during the move operation.
func moveArchiveFile(tempArchivePath string) (string, error) {
	newArchivePath := path.Join(shared.State.CrackersPath, "hashcat.7z")
	err := os.Rename(tempArchivePath, newArchivePath)
	if err != nil {
		shared.Logger.Error("Error moving file: ", err)

		return "", err
	}
	shared.Logger.Debug("Moved file", "old_path", tempArchivePath, "new_path", newArchivePath)

	return newArchivePath, err
}

// base64ToHex converts a Base64-encoded string to its hexadecimal representation.
// Returns an empty string if the input Base64 string is blank.
// Decodes the Base64 string and encodes it as a hexadecimal string.
func base64ToHex(base64 string) string {
	if strutil.IsBlank(base64) {
		return ""
	}
	str := cryptor.Base64StdDecode(base64)
	hx := hex.EncodeToString([]byte(str))

	return hx
}

// resourceNameOrBlank returns the FileName from the given AttackResourceFile or an empty string if the resource is nil.
func resourceNameOrBlank(resource *components.AttackResourceFile) string {
	if resource == nil {
		return ""
	}

	return resource.FileName
}

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

// downloadHashList downloads the hash list for a given attack.
// It constructs the local path for the hash list file and attempts to remove any existing file at that location.
// The function makes an API call to fetch the hash list, checks the response status, and handles errors if the call fails.
// If the response stream is not nil, it writes the hash list to the file and verifies the file's validity.
// Logs relevant actions and errors encountered during the process and returns any errors that occur.
func downloadHashList(attack *components.Attack) error {
	if attack == nil {
		return logAndSendError("Attack is nil", nil, operations.SeverityCritical, nil)
	}

	hashlistPath := path.Join(shared.State.HashlistPath, convertor.ToString(attack.GetHashListID())+".txt")
	shared.Logger.Debug("Downloading hashlist", "url", attack.GetHashListURL(), "path", hashlistPath)

	if err := removeExistingFile(hashlistPath); err != nil {
		return err
	}

	response, err := SdkClient.Attacks.GetHashList(Context, attack.ID)
	if err != nil {
		return logAndSendError("Error downloading hashlist from the CipherSwarm API", nil, operations.SeverityCritical, nil)
	}

	if response.StatusCode != http.StatusOK {
		return logAndSendError("Error downloading hashlist", errors.New(response.RawResponse.Status), operations.SeverityCritical, nil)
	}

	if response.ResponseStream == nil {
		return logAndSendError("Response stream is nil", nil, operations.SeverityCritical, nil)
	}

	if err := writeResponseToFile(response.ResponseStream, hashlistPath); err != nil {
		return err
	}

	if !fileExistsAndValid(hashlistPath, "") {
		return logAndSendError("Downloaded hashlist is invalid or empty", nil, operations.SeverityCritical, nil)
	}

	shared.Logger.Debug("Downloaded hashlist", "path", hashlistPath)

	return nil
}

// downloadResourceFile downloads a resource file if the provided resource is not nil.
// Constructs the file path based on the resource file name and logs the download action.
// If checksum verification is not always skipped, converts the base64 checksum to hex.
// Downloads the file using the resource's download URL, target file path, and checksum for verification.
// Logs and sends an error report if file download fails or if the downloaded file is empty.
func downloadResourceFile(resource *components.AttackResourceFile) error {
	if resource == nil {
		return nil
	}

	filePath := path.Join(shared.State.FilePath, resource.FileName)
	shared.Logger.Debug("Downloading resource file", "url", resource.GetDownloadURL(), "path", filePath)

	checksum := ""
	if !shared.State.AlwaysTrustFiles {
		checksum = base64ToHex(resource.GetChecksum())
	} else {
		shared.Logger.Debug("Skipping checksum verification")
	}

	if err := downloadFile(resource.GetDownloadURL(), filePath, checksum); err != nil {
		return logAndSendError("Error downloading attack resource", err, operations.SeverityCritical, nil)
	}

	if downloadSize, _ := fileutil.FileSize(filePath); downloadSize == 0 {
		return logAndSendError("Downloaded file is empty", nil, operations.SeverityCritical, nil)
	}

	shared.Logger.Debug("Downloaded resource file", "path", filePath)

	return nil
}
