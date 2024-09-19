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

// getCurrentHashcatVersion retrieves the current version of the Hashcat binary.
// It checks multiple locations for the Hashcat executable:
// 1. The path specified in the configuration.
// 2. The default crackers path with the expected binary name.
// 3. The system's $PATH environment variable.
// If found, it returns the Hashcat version and updates the configuration with the found path.
// If not found, it returns a default version "0.0.0" and an error indicating the binary does not exist.
func getCurrentHashcatVersion() (string, error) {
	hashcatPath := viper.GetString("hashcat_path")
	if version, err := tryCheckForHashcat(hashcatPath); err == nil {
		return version, nil
	}

	shared.Logger.Error("Didn't find hashcat binary in expected location", "path", hashcatPath)
	hashcatPath = path.Join(shared.State.CrackersPath, "hashcat", arch.GetDefaultHashcatBinaryName())
	if version, err := tryCheckForHashcat(hashcatPath); err == nil {
		shared.Logger.Debug("Using hashcat binary from crackers directory", "path", hashcatPath)
		viper.Set("hashcat_path", hashcatPath)

		return version, nil
	}

	shared.Logger.Error("Hashcat binary not found in crackers path",
		"bin_name", arch.GetDefaultHashcatBinaryName(),
		"path", hashcatPath)

	if hashcatPath, err := exec.LookPath("hashcat"); err == nil {
		shared.Logger.Debug("Using hashcat binary from $PATH", "path", hashcatPath)
		viper.Set("hashcat_path", hashcatPath)

		return fetchHashcatVersion(hashcatPath)
	}

	shared.Logger.Error("Hashcat binary does not exist", "path", hashcatPath)

	return "0.0.0", errors.New("hashcat binary does not exist")
}

// tryCheckForHashcat checks if the Hashcat binary exists at the given path.
// If it exists, it returns the Hashcat version using fetchHashcatVersion.
// If it does not exist, it returns an error indicating the binary was not found.
func tryCheckForHashcat(hashcatPath string) (string, error) {
	if fileutil.IsExist(hashcatPath) {
		return fetchHashcatVersion(hashcatPath)
	}

	return "", errors.New("hashcat binary not found")
}

// fetchHashcatVersion retrieves the current version of the Hashcat binary located at hashcatPath.
// It utilizes the arch.GetHashcatVersion method to fetch the version. If there is an error, it logs the error and returns "0.0.0".
// Parameters:
//   - hashcatPath: The file path to the Hashcat executable.
//
// Returns:
//   - A string representing the Hashcat version.
//   - An error if fetching the version fails.
func fetchHashcatVersion(hashcatPath string) (string, error) {
	hashcatVersion, err := arch.GetHashcatVersion(hashcatPath)
	if err != nil {
		shared.Logger.Error("Error getting hashcat version", "error", err)

		return "0.0.0", err
	}
	shared.Logger.Debug("Current hashcat version", "version", hashcatVersion)

	return hashcatVersion, nil
}

// CheckForExistingClient verifies if a process described by a PID file is already running.
// This function performs the following steps:
// 1. Check if the PID file exists; if not, return false.
// 2. Read the PID from the file and attempt to convert it to an integer.
// 3. Check if the process with the given PID is running and log relevant information.
// 4. Return true if the process is running, otherwise return false and clean up the PID file if necessary.
func CheckForExistingClient(pidFilePath string) bool {
	if fileutil.IsExist(pidFilePath) {
		pidString, err := fileutil.ReadFileToString(pidFilePath)
		if err != nil {
			shared.Logger.Error("Error reading PID file", "path", pidFilePath)

			return true
		}

		pidValue, err := convertor.ToInt(strutil.Trim(pidString))
		if err != nil {
			shared.Logger.Error("Error converting PID to integer", "pid", pidString)

			return true
		}

		pidRunning, err := process.PidExists(int32(pidValue)) //nolint:gosec
		if err != nil {
			shared.Logger.Error("Error checking if process is running", "pid", pidValue)

			return true
		}

		shared.Logger.Warn("Existing lock file found", "path", pidFilePath, "pid", pidValue)
		if !pidRunning {
			shared.Logger.Warn("Existing process is not running, cleaning up file", "pid", pidValue)
		}

		return pidRunning
	}

	return false
}

// CreateLockFile creates a lock file with the current process ID to prevent multiple instances from running simultaneously.
// It writes the PID to the file specified by shared.State.PidFile using fileutil.WriteStringToFile.
// If an error occurs while writing the PID to the file, it logs the error and returns it.
func CreateLockFile() error {
	lockFilePath := shared.State.PidFile

	pidValue := os.Getpid()
	pidString := convertor.ToString(pidValue)
	err := fileutil.WriteStringToFile(lockFilePath, pidString, false)
	if err != nil {
		shared.Logger.Error("Error writing PID to file", "path", lockFilePath)

		return err
	}

	return nil
}

// CreateDataDirs creates necessary data directories specified in shared.State.
// Iterates over a list of directory paths, checks for emptiness and existence,
// and creates directories if they are missing. Logs errors and successes.
func CreateDataDirs() error {
	dataDirs := []string{
		shared.State.FilePath,
		shared.State.CrackersPath,
		shared.State.HashlistPath,
		shared.State.ZapsPath,
		shared.State.PreprocessorsPath,
		shared.State.ToolsPath,
		shared.State.OutPath,
		shared.State.RestoreFilePath,
	}

	for _, dir := range dataDirs {
		if strutil.IsBlank(dir) {
			shared.Logger.Error("Data directory not set")

			continue
		}

		if !fileutil.IsDir(dir) {
			if err := fileutil.CreateDir(dir); err != nil {
				shared.Logger.Error("Error creating directory", "path", dir, "error", err)

				return err
			}
			shared.Logger.Info("Created directory", "path", dir)
		}
	}

	return nil
}

// downloadHashList downloads the hashlist for the given attack and saves it to the specified path.
// It removes any existing file at the target path before downloading.
// Logs relevant actions and errors during the procedure and validates the downloaded file.
// Returns an error if any step in the process encounters an issue, otherwise returns nil.
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

// removeExistingFile removes the file at the specified filePath if it exists.
// If the removal fails, it logs the error and sends a critical error to the server.
// Parameters:
// - filePath: The path to the file to remove.
// Returns an error if the file removal fails, otherwise returns nil.
func removeExistingFile(filePath string) error {
	if fileutil.IsExist(filePath) {
		if err := os.Remove(filePath); err != nil {
			return logAndSendError("Error removing old hashlist", err, operations.SeverityCritical, nil)
		}
	}

	return nil
}

// writeResponseToFile writes the contents of the responseStream to a file specified by filePath.
// It attempts to create the file at the given path, logging and returning a critical error if creation fails.
// The function ensures the file is properly closed after writing the response stream content.
// If an error occurs during writing, it logs and returns a critical error.
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

// downloadFile downloads a file from the provided URL to the specified path and verifies it using the given checksum.
// If the URL is invalid, it logs an error and returns an error.
// If the file already exists and passes checksum verification, it logs an info message and returns nil.
// Otherwise, it downloads the file, verifies the checksum, and logs either success or failure.
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

// fileExistsAndValid checks if a file exists at the given path and verifies it against the provided checksum.
//
// Parameters:
// - path: The file path to check existence.
// - checksum: The expected checksum to verify the file's validity.
//
// Returns:
// - bool: true if the file exists and is valid based on the provided checksum; false otherwise.
//
// Actions:
// - Checks if the file at the given path exists using fileutil.IsExist.
// - If the checksum is blank, returns true since existence is validated.
// - Calculates the file's MD5 checksum using cryptor.Md5File and compares it against the provided checksum.
// - Logs errors and warnings for checksum mismatches or other issues.
// - Removes the file if checksums do not match and logs the removal error if any.
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

// downloadAndVerifyFile downloads a file from the given URL and saves it to the specified path.
//
// Parameters:
// - url: The URL to download the file from.
// - path: The local file path to save the downloaded file.
// - checksum: The expected checksum to verify the integrity of the downloaded file.
//
// Actions:
// - If a checksum is provided, append it to the URL as a query parameter.
// - Configures and initializes the getter.Client for downloading the file.
// - Attempts to download the file to the specified path.
// - If a checksum is provided, verifies the downloaded file's integrity by comparing it with the given checksum.
// - Logs and returns an error if the file download fails or if checksum verification fails.
//
// Returns:
// - An error if the download or checksum verification fails, otherwise returns nil.
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

// appendChecksumToURL appends a checksum query parameter to a given URL and returns the modified URL string.
//
// Parameters:
// - url: The base URL to which the checksum will be appended.
// - checksum: The checksum value to append as a query parameter.
//
// Returns:
// - A string representing the modified URL with the checksum appended as a query parameter.
// - An error if the base URL is malformed or cannot be parsed.
//
// Actions:
// - Parses the provided URL string.
// - Adds the "checksum" query parameter to the parsed URL.
// - Encodes the modified URL and returns it as a string.
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

// extractHashcatArchive extracts a Hashcat archive to the designated CrackersPath.
// It performs the following steps:
// 1. Removes any existing backup of the old Hashcat directory.
// 2. Renames the current Hashcat directory to create a backup.
// 3. Extracts the new Hashcat directory from the provided archive using the `7z` command.
// Returns the path to the new Hashcat directory or an error if any step fails.
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

// moveArchiveFile moves a temporary archive file to a predefined path within the CrackersPath.
// It performs the following steps:
// 1. Constructs the new archive path using the shared state for CrackersPath.
// 2. Renames (moves) the temporary archive file to the new archive path.
// 3. Logs an error if the rename operation fails and returns the error.
// 4. Logs a debug message indicating the move was successful and returns the new archive path without error.
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

// base64ToHex converts a base64 encoded string to its hexadecimal representation.
// Returns an empty string if the input is blank.
// It decodes the base64 string, converts the result to bytes, and then encodes those bytes as a hex string.
func base64ToHex(base64 string) string {
	if strutil.IsBlank(base64) {
		return ""
	}
	str := cryptor.Base64StdDecode(base64)
	hx := hex.EncodeToString([]byte(str))

	return hx
}

// resourceNameOrBlank returns the file name from an AttackResourceFile if it exists, otherwise it returns an empty string.
// If the resource is nil, it returns an empty string. If the resource is non-nil, it returns the FileName of the resource.
func resourceNameOrBlank(resource *components.AttackResourceFile) string {
	if resource == nil {
		return ""
	}

	return resource.FileName
}
