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

// getCurrentHashcatVersion attempts to determine the current version of the Hashcat binary.
// It first checks the path specified in the configuration. If not found, it checks the default
// crackers directory. If still not found, it looks for the binary in the system's $PATH.
// If the binary is found in any of these locations, it returns the version as a string.
// If the binary is not found, it logs appropriate error messages and returns "0.0.0" along with an error.
//
// Returns:
//   - string: The version of the Hashcat binary if found, otherwise "0.0.0".
//   - error: An error if the Hashcat binary is not found, otherwise nil.
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

func tryCheckForHashcat(hashcatPath string) (string, error) {
	if fileutil.IsExist(hashcatPath) {
		return fetchHashcatVersion(hashcatPath)
	}

	return "", errors.New("hashcat binary not found")
}

func fetchHashcatVersion(hashcatPath string) (string, error) {
	hashcatVersion, err := arch.GetHashcatVersion(hashcatPath)
	if err != nil {
		shared.Logger.Error("Error getting hashcat version", "error", err)

		return "0.0.0", err
	}
	shared.Logger.Debug("Current hashcat version", "version", hashcatVersion)

	return hashcatVersion, nil
}

// CheckForExistingClient checks if there is an existing client running by checking the PID file.
// It reads the PID file and checks if the process with the specified PID is running.
// If the PID file does not exist, it returns false.
// If the PID file exists and the process is running, it returns true.
// If the PID file exists and the process is not running, it returns false.
// If there is an error reading the PID file or checking if the process is running, it returns true.
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

// CreateLockFile creates a lock file at the specified path using the configured PID file path.
// It returns the created file and any error encountered during the process.
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

// CreateDataDirs creates a set of predefined directories if they do not already exist.
// It retrieves the directory paths from the shared.State configuration and iterates over them.
// For each directory path, it checks if the path is blank or if it already exists as a directory.
// If the path is blank, it logs an error and continues to the next path.
// If the directory does not exist, it attempts to create it and logs the result.
// If an error occurs during the creation of any directory, it logs the error and returns it.
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

// downloadHashList downloads a hash list for a given attack and saves it to a file.
//
// Parameters:
//   - attack: A pointer to an Attack object containing details of the attack.
//
// Returns:
//   - error: An error object if an error occurs, otherwise nil.
//
// The function performs the following steps:
//  1. Checks if the attack object is nil and logs a critical error if it is.
//  2. Constructs the file path for the hash list using the attack's hash list ID.
//  3. Logs the URL and path for the hash list download.
//  4. Removes any existing file at the hash list path.
//  5. Downloads the hash list from the CipherSwarm API using the attack ID.
//  6. Checks the response status code and logs a critical error if it is not OK.
//  7. Checks if the response stream is nil and logs a critical error if it is.
//  8. Writes the response stream to the file at the hash list path.
//  9. Validates the downloaded hash list file.
//  10. Logs the successful download of the hash list.
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
// If the file cannot be removed, it logs the error and sends an error message with critical severity.
//
// Parameters:
//   - filePath: The path to the file that needs to be removed.
//
// Returns:
//   - error: An error if the file removal fails, otherwise nil.
func removeExistingFile(filePath string) error {
	if fileutil.IsExist(filePath) {
		if err := os.Remove(filePath); err != nil {
			return logAndSendError("Error removing old hashlist", err, operations.SeverityCritical, nil)
		}
	}

	return nil
}

// writeResponseToFile writes the contents of the provided io.Reader (responseStream)
// to a file specified by filePath. If the file does not exist, it will be created.
// If an error occurs during file creation or writing, it logs the error and returns it.
//
// Parameters:
//   - responseStream (io.Reader): The input stream containing the data to be written to the file.
//   - filePath (string): The path where the file will be created or overwritten.
//
// Returns:
//   - error: An error object if an error occurs during file creation or writing, otherwise nil.
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

// downloadFile downloads a file from the specified URL to the given path.
// It validates the URL, checks if the file already exists, and verifies the checksum if provided.
// If the file exists and the checksum matches, it skips the download. If the checksums do not match,
// it removes the existing file and proceeds with the download.
//
// Parameters:
//   - url: The URL of the file to download.
//   - path: The local file path where the downloaded file will be saved.
//   - checksum: The expected MD5 checksum of the file. If provided, it will be used to verify the file integrity.
//
// Returns:
//   - error: An error object if any error occurs during the process, otherwise nil.
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

// fileExistsAndValid checks if a file exists at the given path and optionally verifies its checksum.
// If the file does not exist, it returns false.
// If the checksum is blank, it returns true if the file exists.
// If the checksum is provided, it calculates the file's MD5 checksum and compares it with the provided checksum.
// If the checksums match, it returns true.
// If the checksums do not match, it logs a warning, sends an agent error, attempts to remove the file, and returns false.
//
// Parameters:
//   - path: The file path to check.
//   - checksum: The expected MD5 checksum of the file.
//
// Returns:
//   - bool: True if the file exists and the checksum (if provided) matches, otherwise false.
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

// downloadAndVerifyFile downloads a file from the specified URL to the given path and verifies it using the provided checksum.
// If the checksum is not blank, it appends the checksum to the URL before downloading.
//
// Parameters:
//   - url: The URL of the file to download.
//   - path: The local file path where the downloaded file will be saved.
//   - checksum: The checksum to verify the downloaded file.
//
// Returns:
//   - error: An error if the download or verification fails, otherwise nil.
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

// appendChecksumToURL appends a checksum query parameter to the given URL.
//
// Parameters:
//   - url: The base URL to which the checksum will be appended.
//   - checksum: The checksum value to append as a query parameter.
//
// Returns:
//   - A string representing the new URL with the checksum appended.
//   - An error if the URL parsing fails.
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

// extractHashcatArchive extracts a Hashcat archive to a specified directory.
// It performs the following steps:
// 1. Removes any existing backup of the Hashcat directory.
// 2. Moves the current Hashcat directory to a backup location.
// 3. Extracts the new Hashcat archive using the 7z command.
//
// Parameters:
// - newArchivePath: The file path to the new Hashcat archive.
//
// Returns:
// - A string representing the path to the extracted Hashcat directory.
// - An error if any step in the process fails.
//
// The function logs errors and sends agent error notifications if it encounters issues
// during the removal, renaming, or extraction processes.
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

// moveArchiveFile moves a file from a temporary archive path to a new location
// within the CrackersPath directory. The new file is named "hashcat.7z".
// It returns the new file path or an error if the operation fails.
//
// Parameters:
//   - tempArchivePath: The path to the temporary archive file.
//
// Returns:
//   - string: The new path of the moved archive file.
//   - error: An error if the file move operation fails.
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

// base64ToHex converts a Base64 encoded string to its hexadecimal representation.
// It first decodes the Base64 string and then encodes the resulting bytes to a hex string.
// If the input Base64 string is blank, it returns an empty string.
//
// Parameters:
// - base64: A string containing the Base64 encoded data.
//
// Returns:
// - A string containing the hexadecimal representation of the decoded Base64 data.
func base64ToHex(base64 string) string {
	if strutil.IsBlank(base64) {
		return ""
	}
	str := cryptor.Base64StdDecode(base64)
	hx := hex.EncodeToString([]byte(str))

	return hx
}

// resourceNameOrBlank returns the file name of the given AttackResourceFile.
// If the resource is nil, it returns an empty string.
//
// Parameters:
//   - resource: A pointer to an AttackResourceFile.
//
// Returns:
//   - A string representing the file name of the resource, or an empty string if the resource is nil.
func resourceNameOrBlank(resource *components.AttackResourceFile) string {
	if resource == nil {
		return ""
	}

	return resource.FileName
}
