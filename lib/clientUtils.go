package lib

import (
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
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
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

// CheckForExistingClient checks if a client process is already running by examining a PID file at the specified path.
// Returns true if the process is found or errors occur, otherwise false.
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

// CreateLockFile creates a lock file with the current process PID.
// Writes the PID to the designated lock file in the shared state.
// Logs an error and returns it if writing fails.
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

// CreateDataDirs creates required directories based on the paths set in shared.State. It checks for each path's existence,
// ensures it's not blank, and creates the directory if it doesn't exist, logging any errors that occur. Returns an error
// if any directory creation fails.
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
