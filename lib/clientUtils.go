package lib

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	url2 "net/url"
	"os"
	"path"

	"github.com/duke-git/lancet/cryptor"
	"github.com/duke-git/lancet/v2/validator"
	"github.com/hashicorp/go-getter"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarmagent/lib/utils"

	"github.com/duke-git/lancet/convertor"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/duke-git/lancet/fileutil"
	"github.com/unclesp1d3r/cipherswarmagent/shared"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
)

func getCurrentHashcatVersion() (string, error) {
	// Check where the hashcat binary should be
	hashcatExists := fileutil.IsExist(viper.GetString("hashcat_path"))
	if !hashcatExists {
		shared.Logger.Error("Cannot find hashcat binary, checking fallback location.", "path", viper.GetString("hashcat_path"))

		// Check if the hashcat binary exists in the crackers directory
		fallbackPath := path.Join(
			shared.State.CrackersPath,
			"hashcat",
			arch.GetDefaultHashcatBinaryName(),
		)
		if fileutil.IsExist(fallbackPath) {
			shared.Logger.Debug("Using hashcat binary from crackers directory", "path", fallbackPath)
			viper.Set("hashcat_path", fallbackPath)
		} else {
			shared.Logger.Error("Hashcat binary does not exist", "path", fallbackPath)
		}
	}
	if !hashcatExists {
		shared.Logger.Error("Hashcat binary does not exist", "path", viper.GetString("hashcat_path"))
		return "0.0.0", errors.New("hashcat binary does not exist")
	}

	// Found the hashcat binary, get the version
	hashcatVersion, err := arch.GetHashcatVersion(viper.GetString("hashcat_path"))
	if err != nil {
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

		pidRunning, err := process.PidExists(int32(pidValue))
		if err != nil {
			shared.Logger.Error("Error checking if process is running", "pid", pidValue)
			return true
		}

		shared.Logger.Warn("Existing lock file found", "path", pidFilePath, "pid", pidValue)
		if !pidRunning {
			shared.Logger.Warn("Existing process is not running, cleaning up file", "pid", pidValue)
		}
		return pidRunning
	} else {
		return false
	}
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

// CreateDataDirs creates the necessary data directories for the CipherSwarmAgent.
// It checks if the directories already exist, and if not, it creates them.
// Returns an error if there was a problem creating the directories.
func CreateDataDirs() error {
	dataDirs := []string{
		shared.State.FilePath,
		shared.State.CrackersPath,
		shared.State.HashlistPath,
		shared.State.ZapsPath,
		shared.State.PreprocessorsPath,
		shared.State.ToolsPath,
		shared.State.OutPath,
	}
	for _, dir := range dataDirs {
		if dir == "" {
			shared.Logger.Error("Data directory not set")
		}

		if !fileutil.IsDir(dir) {
			err := fileutil.CreateDir(dir)
			if err != nil {
				return err
			}
			shared.Logger.Info("Created directory", "path", dir)
		}
	}
	return nil
}

func downloadHashList(attack *components.Attack) error {
	if attack == nil {
		shared.Logger.Error("Attack is nil")
		return errors.New("attack is nil")
	}

	// Download the hashlist
	hashlistPath := path.Join(shared.State.HashlistPath, convertor.ToString(attack.GetHashListID())+".txt")
	shared.Logger.Debug("Downloading hashlist", "url", attack.GetHashListURL(), "path", hashlistPath)
	// We should always download the hashlist, even if it already exists
	// This is because the hashlist may have been updated on the server
	if fileutil.IsExist(hashlistPath) {
		err := os.Remove(hashlistPath)
		if err != nil {
			shared.Logger.Error("Error removing old hashlist", "error", err)
			SendAgentError(err.Error(), nil, components.SeverityCritical)
			return err
		}
	}

	response, err := SdkClient.Attacks.GetHashList(Context, attack.ID)
	if err != nil {
		shared.Logger.Error("Error downloading hashlist from the CipherSwarm API", "error", err)
		SendAgentError(err.Error(), nil, components.SeverityCritical)
		return err
	}

	if response.StatusCode == http.StatusOK {
		if response.ResponseStream != nil {
			f, err := os.Create(hashlistPath)
			if err != nil {
				shared.Logger.Error("Error creating hashlist file", "error", err)
				SendAgentError(err.Error(), nil, components.SeverityCritical)
				return err
			}
			defer f.Close()
			_, err = io.Copy(f, response.ResponseStream)
			if err != nil {
				shared.Logger.Error("Error writing hashlist file", "error", err)
				SendAgentError(err.Error(), nil, components.SeverityCritical)
				return err
			}
			shared.Logger.Debug("Downloaded hashlist", "path", hashlistPath)
			hashSize, _ := fileutil.FileSize(hashlistPath)
			if hashSize == 0 {
				shared.Logger.Error("Downloaded hashlist is empty", "path", hashlistPath)
				SendAgentError("Downloaded hashlist is empty", nil, components.SeverityCritical)
				return errors.New("downloaded hashlist is empty, probably completed task")
			}
		}
	} else {
		shared.Logger.Error("Error downloading hashlist", "response", response.RawResponse.Status)
		return errors.New("failed to download hashlist")
	}
	return nil
}

func downloadFile(url string, path string, checksum string) error {
	if !validator.IsUrl(url) {
		shared.Logger.Error("Invalid URL", "url", url)
		return errors.New("invalid URL")
	}

	if fileutil.IsExist(path) {
		if strutil.IsNotBlank(checksum) {
			fileChecksum, err := cryptor.Md5File(path)
			if err != nil {
				return err
			}
			if fileChecksum == checksum {
				shared.Logger.Info("Download already exists", "path", path)
				return nil
			}
			shared.Logger.Warn("Checksums do not match", "path", path, "url_checksum", checksum, "file_checksum", fileChecksum)
			SendAgentError("Resource "+path+" exists, but checksums do not match", nil, components.SeverityInfo)
			err = os.Remove(path)
			if err != nil {
				SendAgentError(err.Error(), nil, components.SeverityMajor)
				return err
			}
		}
	}
	DisplayDownloadFile(url, path)
	cwd, err := os.Getwd()
	if err != nil {
		shared.Logger.Error("Error getting current working directory: ", "error", err)
	}

	if strutil.IsNotBlank(checksum) {
		urlA, err := url2.Parse(url)
		if err != nil {
			shared.Logger.Error("Error parsing URL: ", "error", err)
			return err
		}
		values := urlA.Query()
		values.Add("checksum", checksum)
		urlA.RawQuery = values.Encode()
		url = urlA.String()
	}

	client := &getter.Client{
		Ctx:      context.Background(),
		Dst:      path,
		Src:      url,
		Pwd:      cwd,
		Insecure: true,
		Mode:     getter.ClientModeFile,
	}

	_ = client.Configure(
		getter.WithProgress(utils.DefaultProgressBar),
		getter.WithUmask(os.FileMode(0o022)),
	)

	if err := client.Get(); err != nil {
		shared.Logger.Debug("Error downloading file: ", "error", err)
		return err
	}
	DisplayDownloadFileComplete(url, path)
	return nil
}

func extractHashcatArchive(newArchivePath string) (string, error) {
	hashcatDirectory := path.Join(shared.State.CrackersPath, "hashcat")
	hashcatBackupDirectory := hashcatDirectory + "_old"
	// Get rid of the old hashcat backup directory
	err := os.RemoveAll(hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		shared.Logger.Error("Error removing old hashcat directory: ", "error", err)
		SendAgentError(err.Error(), nil, components.SeverityCritical)
		return "", err // Don't continue if we can't remove the old directory
	}

	// Move the old hashcat directory to a backup location
	err = os.Rename(hashcatDirectory, hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		shared.Logger.Error("Error moving old hashcat directory: ", "error", err)
		SendAgentError(err.Error(), nil, components.SeverityCritical)
		return "", err // Don't continue if we can't move the old directory
	}

	// Extract the new hashcat directory using the 7z command
	err = arch.Extract7z(newArchivePath, shared.State.CrackersPath)
	if err != nil {
		shared.Logger.Error("Error extracting file: ", "error", err)
		SendAgentError(err.Error(), nil, components.SeverityCritical)
		return "", err // Don't continue if we can't extract the file
	}
	return hashcatDirectory, err
}

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

func base64ToHex(base64 string) string {
	if strutil.IsBlank(base64) {
		return ""
	}
	str := cryptor.Base64StdDecode(base64)
	hx := hex.EncodeToString([]byte(str))
	return hx
}
