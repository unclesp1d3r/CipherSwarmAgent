package lib

import (
	"errors"
	"github.com/spf13/afero"
	"os"
	"os/exec"
	"path"
	"strconv"
	"time"

	"github.com/imroc/req/v3"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
)

var (
	// AgentPlatform represents the platform on which the agent is running.
	AgentPlatform = ""
	Client        = req.C()
	Configuration AgentConfiguration // AgentConfiguration represents the configuration of the agent.
)

// AuthenticateAgent authenticates the agent with the CipherSwarm API.
// It sends a GET request to the "/authenticate" endpoint and checks the response.
// If the response is successful, it parses the response body into an AgentAuthenticationResult struct.
// If the agent is successfully authenticated, it logs a success message.
// If the agent fails to authenticate, it logs an error message and exits the program.
// If there is an error connecting to the CipherSwarm API, it logs an error message.
// Finally, it logs the response body for debugging purposes.
func AuthenticateAgent() (int, error) {
	result := AgentAuthenticationResult{}
	resp, err := Client.R().Get("/authenticate")
	if err != nil {
		Logger.Error("Error connecting to the CipherSwarm API", err)
		return 0, err
	}

	if resp.IsSuccessState() {
		err = resp.Into(&result)
		if err != nil {
			Logger.Fatal(err)
			return 0, err
		}

		if result.Authenticated {
			viper.Set("agent_id", result.AgentID)
			return result.AgentID, nil
		} else {
			return 0, errors.New("failed to authenticate with the CipherSwarm API")
		}
	} else {
		Logger.Error("bad response: %v", resp)
		return 0, resp.Err
	}
}

// GetAgentConfiguration retrieves the agent configuration from the CipherSwarm API.
// It takes a req.Client as a parameter and returns an AgentConfiguration.
// If there is an error connecting to the API or if the response is not successful,
// it logs the error and returns an empty AgentConfiguration.
// If the response is successful, it logs the response body for debugging purposes.
func GetAgentConfiguration() (AgentConfiguration, error) {
	rep, err := Client.R().Get("/configuration")
	if err != nil {
		return AgentConfiguration{}, err
	}

	result := AgentConfiguration{}
	if rep.IsSuccessState() {
		Logger.Debug(rep.String())
		err = rep.Into(&result)
		if err != nil {
			return AgentConfiguration{}, err
		}

	} else {
		return AgentConfiguration{}, errors.New("bad response: " + rep.String())
	}

	if result.Config.UseNativeHashcat {
		Logger.Debug("Using native Hashcat")
		binPath, err := exec.LookPath("hashcat")
		if err != nil {
			Logger.Error("Error finding hashcat binary: ", err)
		}
		viper.Set("hashcat_path", binPath)
	} else {
		Logger.Debug("Using server-provided Hashcat binary")

	}
	return result, nil
}

// UpdateAgentMetadata updates the metadata of an agent.
// It takes a client object and an agent ID as parameters.
// It retrieves the host information and constructs an AgentMetadata object.
// The AgentMetadata object includes the agent's name, client signature, devices, and operating system.
// The agent metadata is then sent to the server using a PUT request.
// If there is an error retrieving the host information or updating the agent metadata, an error message is logged.
// The updated agent metadata is also logged for debugging purposes.
func UpdateAgentMetadata(agentID int) {
	Logger.Info("Updating agent metadata with the CipherSwarm API")
	info, err := host.Info()
	if err != nil {
		Logger.Error("Error getting info info: ", err)
	}

	// client_signature represents the signature of the client, which includes the CipherSwarm Agent version, operating system,
	//   and kernel architecture.
	clientSignature := "CipherSwarm Agent/" + AgentVersion + " " + info.OS + "/" + info.KernelArch

	devices, err := arch.GetDevices()
	if err != nil {
		Logger.Error("Error getting devices: ", err)
	}

	agentMetadata := AgentMetadata{
		Name:            info.Hostname,
		ClientSignature: clientSignature,
		Devices:         devices,
	}

	AgentPlatform = info.OS

	switch info.OS {
	case "linux":
		agentMetadata.OperatingSystem = Linux
	case "windows":
		agentMetadata.OperatingSystem = Windows
	case "darwin":
		agentMetadata.OperatingSystem = Darwin
	default:
		agentMetadata.OperatingSystem = Other
	}

	resp, err := Client.R().SetBody(agentMetadata).Put("/agents/" + strconv.Itoa(agentID))
	if err != nil {
		Logger.Error("Error updating agent metadata: ", err)
	}

	if resp.IsSuccessState() {
		Logger.Info("Agent metadata updated with the CipherSwarm API")
	} else {
		Logger.Error("Error updating agent metadata: ", resp.String())
	}
}

// UpdateCracker checks for an updated version of the cracker and performs the necessary actions.
// It takes a client object as a parameter and uses it to make a request to check for updates.
// If an updated version is available, it logs the information about the latest version.
// If any errors occur during the process, they are logged as well.
func UpdateCracker() {
	updateCrackerResponse := UpdateCrackerResponse{}
	Logger.Info("Checking for updated cracker")
	currentVersion, err := GetCurrentHashcatVersion()
	if err != nil {
		Logger.Error("Error getting current hashcat version", "error", err)
	}

	resp := Client.Get("/crackers/check_for_cracker_update").
		AddQueryParams("version", currentVersion).
		AddQueryParams("operating_system", AgentPlatform).Do()
	if resp.Err != nil {
		Logger.Error("Error checking for updated cracker: ", resp.Err)
	}

	if resp.IsSuccessState() {
		err := resp.Into(&updateCrackerResponse)
		if err != nil {
			Logger.Error("Error parsing response: ", err)
		}
		if updateCrackerResponse.Available {
			Logger.Info("New cracker available", "latest_version", updateCrackerResponse.LatestVersion.Version)
			Logger.Info("Download URL", "url", updateCrackerResponse.DownloadURL)

			// Get the file to a temporary location and then move it to the correct location
			// This is to prevent the file from being corrupted if the download is interrupted
			tempDir, err := os.MkdirTemp("", "cipherswarm-*")
			if err != nil {
				Logger.Error("Error creating temporary directory: ", "error", err)
			}
			defer func(path string) {
				err := os.RemoveAll(path)
				if err != nil {
					Logger.Error("Error removing temporary directory: ", "error", err)
				}
			}(tempDir)

			tempArchivePath := path.Join(tempDir, "hashcat.7z")
			_, err = Client.R().
				SetOutputFile(tempArchivePath).
				SetDownloadCallbackWithInterval(func(info req.DownloadInfo) {
					if info.Response.Response != nil {
						Logger.Infof("downloaded %.2f%%\n", float64(info.DownloadedSize)/float64(info.Response.ContentLength)*100.0)
					}
				}, 200*time.Millisecond).
				Get(updateCrackerResponse.DownloadURL)
			if err != nil {
				Logger.Error("Error downloading cracker: ", "error", err)
			}
			// Move the file to the correct location in the crackers directory
			newArchivePath, err := moveArchiveFile(tempArchivePath)
			if err != nil {
				Logger.Error("Error moving file: ", "error", err)
				return // Don't continue if we can't move the file
			}

			// Extract the file
			// At some point, we should check the hash of the file to make sure it's not corrupted
			// We should also implement 7z extraction in Go, for now we'll use the 7z command
			hashcatDirectory, err := extractHashcatArchive(newArchivePath)
			if err != nil {
				Logger.Error("Error extracting file: ", err)
				return // Don't continue if we can't extract the file
			}

			// Check if the new hashcat directory exists
			hashcatExists, _ := afero.Exists(AppFs, hashcatDirectory)
			if !hashcatExists {
				Logger.Error("New hashcat directory does not exist", "path", hashcatDirectory)
				return
			}

			// Check to make sure there's a hashcat binary in the new directory
			hashcatBinaryPath := path.Join(hashcatDirectory, updateCrackerResponse.ExecName)
			hashcatBinaryExists, _ := afero.Exists(AppFs, hashcatBinaryPath)
			if !hashcatBinaryExists {
				Logger.Error("New hashcat binary does not exist", "path", hashcatBinaryPath)
				return
			}

			err = os.Remove(newArchivePath)
			if err != nil {
				Logger.Error("Error removing 7z file", "error", err)
			}

			// Update the config file
			viper.Set(
				"hashcat_path",
				path.Join(viper.GetString("crackers_path"), "hashcat", updateCrackerResponse.ExecName),
			)
			_ = viper.WriteConfig()
		}
	} else {
		Logger.Error("Error checking for updated cracker: ", resp.String())
	}
}

func extractHashcatArchive(newArchivePath string) (string, error) {
	hashcatDirectory := path.Join(viper.GetString("crackers_path"), "hashcat")
	hashcatBackupDirectory := hashcatDirectory + "_old"
	// Get rid of the old hashcat backup directory
	err := os.RemoveAll(hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		Logger.Error("Error removing old hashcat directory: ", "error", err)
		return "", err // Don't continue if we can't remove the old directory
	}

	// Move the old hashcat directory to a backup location
	err = os.Rename(hashcatDirectory, hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		Logger.Error("Error moving old hashcat directory: ", "error", err)
		return "", err // Don't continue if we can't move the old directory
	}

	// Extract the new hashcat directory using the 7z command
	err = arch.Extract7z(newArchivePath, viper.GetString("crackers_path"))
	if err != nil {
		Logger.Error("Error extracting file: ", "error", err)
		return "", err // Don't continue if we can't extract the file
	}
	return hashcatDirectory, err
}

func moveArchiveFile(tempArchivePath string) (string, error) {
	newArchivePath := path.Join(viper.GetString("crackers_path"), "hashcat.7z")
	err := os.Rename(tempArchivePath, newArchivePath)
	if err != nil {
		Logger.Error("Error moving file: ", err)
		return "", err
	}
	Logger.Debug("Moved file", "old_path", tempArchivePath, "new_path", newArchivePath)
	return newArchivePath, err
}
