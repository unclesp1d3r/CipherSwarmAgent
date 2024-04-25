package lib

import (
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"time"

	"github.com/spf13/afero"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"

	"github.com/imroc/req/v3"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"

	"github.com/unclesp1d3r/cipherswarm-agent-go-api"
)

var (
	// agentPlatform represents the platform on which the agent is running.
	agentPlatform    = ""
	Configuration    AgentConfiguration // AgentConfiguration represents the configuration of the agent.
	Context          context.Context
	APIConfiguration cipherswarm.Configuration
	apiClient        = cipherswarm.NewAPIClient(&APIConfiguration)
)

// AuthenticateAgent authenticates the agent with the CipherSwarm API.
// It sends an authentication request to the API and returns the agent ID if successful.
// If there is an error connecting to the API or if the authentication fails, an error is returned.
func AuthenticateAgent() (int64, error) {
	resp, httpRes, err := apiClient.ClientAPI.Authenticate(Context).Execute()
	if err != nil {
		Logger.Error("Error connecting to the CipherSwarm API", err)
		return 0, err
	}

	if httpRes.StatusCode == 200 {
		agentID := resp.GetAgentId()
		viper.Set("agent_id", agentID)

		if !resp.GetAuthenticated() {
			Logger.Error("Error authenticating with the CipherSwarm API", "response", httpRes.Status)
			return 0, errors.New("failed to authenticate with the CipherSwarm API")
		}
		Logger.Info("Agent authenticated with the CipherSwarm API", "agent_id", agentID)
		return agentID, nil

	}

	Logger.Error("bad response: %v", resp)
	return 0, errors.New("bad response: " + httpRes.Status)
}

// GetAgentConfiguration retrieves the agent configuration from the CipherSwarm API.
// It returns an AgentConfiguration struct and an error if there was a problem connecting to the API or if the response was not successful.
func GetAgentConfiguration() (AgentConfiguration, error) {
	agentConfig := AgentConfiguration{}
	result, httpRes, err := apiClient.ClientAPI.Configuration(Context).Execute()
	if err != nil {
		Logger.Error("Error connecting to the CipherSwarm API", err)
		return agentConfig, err
	}

	if httpRes.StatusCode == 200 {
		agentConfig.APIVersion = result.GetApiVersion()

		advancedConfig := result.GetConfig()
		agentConfig.Config.UseNativeHashcat = advancedConfig.GetUseNativeHashcat()
		agentConfig.Config.AgentUpdateInterval = int(advancedConfig.GetAgentUpdateInterval())
		agentConfig.Config.BackendDevices = advancedConfig.GetBackendDevice()

		if agentConfig.Config.UseNativeHashcat {
			Logger.Debug("Using native Hashcat")
			binPath, err := exec.LookPath("hashcat")
			if err != nil {
				Logger.Error("Error finding hashcat binary: ", err)
			}
			viper.Set("hashcat_path", binPath)
		} else {
			Logger.Debug("Using server-provided Hashcat binary")

		}
		return agentConfig, nil
	}

	Logger.Error("bad response: %v", result)
	return agentConfig, errors.New("bad response: " + httpRes.Status)
}

// UpdateAgentMetadata updates the metadata of an agent.
// It takes a client object and an agent ID as parameters.
// It retrieves the host information and constructs an AgentMetadata object.
// The AgentMetadata object includes the agent's name, client signature, devices, and operating system.
// The agent metadata is then sent to the server using a PUT request.
// If there is an error retrieving the host information or updating the agent metadata, an error message is logged.
// The updated agent metadata is also logged for debugging purposes.
func UpdateAgentMetadata(agentID int64) {
	Logger.Info("Updating agent metadata with the CipherSwarm API")
	info, err := host.Info()
	if err != nil {
		Logger.Error("Error getting info info: ", err)
	}

	// client_signature represents the signature of the client, which includes the CipherSwarm Agent version, operating system,
	//   and kernel architecture.
	clientSignature := fmt.Sprintf("CipherSwarm Agent/%s %s/%s", AgentVersion, info.OS, info.KernelArch)

	devices, err := arch.GetDevices()
	if err != nil {
		Logger.Error("Error getting devices: ", err)
	}

	agentPlatform = info.OS
	agentUpdate := *cipherswarm.NewAgentUpdate(agentID, info.Hostname, clientSignature, info.OS, devices)

	result, httpRes, err := apiClient.AgentsAPI.UpdateAgent(Context, agentID).AgentUpdate(agentUpdate).Execute()
	if err != nil {
		Logger.Error("Error updating agent metadata", "error", err)
	}

	if httpRes.StatusCode == 200 {
		Logger.Info("Agent metadata updated with the CipherSwarm API", "agent_id", agentID)
		Logger.Debug("Agent metadata", "metadata", result)
	} else {
		Logger.Error("bad response: %v", result)
	}
}

// UpdateCracker checks for an updated version of the cracker and performs the necessary actions.
// It takes a client object as a parameter and uses it to make a request to check for updates.
// If an updated version is available, it logs the information about the latest version.
// If any errors occur during the process, they are logged as well.
func UpdateCracker() {
	Logger.Info("Checking for updated cracker")
	currentVersion, err := GetCurrentHashcatVersion()
	if err != nil {
		Logger.Error("Error getting current hashcat version", "error", err)
	}

	result, httpRes, err := apiClient.CrackersAPI.CheckForCrackerUpdate(Context).
		OperatingSystem(agentPlatform).Version(currentVersion).Execute()
	if err != nil {
		Logger.Error("Error connecting to the CipherSwarm API", err)
		return
	}

	if httpRes.StatusCode == 204 {
		Logger.Debug("No new cracker available")
		return
	}

	if httpRes.StatusCode == 200 {
		if result.GetAvailable() {
			Logger.Info("New cracker available", "latest_version", result.GetLatestVersion())
			Logger.Info("Download URL", "url", result.GetDownloadUrl())

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

			err = downloadFile(result.GetDownloadUrl(), tempArchivePath, "")
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
			hashcatBinaryPath := path.Join(hashcatDirectory, result.GetExecName())
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
				path.Join(viper.GetString("crackers_path"), "hashcat", result.GetExecName()),
			)
			_ = viper.WriteConfig()
		} else {
			Logger.Debug("No new cracker available", "latest_version", result.GetLatestVersion())
		}
	} else {
		Logger.Error("Error checking for updated cracker", "CrackerUpdate", result)
	}
}

func GetNewTask() (*cipherswarm.Task, error) {
	result, httpRes, err := apiClient.TasksAPI.NewTask(Context).Execute()
	if err != nil {
		return nil, err
	}
	if httpRes.StatusCode == 204 {
		return nil, nil
	}

	if httpRes.StatusCode == 200 {
		return result, nil
	}

	return nil, errors.New("bad response: " + httpRes.Status)
}

func GetAttackParameters(attackID int64) (*cipherswarm.Attack, error) {
	result, httpRes, err := apiClient.AttacksAPI.ShowAttack(Context, attackID).Execute()
	if err != nil {
		Logger.Error("Error connecting to the CipherSwarm API", err)
		return nil, err
	}

	if httpRes.StatusCode == 200 {

		return result, nil
	}
	return nil, errors.New("bad response: " + httpRes.Status)
}

func SendBenchmarkResults(agentID int64, benchmarkResults []BenchmarkResult) error {
	var results []cipherswarm.HashcatBenchmark
	for _, result := range benchmarkResults {
		hashType, _ := strconv.Atoi(result.HashType)
		runtimeMs, _ := strconv.ParseInt(result.RuntimeMs, 10, 64)
		speedHs, _ := strconv.ParseFloat(result.SpeedHs, 32)
		device, _ := strconv.Atoi(result.Device)

		benchmark := cipherswarm.NewHashcatBenchmark(int32(hashType), runtimeMs, float32(speedHs), int32(device))
		results = append(results, *benchmark)
	}
	httpRes, err := apiClient.AgentsAPI.SubmitBenchmarkAgent(Context, agentID).
		HashcatBenchmark(results).Execute()
	if err != nil {
		return err
	}

	if httpRes.StatusCode == 204 {
		return nil
	}
	return errors.New("bad response: " + httpRes.Status)
}

func GetLastBenchmarkDate(agentID int64) (time.Time, error) {
	result, httpRes, err := apiClient.AgentsAPI.LastBenchmarkAgent(Context, agentID).Execute()
	if err != nil {
		Logger.Error("Error connecting to the CipherSwarm API", err)
		return time.Time{}, err
	}

	if httpRes.StatusCode == 200 {
		return result.GetLastBenchmarkDate(), nil
	}

	return time.Time{}, errors.New("bad response: " + httpRes.Status)
}

func UpdateBenchmarks(agentID int64) {
	jobParams := hashcat.HashcatParams{
		AttackMode:     hashcat.AttackBenchmark,
		AdditionalArgs: arch.GetAdditionalHashcatArgs(),
	}

	sess, err := hashcat.NewHashcatSession("benchmark", jobParams)
	if err != nil {
		Logger.Error("Failed to create benchmark session", "error", err)
		return
	}

	Logger.Info("Performing benchmarks")
	benchmarkResult, done := RunBenchmarkTask(sess)
	if done {
		return
	}
	Logger.Debug("Benchmark session completed", "results", benchmarkResult)
	err = SendBenchmarkResults(agentID, benchmarkResult)
	if err != nil {
		Logger.Error("Failed to send benchmark results", "error", err)
		return
	}
}

func DownloadFiles(attack *cipherswarm.Attack) error {
	Logger.Info("Downloading files for attack", "attack_id", attack.GetId())

	// Download the hashlist
	hashlistPath := path.Join(viper.GetString("hashlist_path"), strconv.FormatInt(attack.GetHashListId(), 10)+".txt")
	Logger.Debug("Downloading hashlist", "url", attack.GetHashListUrl(), "path", hashlistPath)
	err := downloadFile(attack.GetHashListUrl(), hashlistPath, attack.GetHashListChecksum())
	if err != nil {
		Logger.Error("Error downloading hashlist", "error", err)
		return err
	}

	// Download the wordlists
	for _, wordlist := range attack.WordLists {
		wordlistPath := path.Join(viper.GetString("file_path"), wordlist.FileName)
		Logger.Debug("Downloading wordlist", "url", wordlist.GetDownloadUrl(), "path", wordlistPath)
		err := downloadFile(wordlist.GetDownloadUrl(), wordlistPath, wordlist.GetChecksum())
		if err != nil {
			Logger.Error("Error downloading wordlist", "error", err)
			return err
		}
	}

	// Download the rulelists
	for _, rulelist := range attack.RuleLists {
		rulelistPath := path.Join(viper.GetString("file_path"), rulelist.FileName)
		Logger.Debug("Downloading rulelist", "url", rulelist.GetDownloadUrl(), "path", rulelistPath)
		err := downloadFile(rulelist.GetDownloadUrl(), rulelistPath, rulelist.GetChecksum())
		if err != nil {
			Logger.Error("Error downloading rulelist", "error", err)
			return err
		}
	}

	return nil
}

func downloadFile(url string, path string, checksum string) error {
	if _, err := os.Stat(path); err == nil {
		if checksum != "" {
			// MD5 hash the file and compare it to the checksum
			// If the checksums match, the file is already downloaded
			plainTextByte, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// Check the checksum
			md5sum := md5.Sum(plainTextByte) //nolint:gosec
			// base64 encoded md5 hash
			fileChecksum := base64.StdEncoding.EncodeToString(md5sum[:])
			if fileChecksum == checksum {
				Logger.Debug("Download already exists", "path", path)
				return nil
			}
			Logger.Debug("Checksums do not match", "path", path)
			err = os.Remove(path)
			if err != nil {
				return err
			}
			return nil
		}
		Logger.Debug("Download already exists", "path", path)
		return nil
	}
	Logger.Info("Downloading file", "url", url, "path", path)
	_, err := req.SetTimeout(5*time.Second).
		SetCommonHeader("Accept", "application/json").
		R().
		SetOutputFile(path).
		SetDownloadCallbackWithInterval(func(info req.DownloadInfo) {
			if info.Response.Response != nil {
				Logger.Infof("downloaded %.2f%%\n", float64(info.DownloadedSize)/float64(info.Response.ContentLength)*100.0)
			}
		}, 1*time.Second).
		Get(url)
	if err != nil {
		return err
	}
	Logger.Debug("Downloaded file", "url", url, "path", path)
	return nil
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

func SendHeartBeat(agentID int64) {
	httpRes, err := apiClient.AgentsAPI.HeartbeatAgent(Context, agentID).Execute()
	if err != nil {
		Logger.Error("Error sending heartbeat", "error", err)
		return
	}

	if httpRes.StatusCode == 204 {
		Logger.Debug("Heartbeat sent")
	} else {
		Logger.Error("Error sending heartbeat", "response", httpRes)
	}

}

func RunTask(task *cipherswarm.Task, attack *cipherswarm.Attack) {
	Logger.Info("Running task", "task_id", task.GetId())
	// Create the hashcat session

	// TODO: Need to unify the AttackParameters and HashcatParams structs
	jobParams := hashcat.HashcatParams{
		AttackMode:         GetAttackMode(attack),
		HashType:           uint(attack.HashMode),
		HashFile:           path.Join(viper.GetString("hashlist_path"), strconv.Itoa(int(attack.GetHashListId()))+".txt"),
		Mask:               attack.GetMask(),
		MaskIncrement:      attack.GetIncrementMode(),
		MaskIncrementMin:   uint(attack.GetIncrementMinimum()),
		MaskIncrementMax:   uint(attack.GetIncrementMaximum()),
		MaskShardedCharset: "",
		MaskCustomCharsets: nil,
		WordlistFilenames:  GetWordlistFilenames(attack),
		RulesFilenames:     GetRulelistFilenames(attack),
		AdditionalArgs:     arch.GetAdditionalHashcatArgs(),
		OptimizedKernels:   attack.Optimized,
		SlowCandidates:     attack.SlowCandidateGenerators,
		Skip:               task.GetSkip(),
		Limit:              task.GetLimit(),
	}

	sess, err := hashcat.NewHashcatSession("attack", jobParams)
	if err != nil {
		Logger.Error("Failed to create attack session", "error", err)
		return
	}

	Logger.Info("Running attack")
	if !AcceptTask(task) {
		Logger.Error("Failed to accept task", "task_id", task.GetId())
		return
	}
	RunAttackTask(sess, task)

	Logger.Info("Attack completed")
}

func SendStatusUpdate(update hashcat.HashcatStatus, task *cipherswarm.Task) {
	// TODO: Implement receiving a result code when sending this status update
	// Depending on the code, we should stop the job or pause it

	// Hashcat doesn't seem to update the time consistently, so we'll set it here
	if update.Time.IsZero() {
		update.Time = time.Now()
	}

	Logger.Debug("Sending status update", "status", update)

	var deviceStatuses []cipherswarm.DeviceStatus
	for _, device := range update.Devices {
		deviceStatus := *cipherswarm.NewDeviceStatus(
			device.DeviceID,
			device.DeviceName,
			device.DeviceType,
			device.Speed,
			device.Util,
			device.Temp)
		deviceStatuses = append(deviceStatuses, deviceStatus)
	}

	guess := *cipherswarm.NewHashcatGuess(
		update.Guess.GuessBase,
		int64(update.Guess.GuessBaseCount),
		int64(update.Guess.GuessBaseOffset),
		update.Guess.GuessModPercent,
		update.Guess.GuessMod,
		int64(update.Guess.GuessModCount),
		int64(update.Guess.GuessModOffset),
		update.Guess.GuessModPercent,
		update.Guess.GuessMode)

	taskStatus := *cipherswarm.NewTaskStatus(
		update.OriginalLine,
		update.Time,
		update.Session,
		guess,
		update.Status,
		update.Target,
		update.Progress,
		update.RestorePoint,
		update.RecoveredHashes,
		update.RecoveredSalts,
		update.Rejected,
		deviceStatuses,
		time.Unix(update.TimeStart, 0),
		time.Unix(update.EstimatedStop, 0))

	httpRes, err := apiClient.TasksAPI.SubmitStatus(Context, task.GetId()).TaskStatus(taskStatus).Execute()
	if err != nil {
		Logger.Error("Error sending status update", "error", err)
		return
	}
	// We'll do something with the status update responses at some point. Maybe tell the job to stop or pause.
	if httpRes.StatusCode == 204 {
		Logger.Debug("Status update sent successfully")
	} else {
		Logger.Error("Error sending status update", "response", httpRes)
	}
}

func AcceptTask(task *cipherswarm.Task) bool {
	httpRes, err := apiClient.TasksAPI.AcceptTask(Context, task.GetId()).Execute()
	if err != nil {
		Logger.Error("Error accepting task", "error", err)
		return false
	}

	if httpRes.StatusCode == 204 {
		Logger.Debug("Task accepted")
		return true
	} else {
		if httpRes.StatusCode == 422 {
			Logger.Error("Task already completed", "task_id", task.GetId(), "status", httpRes)
			return false
		}
		Logger.Error("Error accepting task", "response", httpRes)
		return false
	}

}

func MarkTaskExhausted(task *cipherswarm.Task) {
	_, err := apiClient.TasksAPI.ExhaustedTask(Context, task.GetId()).Execute()
	if err != nil {
		Logger.Error("Error notifying server", "error", err)
	}

}

func SendCrackedHash(hash hashcat.HashcatResult, task *cipherswarm.Task) {
	result := *cipherswarm.NewHashcatResult(hash.Timestamp, hash.Hash, hash.Plaintext)

	httpRes, err := apiClient.TasksAPI.SubmitCrack(Context, task.GetId()).
		HashcatResult(result).Execute()
	if err != nil {
		Logger.Error("Error sending cracked hash", "error", err)
		return
	}

	if httpRes.StatusCode == 200 || httpRes.StatusCode == 204 {
		Logger.Debug("Cracked hash sent")
		if httpRes.StatusCode == 204 {
			Logger.Info("Hashlist completed", "hash", hash.Hash)
		}
	} else {
		Logger.Error("Error sending cracked hash", "response", httpRes)
	}

}
