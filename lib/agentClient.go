package lib

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"time"

	"github.com/duke-git/lancet/convertor"

	"github.com/duke-git/lancet/cryptor"
	"github.com/duke-git/lancet/fileutil"
	"github.com/unclesp1d3r/cipherswarmagent/shared"

	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"

	"github.com/imroc/req/v3"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"

	"github.com/unclesp1d3r/cipherswarm-agent-go-api"
)

var (
	// agentPlatform represents the platform on which the agent is running.
	agentPlatform    = ""                                          // agentPlatform represents the platform on which the agent is running.
	Configuration    AgentConfiguration                            // AgentConfiguration represents the configuration of the agent.
	Context          context.Context                               // Context represents the context of the agent.
	APIConfiguration cipherswarm.Configuration                     // APIConfiguration represents the configuration of the API.
	apiClient        = cipherswarm.NewAPIClient(&APIConfiguration) // apiClient represents the API client.
)

// AuthenticateAgent authenticates the agent with the CipherSwarm API.
// It sends an authentication request to the API and checks the response status.
// If the authentication is successful, it sets the agent ID in the shared state.
// If the authentication fails, it returns an error.
// The function returns an error if there is an error connecting to the API or if the response status is not OK.
func AuthenticateAgent() error {
	result, httpRes, err := apiClient.ClientAPI.Authenticate(Context).Execute()
	if err != nil {
		shared.Logger.Error("Error connecting to the CipherSwarm API", err)
		return err
	}

	if result == nil {
		shared.Logger.Error("Error authenticating with the CipherSwarm API", "response", httpRes.Status)
		return errors.New("failed to authenticate with the CipherSwarm API")
	}

	if httpRes.StatusCode == http.StatusOK {
		agentID := result.GetAgentId()
		shared.State.AgentID = agentID

		if !result.GetAuthenticated() {
			shared.Logger.Error("Error authenticating with the CipherSwarm API", "response", httpRes.Status)
			return errors.New("failed to authenticate with the CipherSwarm API")
		}
		shared.Logger.Info("Agent authenticated with the CipherSwarm API", "agent_id", agentID)
		return nil

	}

	shared.Logger.Error("bad response: %v", result)
	return errors.New("bad response: " + httpRes.Status)
}

// GetAgentConfiguration retrieves the agent configuration from the CipherSwarm API.
// It returns an AgentConfiguration struct and an error if there was a problem connecting to the API or if the response was not successful.
func GetAgentConfiguration() (AgentConfiguration, error) {
	agentConfig := AgentConfiguration{}
	result, httpRes, err := apiClient.ClientAPI.Configuration(Context).Execute()
	if err != nil {
		shared.Logger.Error("Error connecting to the CipherSwarm API", err)
		return agentConfig, err
	}

	if result == nil {
		shared.Logger.Error("Error getting agent configuration", "response", httpRes)
		return agentConfig, errors.New("failed to get agent configuration")
	}

	if httpRes.StatusCode == http.StatusOK {
		agentConfig.APIVersion = result.GetApiVersion()

		advancedConfig := result.GetConfig()
		agentConfig.Config.UseNativeHashcat = advancedConfig.GetUseNativeHashcat()
		agentConfig.Config.AgentUpdateInterval = advancedConfig.GetAgentUpdateInterval()
		agentConfig.Config.BackendDevices = advancedConfig.GetBackendDevice()

		if agentConfig.Config.UseNativeHashcat {
			shared.Logger.Debug("Using native Hashcat")
			// Find the Hashcat binary path
			binPath, err := exec.LookPath("hashcat")
			if err != nil {
				shared.Logger.Error("Error finding hashcat binary: ", err)
			}
			viper.Set("hashcat_path", binPath)
			_ = viper.WriteConfig()
		} else {
			shared.Logger.Debug("Using server-provided Hashcat binary")
		}
		return agentConfig, nil
	}

	shared.Logger.Error("bad response: %v", result)
	return agentConfig, errors.New("bad response: " + httpRes.Status)
}

// UpdateAgentMetadata updates the agent metadata with the CipherSwarm API.
// It retrieves the host information, including the operating system and kernel architecture,
// and constructs a client signature that represents the CipherSwarm Agent version, operating system,
// and kernel architecture. It then retrieves the devices information and creates an agent update
// object with the agent ID, hostname, client signature, operating system, and devices.
// Finally, it sends the agent update request to the CipherSwarm API and handles the response.
func UpdateAgentMetadata() {
	info, err := host.Info()
	if err != nil {
		shared.Logger.Error("Error getting info info: ", err)
		return
	}

	// client_signature represents the signature of the client, which includes the CipherSwarm Agent version, operating system,
	//   and kernel architecture.
	clientSignature := fmt.Sprintf("CipherSwarm Agent/%s %s/%s", AgentVersion, info.OS, info.KernelArch)

	devices, err := arch.GetDevices()
	if err != nil {
		shared.Logger.Error("Error getting devices: ", err)
	}

	agentPlatform = info.OS
	agentUpdate := *cipherswarm.NewAgentUpdate(shared.State.AgentID, info.Hostname, clientSignature, info.OS, devices)

	result, httpRes, err := apiClient.AgentsAPI.UpdateAgent(Context, shared.State.AgentID).AgentUpdate(agentUpdate).Execute()
	if err != nil {
		shared.Logger.Error("Error updating agent metadata", "error", err)
	}

	if result == nil {
		shared.Logger.Error("Error updating agent metadata", "response", httpRes)
		return
	}

	if httpRes.StatusCode == http.StatusOK {
		DisplayAgentMetadataUpdated(result)
	} else {
		shared.Logger.Error("bad response: %v", result)
	}
}

// UpdateCracker checks for an updated version of the cracker and performs the necessary updates.
// It retrieves the current version of the cracker, checks for updates from the CipherSwarm API,
// downloads and extracts the updated cracker, and updates the configuration file.
func UpdateCracker() {
	shared.Logger.Info("Checking for updated cracker")
	currentVersion, err := GetCurrentHashcatVersion()
	if err != nil {
		shared.Logger.Error("Error getting current hashcat version", "error", err)
	}

	result, httpRes, err := apiClient.CrackersAPI.CheckForCrackerUpdate(Context).
		OperatingSystem(agentPlatform).Version(currentVersion).Execute()
	if err != nil {
		shared.Logger.Error("Error connecting to the CipherSwarm API", err)
		return
	}

	if result == nil {
		shared.Logger.Error("Error checking for updated cracker", "response", httpRes)
		return
	}

	if httpRes.StatusCode == http.StatusNoContent {
		shared.Logger.Debug("No new cracker available")
		return
	}

	if httpRes.StatusCode == http.StatusOK {
		if result.GetAvailable() {
			DisplayNewCrackerAvailable(result)

			// Get the file to a temporary location and then move it to the correct location
			// This is to prevent the file from being corrupted if the download is interrupted
			tempDir, err := os.MkdirTemp("", "cipherswarm-*")
			if err != nil {
				shared.Logger.Error("Error creating temporary directory: ", "error", err)
			}
			defer func(path string) {
				err := os.RemoveAll(path)
				if err != nil {
					shared.Logger.Error("Error removing temporary directory: ", "error", err)
				}
			}(tempDir)

			tempArchivePath := path.Join(tempDir, "hashcat.7z")

			err = downloadFile(result.GetDownloadUrl(), tempArchivePath, "")
			if err != nil {
				shared.Logger.Error("Error downloading cracker: ", "error", err)
			}
			// Move the file to the correct location in the crackers directory
			newArchivePath, err := moveArchiveFile(tempArchivePath)
			if err != nil {
				shared.Logger.Error("Error moving file: ", "error", err)
				return // Don't continue if we can't move the file
			}

			// Extract the file
			// At some point, we should check the hash of the file to make sure it's not corrupted
			// We should also implement 7z extraction in Go, for now we'll use the 7z command
			hashcatDirectory, err := extractHashcatArchive(newArchivePath)
			if err != nil {
				shared.Logger.Error("Error extracting file: ", err)
				return // Don't continue if we can't extract the file
			}

			// Check if the new hashcat directory exists
			hashcatExists := fileutil.IsDir(hashcatDirectory)
			if !hashcatExists {
				shared.Logger.Error("New hashcat directory does not exist", "path", hashcatDirectory)
				return
			}

			// Check to make sure there's a hashcat binary in the new directory
			hashcatBinaryPath := path.Join(hashcatDirectory, result.GetExecName())
			hashcatBinaryExists := fileutil.IsExist(hashcatBinaryPath)
			if !hashcatBinaryExists {
				shared.Logger.Error("New hashcat binary does not exist", "path", hashcatBinaryPath)
				return
			}

			err = os.Remove(newArchivePath)
			if err != nil {
				shared.Logger.Error("Error removing 7z file", "error", err)
			}

			// Update the config file with the new hashcat path
			viper.Set(
				"hashcat_path",
				path.Join(shared.State.CrackersPath, "hashcat", result.GetExecName()),
			)
			_ = viper.WriteConfig()
		} else {
			shared.Logger.Debug("No new cracker available", "latest_version", result.GetLatestVersion())
		}
	} else {
		shared.Logger.Error("Error checking for updated cracker", "CrackerUpdate", result)
	}
}

// GetNewTask retrieves a new task from the API.
// It returns the new task if successful, or an error if there was a problem.
func GetNewTask() (*cipherswarm.Task, error) {
	result, httpRes, err := apiClient.TasksAPI.NewTask(Context).Execute()
	if err != nil {
		return nil, err
	}
	if httpRes.StatusCode == http.StatusNoContent {
		// No new task available
		return nil, nil
	}

	if httpRes.StatusCode == http.StatusOK {
		// New task available
		return result, nil
	}

	return nil, errors.New("bad response: " + httpRes.Status)
}

// GetAttackParameters retrieves the attack parameters for the specified attack ID.
// It makes a request to the CipherSwarm API and returns the attack details if the request is successful.
// If there is an error connecting to the API or if the response is not successful, an error is returned.
func GetAttackParameters(attackID int64) (*cipherswarm.Attack, error) {
	result, httpRes, err := apiClient.AttacksAPI.ShowAttack(Context, attackID).Execute()
	if err != nil {
		shared.Logger.Error("Error connecting to the CipherSwarm API", err)
		return nil, err
	}

	if result == nil {
		shared.Logger.Error("Error getting attack parameters", "response", httpRes)
		return nil, errors.New("failed to get attack parameters")
	}

	if httpRes.StatusCode == http.StatusOK {
		return result, nil
	}
	return nil, errors.New("bad response: " + httpRes.Status)
}

// SendBenchmarkResults sends benchmark results to the server.
// It takes a slice of benchmark results as input and returns an error if any.
// Each benchmark result contains information about the hash type, runtime in milliseconds,
// speed in hashes per second, and the device used for benchmarking.
// The function converts the benchmark results into a format compatible with the server's API,
// and submits them using an HTTP request.
// If the request is successful and the server responds with a status code of 204 (No Content),
// the function returns nil. Otherwise, it returns an error with a descriptive message.
func SendBenchmarkResults(benchmarkResults []BenchmarkResult) error {
	var results []cipherswarm.HashcatBenchmark
	for _, result := range benchmarkResults {
		hashType, err := convertor.ToInt(result.HashType)
		if err != nil {
			continue
		}
		runtimeMs, err := convertor.ToInt(result.RuntimeMs)
		if err != nil {
			continue
		}
		speedHs, err := convertor.ToFloat(result.SpeedHs)
		if err != nil {
			continue
		}
		device, err := convertor.ToInt(result.Device)
		if err != nil {
			continue
		}

		benchmark := cipherswarm.NewHashcatBenchmark(int32(hashType), runtimeMs, float32(speedHs), int32(device))
		results = append(results, *benchmark)
	}
	httpRes, err := apiClient.AgentsAPI.SubmitBenchmarkAgent(Context, shared.State.AgentID).
		HashcatBenchmark(results).Execute()
	if err != nil {
		return err
	}

	if httpRes.StatusCode == http.StatusNoContent {
		return nil
	}
	return errors.New("bad response: " + httpRes.Status)
}

// GetLastBenchmarkDate retrieves the last benchmark date from the CipherSwarm API.
// It returns the last benchmark date as a time.Time value and an error if any.
func GetLastBenchmarkDate() (time.Time, error) {
	result, httpRes, err := apiClient.AgentsAPI.LastBenchmarkAgent(Context, shared.State.AgentID).Execute()
	if err != nil {
		shared.Logger.Error("Error connecting to the CipherSwarm API", err)
		return time.Time{}, err
	}

	if result == nil {
		shared.Logger.Error("Error getting last benchmark date", "response", httpRes)
		return time.Time{}, errors.New("failed to get last benchmark date")
	}

	if httpRes.StatusCode == http.StatusOK {
		return result.GetLastBenchmarkDate(), nil
	}

	return time.Time{}, errors.New("bad response: " + httpRes.Status)
}

// UpdateBenchmarks updates the benchmarks for the agent.
func UpdateBenchmarks() {
	jobParams := hashcat.Params{
		AttackMode:     hashcat.AttackBenchmark,
		AdditionalArgs: arch.GetAdditionalHashcatArgs(),
	}

	sess, err := hashcat.NewHashcatSession("benchmark", jobParams)
	if err != nil {
		shared.Logger.Error("Failed to create benchmark session", "error", err)
		return
	}

	DisplayBenchmarkStarting()
	benchmarkResult, done := RunBenchmarkTask(sess)
	if done {
		return
	}
	DisplayBenchmarksComplete(benchmarkResult)
	err = SendBenchmarkResults(benchmarkResult)
	if err != nil {
		shared.Logger.Error("Failed to send benchmark results", "error", err)
		return
	}
}

// DownloadFiles downloads the necessary files for the given attack.
// It downloads the hashlist, wordlists, and rulelists required for the attack.
// The downloaded files are saved to the specified file paths.
// If any error occurs during the download process, the function returns the error.
func DownloadFiles(attack *cipherswarm.Attack) error {
	DisplayDownloadFileStart(attack)

	// Download the hashlist
	hashlistPath := path.Join(shared.State.HashlistPath, strconv.FormatInt(attack.GetHashListId(), 10)+".txt")
	shared.Logger.Debug("Downloading hashlist", "url", attack.GetHashListUrl(), "path", hashlistPath)

	// We should always download the hashlist, even if it already exists
	// This is because the hashlist may have been updated on the server
	if fileutil.IsExist(hashlistPath) {
		err := os.Remove(hashlistPath)
		if err != nil {
			shared.Logger.Error("Error removing old hashlist", "error", err)
			return err
		}
	}

	result, httpRes, err := apiClient.AttacksAPI.HashListAttack(Context, attack.GetId()).Execute()
	if err != nil {
		shared.Logger.Error("Error downloading hashlist from the CipherSwarm API", "error", err)
		return err
	}

	if result == nil {
		shared.Logger.Error("Error downloading hashlist", "response", httpRes)
		return errors.New("failed to download hashlist")
	}

	if httpRes.StatusCode == http.StatusOK {
		// Move the file to the correct location in the hashlist directory
		err = os.Rename(result.Name(), hashlistPath)
		if err != nil {
			shared.Logger.Error("Error moving file", "error", err)
			return err
		}
	}

	// Download the wordlists
	for _, wordlist := range attack.WordLists {
		wordlistPath := path.Join(shared.State.FilePath, wordlist.FileName)
		shared.Logger.Debug("Downloading wordlist", "url", wordlist.GetDownloadUrl(), "path", wordlistPath)
		err := downloadFile(wordlist.GetDownloadUrl(), wordlistPath, wordlist.GetChecksum())
		if err != nil {
			shared.Logger.Error("Error downloading wordlist", "error", err)
			return err
		}
	}
	// Download the rulelists
	for _, rulelist := range attack.RuleLists {
		rulelistPath := path.Join(shared.State.FilePath, rulelist.FileName)
		shared.Logger.Debug("Downloading rulelist", "url", rulelist.GetDownloadUrl(), "path", rulelistPath)
		err := downloadFile(rulelist.GetDownloadUrl(), rulelistPath, rulelist.GetChecksum())
		if err != nil {
			shared.Logger.Error("Error downloading rulelist", "error", err)
			return err
		}
	}

	return nil
}

// SendHeartBeat sends a heartbeat to the agent API.
// It makes an HTTP request to the agent API's HeartbeatAgent endpoint
// and logs the result.
func SendHeartBeat() {
	httpRes, err := apiClient.AgentsAPI.HeartbeatAgent(Context, shared.State.AgentID).Execute()
	if err != nil {
		shared.Logger.Error("Error sending heartbeat", "error", err)
		return
	}

	if httpRes.StatusCode == http.StatusNoContent {
		shared.Logger.Debug("Heartbeat sent")
	} else {
		shared.Logger.Error("Error sending heartbeat", "response", httpRes)
	}
}

// RunTask executes a task using the provided attack parameters.
// It creates a hashcat session based on the attack parameters and runs the attack task.
// If the task is accepted, it displays a message indicating that the task has been accepted.
// After the attack task is completed, it displays a message indicating that the task has been completed.
// If any error occurs during the process, it logs the error and returns.
func RunTask(task *cipherswarm.Task, attack *cipherswarm.Attack) {
	DisplayRunTaskStarting(task)
	// Create the hashcat session

	// TODO: Need to unify the AttackParameters and HashcatParams structs
	jobParams := hashcat.Params{
		AttackMode:       GetAttackMode(attack),
		HashType:         attack.HashMode,
		HashFile:         path.Join(shared.State.HashlistPath, convertor.ToString(attack.GetHashListId())+".txt"),
		Mask:             attack.GetMask(),
		MaskIncrement:    attack.GetIncrementMode(),
		MaskIncrementMin: attack.GetIncrementMinimum(),
		MaskIncrementMax: attack.GetIncrementMaximum(),
		MaskCustomCharsets: []string{
			attack.GetCustomCharset1(),
			attack.GetCustomCharset2(),
			attack.GetCustomCharset3(),
			attack.GetCustomCharset4(),
		},
		WordlistFilenames: GetWordlistFilenames(attack),
		RulesFilenames:    GetRulelistFilenames(attack),
		AdditionalArgs:    arch.GetAdditionalHashcatArgs(),
		OptimizedKernels:  attack.Optimized,
		SlowCandidates:    attack.SlowCandidateGenerators,
		Skip:              task.GetSkip(),
		Limit:             task.GetLimit(),
	}

	sess, err := hashcat.NewHashcatSession("attack", jobParams)
	if err != nil {
		shared.Logger.Error("Failed to create attack session", "error", err)
		return
	}

	if AcceptTask(task) {
		DisplayRunTaskAccepted(task)
	} else {
		shared.Logger.Error("Failed to accept task", "task_id", task.GetId())
		return
	}
	RunAttackTask(sess, task)
	sess.Cleanup()

	DisplayRunTaskCompleted()
}

// SendStatusUpdate sends a status update to the server for a given task.
// It takes a hashcat.Status object and a pointer to a cipherswarm.Task object as parameters.
// The function first checks if the update.Time field is zero and sets it to the current time if it is.
// Then, it creates a list of cipherswarm.DeviceStatus objects based on the update.Devices field.
// Next, it creates a cipherswarm.HashcatGuess object based on the update.Guess field.
// After that, it creates a cipherswarm.TaskStatus object based on the update and the previously created objects.
// Finally, it submits the task status to the server using the apiClient.TasksAPI.SubmitStatus method.
// If there is an error during the submission, an error message is logged and the function returns.
// If the submission is successful, a debug message is logged.
func SendStatusUpdate(update hashcat.Status, task *cipherswarm.Task) {
	// TODO: Implement receiving a result code when sending this status update
	// Depending on the code, we should stop the job or pause it

	// Hashcat doesn't seem to update the time consistently, so we'll set it here
	if update.Time.IsZero() {
		update.Time = time.Now()
	}

	shared.Logger.Debug("Sending status update", "status", update)

	deviceStatuses := make([]cipherswarm.DeviceStatus, len(update.Devices))
	for i, device := range update.Devices {
		deviceStatus := *cipherswarm.NewDeviceStatus(
			device.DeviceID,
			device.DeviceName,
			device.DeviceType,
			device.Speed,
			device.Util,
			device.Temp)
		deviceStatuses[i] = deviceStatus
	}

	guess := *cipherswarm.NewHashcatGuess(
		update.Guess.GuessBase,
		update.Guess.GuessBaseCount,
		update.Guess.GuessBaseOffset,
		update.Guess.GuessModPercent,
		update.Guess.GuessMod,
		update.Guess.GuessModCount,
		update.Guess.GuessModOffset,
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
		shared.Logger.Error("Error sending status update", "error", err)
		return
	}
	// We'll do something with the status update responses at some point. Maybe tell the job to stop or pause.
	if httpRes.StatusCode == http.StatusNoContent {
		shared.Logger.Debug("Status update sent successfully")
	} else {
		shared.Logger.Error("Error sending status update", "response", httpRes)
	}
}

// AcceptTask accepts a task and returns a boolean indicating whether the task was accepted successfully.
// It sends an HTTP request to the API server to accept the task and handles the response accordingly.
func AcceptTask(task *cipherswarm.Task) bool {
	httpRes, err := apiClient.TasksAPI.AcceptTask(Context, task.GetId()).Execute()
	if err != nil {
		shared.Logger.Error("Error accepting task", "error", err)
		return false
	}

	if httpRes.StatusCode == http.StatusNoContent {
		shared.Logger.Debug("Task accepted")
		return true
	} else {
		if httpRes.StatusCode == http.StatusUnprocessableEntity {
			shared.Logger.Error("Task already completed", "task_id", task.GetId(), "status", httpRes)
			return false
		}
		shared.Logger.Error("Error accepting task", "response", httpRes)
		return false
	}
}

// MarkTaskExhausted marks a task as exhausted by notifying the server.
// It takes a pointer to a cipherswarm.Task as input.
// If an error occurs while notifying the server, it logs the error using the Logger.
func MarkTaskExhausted(task *cipherswarm.Task) {
	_, err := apiClient.TasksAPI.ExhaustedTask(Context, task.GetId()).Execute()
	if err != nil {
		shared.Logger.Error("Error notifying server", "error", err)
	}
}

// SendCrackedHash sends a cracked hash to the server.
// It takes a `hashcat.Result` object representing the cracked hash,
// and a pointer to a `cipherswarm.Task` object.
// It submits the crack result to the server using the API client,
// and logs any errors or successful responses.
func SendCrackedHash(hash hashcat.Result, task *cipherswarm.Task) {
	result := *cipherswarm.NewHashcatResult(hash.Timestamp, hash.Hash, hash.Plaintext)

	httpRes, err := apiClient.TasksAPI.SubmitCrack(Context, task.GetId()).
		HashcatResult(result).Execute()
	if err != nil {
		shared.Logger.Error("Error sending cracked hash", "error", err, "hash", hash.Hash)
		return
	}

	if httpRes.StatusCode == http.StatusOK || httpRes.StatusCode == http.StatusNoContent {
		shared.Logger.Debug("Cracked hash sent")
		if httpRes.StatusCode == http.StatusNoContent {
			shared.Logger.Info("Hashlist completed", "hash", hash.Hash)
		}
	} else {
		shared.Logger.Error("Error sending cracked hash", "response", httpRes)
	}

}

// downloadFile downloads a file from the specified URL and saves it to the given path.
// If a checksum is provided, it verifies the downloaded file against the checksum.
// If the file already exists and the checksum matches, it returns without downloading again.
// If the file already exists but the checksum does not match, it deletes the existing file and downloads a new one.
// It displays the progress of the download and completion status.
// Parameters:
//   - url: The URL of the file to download.
//   - path: The path where the downloaded file will be saved.
//   - checksum: The checksum to verify the downloaded file against (optional).
//
// Returns:
//   - error: An error if any occurred during the download or verification process, or nil if successful.
func downloadFile(url string, path string, checksum string) error {
	if fileutil.IsExist(path) {
		if checksum != "" {
			fileChecksum, err := cryptor.Md5File(path)
			if err != nil {
				return err
			}
			if fileChecksum == checksum {
				shared.Logger.Debug("Download already exists", "path", path)
				return nil
			}
			shared.Logger.Debug("Checksums do not match", "path", path)
			err = os.Remove(path)
			if err != nil {
				return err
			}
			return nil
		}
		shared.Logger.Info("Download already exists", "path", path)
		return nil
	}
	DisplayDownloadFile(url, path)
	_, err := req.SetTimeout(5*time.Second).
		SetCommonHeader("Accept", "application/json").
		SetCommonBearerAuthToken(shared.State.APIToken).
		R().
		SetOutputFile(path).
		SetDownloadCallbackWithInterval(func(info req.DownloadInfo) {
			if info.Response.Response != nil {
				DisplayDownloadFileStatusUpdate(info)
			}
		}, 1*time.Second).
		Get(url)
	if err != nil {
		return err
	}
	DisplayDownloadFileComplete(url, path)
	return nil
}

// extractHashcatArchive extracts a hashcat archive to the specified location.
// It removes the old hashcat backup directory, moves the old hashcat directory to a backup location,
// and then extracts the new hashcat directory using the 7z command.
// It returns the path of the extracted hashcat directory and any error encountered during the process.
func extractHashcatArchive(newArchivePath string) (string, error) {
	hashcatDirectory := path.Join(shared.State.CrackersPath, "hashcat")
	hashcatBackupDirectory := hashcatDirectory + "_old"
	// Get rid of the old hashcat backup directory
	err := os.RemoveAll(hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		shared.Logger.Error("Error removing old hashcat directory: ", "error", err)
		return "", err // Don't continue if we can't remove the old directory
	}

	// Move the old hashcat directory to a backup location
	err = os.Rename(hashcatDirectory, hashcatBackupDirectory)
	if err != nil && !os.IsNotExist(err) {
		shared.Logger.Error("Error moving old hashcat directory: ", "error", err)
		return "", err // Don't continue if we can't move the old directory
	}

	// Extract the new hashcat directory using the 7z command
	err = arch.Extract7z(newArchivePath, shared.State.CrackersPath)
	if err != nil {
		shared.Logger.Error("Error extracting file: ", "error", err)
		return "", err // Don't continue if we can't extract the file
	}
	return hashcatDirectory, err
}

// moveArchiveFile moves the archive file from the temporary path to a new path.
// It takes the temporary archive path as input and returns the new archive path and an error (if any).
// The function renames the file using the os.Rename function and logs any errors encountered.
// It also logs the old and new paths of the file after the move operation.
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
