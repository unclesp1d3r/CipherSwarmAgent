package lib

import (
	"crypto/md5" //nolint:gosec
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/spf13/afero"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
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

// TODO: Organize this into a proper API

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
		}
		return 0, errors.New("failed to authenticate with the CipherSwarm API")
	}
	Logger.Error("bad response: %v", resp)
	return 0, resp.Err
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
	clientSignature := fmt.Sprintf("CipherSwarm Agent/%s %s/%s", AgentVersion, info.OS, info.KernelArch)

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

	agentMetadata.OperatingSystem = info.OS

	resp, err := Client.R().SetBody(agentMetadata).Put("/agents/" + strconv.Itoa(agentID))
	if err != nil {
		Logger.Error("Error updating agent metadata", "error", err)
	}

	if resp.IsSuccessState() {
		Logger.Info("Agent metadata updated with the CipherSwarm API")
		Logger.Debug("Agent metadata", "metadata", agentMetadata)
	} else {
		Logger.Error("Error updating agent metadata ", "response", resp.String())
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
		if resp.StatusCode == 204 {
			Logger.Debug("No new cracker available")
			return
		}
		err := resp.Into(&updateCrackerResponse)
		if err != nil {
			Logger.Error("Error parsing response", "error", err, "response", resp.String())
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
		} else {
			Logger.Debug("No new cracker available", "latest_version", updateCrackerResponse.LatestVersion.Version)
		}
	} else {
		Logger.Error("Error checking for updated cracker: ", resp.String())
	}
}

func GetNewTask() (Task, error) {
	task := Task{}
	resp := Client.Get("/tasks/new").Do()

	if resp.Err != nil {
		return task, resp.Err
	}

	if resp.IsSuccessState() {
		if resp.StatusCode == 204 {
			task.Available = false
			return task, nil
		}
		err := resp.Into(&task)
		if err != nil {
			return task, err
		}

		task.Available = true
		return task, nil
	}
	return task, errors.New("bad response: " + resp.String())
}

func GetAttackParameters(attackID int) (AttackParameters, error) {
	attackParameters := AttackParameters{}
	resp := Client.Get("/attacks/" + strconv.Itoa(attackID)).Do()

	if resp.Err != nil {
		return attackParameters, resp.Err
	}

	if resp.IsSuccessState() {
		err := resp.Into(&attackParameters)
		if err != nil {
			return attackParameters, err
		}
		return attackParameters, nil
	}
	return attackParameters, errors.New("bad response: " + resp.String())
}

type BenchmarkResultResponse struct {
	Results []BenchmarkResult `json:"hashcat_benchmarks"`
}

func SendBenchmarkResults(agentID int, benchmarkResults []BenchmarkResult) error {
	results := BenchmarkResultResponse{
		Results: benchmarkResults,
	}
	resp, err := Client.R().SetBody(results).Post("/agents/" + strconv.Itoa(agentID) + "/submit_benchmark")
	if err != nil {
		return err
	}

	if resp.Err != nil {
		return resp.Err
	}

	if resp.IsSuccessState() {
		return nil
	}
	return errors.New("bad response: " + resp.String())
}

type benchmarkDateResponse struct {
	LastBenchmarkDate time.Time `json:"last_benchmark_date"`
}

func GetLastBenchmarkDate(agentID int) (time.Time, error) {
	lastBenchmarkDate := benchmarkDateResponse{}

	resp := Client.Get("/agents/" + strconv.Itoa(agentID) + "/last_benchmark").Do()
	if resp.Err != nil {
		return time.Time{}, resp.Err
	}

	if resp.IsSuccessState() {
		err := resp.Into(&lastBenchmarkDate)
		if err != nil {
			return time.Time{}, err
		}
		return lastBenchmarkDate.LastBenchmarkDate, nil
	}
	return time.Time{}, errors.New("bad response: " + resp.String())
}

func UpdateBenchmarks(agentID int) {
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

func DownloadFiles(attack AttackParameters) error {
	Logger.Info("Downloading files for attack", "attack_id", attack.ID)

	// Download the hashlist
	hashlistPath := path.Join(viper.GetString("hashlist_path"), strconv.Itoa(attack.HashListID)+".txt")
	Logger.Debug("Downloading hashlist", "url", attack.HashListURL, "path", hashlistPath)
	err := downloadFile(attack.HashListURL, hashlistPath, attack.HashListChecksum)
	if err != nil {
		Logger.Error("Error downloading hashlist", "error", err)
		return err
	}

	// Download the wordlists
	for _, wordlist := range attack.WordLists {
		wordlistPath := path.Join(viper.GetString("file_path"), wordlist.FileName)
		Logger.Debug("Downloading wordlist", "url", wordlist.DownloadURL, "path", wordlistPath)
		err := downloadFile(wordlist.DownloadURL, wordlistPath, wordlist.Checksum)
		if err != nil {
			Logger.Error("Error downloading wordlist", "error", err)
			return err
		}
	}

	// Download the rulelists
	for _, rulelist := range attack.RuleLists {
		rulelistPath := path.Join(viper.GetString("file_path"), rulelist.FileName)
		Logger.Debug("Downloading rulelist", "url", rulelist.DownloadURL, "path", rulelistPath)
		err := downloadFile(rulelist.DownloadURL, rulelistPath, rulelist.Checksum)
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
	_, err := Client.R().
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

func SendHeartBeat(agentID int) {
	resp, err := Client.R().Post("/agents/" + strconv.Itoa(agentID) + "/heartbeat")
	if err != nil {
		Logger.Error("Error sending heartbeat", "error", err)
		return
	}

	if resp.IsSuccessState() {
		Logger.Debug("Heartbeat sent")
	} else {
		Logger.Error("Error sending heartbeat", "response", resp.String())
	}

}

func RunTask(task Task, attack AttackParameters) {
	Logger.Info("Running task", "task_id", task.ID)
	// Create the hashcat session

	// TODO: Need to unify the AttackParameters and HashcatParams structs
	jobParams := hashcat.HashcatParams{
		AttackMode:         attack.GetAttackMode(),
		HashType:           uint(attack.HashMode),
		HashFile:           path.Join(viper.GetString("hashlist_path"), strconv.Itoa(attack.HashListID)+".txt"),
		Mask:               attack.Mask,
		MaskIncrement:      attack.IncrementMode,
		MaskIncrementMin:   uint(attack.IncrementMinimum),
		MaskIncrementMax:   uint(attack.IncrementMaximum),
		MaskShardedCharset: "",
		MaskCustomCharsets: nil,
		WordlistFilenames:  attack.GetWordlistFilenames(),
		RulesFilenames:     attack.GetRulelistFilenames(),
		AdditionalArgs:     arch.GetAdditionalHashcatArgs(),
		OptimizedKernels:   attack.Optimized,
		SlowCandidates:     attack.SlowCandidateGenerators,
		Skip:               task.Skip,
		Limit:              task.Limit,
	}

	sess, err := hashcat.NewHashcatSession("attack", jobParams)
	if err != nil {
		Logger.Error("Failed to create attack session", "error", err)
		return
	}

	Logger.Info("Running attack")
	if !AcceptTask(task) {
		Logger.Error("Failed to accept task", "task_id", task.ID)
		return
	}
	RunAttackTask(sess, task)

	Logger.Info("Attack completed")
}

func SendStatusUpdate(update hashcat.HashcatStatus, task Task) {
	// TODO: Implement receiving a result code when sending this status update
	// Depending on the code, we should stop the job or pause it

	// Hashcat doesn't seem to update the time consistently, so we'll set it here
	if update.Time.IsZero() {
		update.Time = time.Now()
	}

	Logger.Debug("Sending status update", "status", update)
	resp, err := Client.R().SetBody(update).Post("/tasks/" + strconv.Itoa(task.ID) + "/submit_status")
	if err != nil {
		Logger.Error("Error sending status update", "error", err)
		return
	}
	// We'll do something with the status update responses at some point. Maybe tell the job to stop or pause.
	if resp.IsSuccessState() {
		Logger.Debug("Status update sent successfully")
	} else {
		Logger.Error("Error sending status update", "response", resp.String())
	}
}

func AcceptTask(task Task) bool {
	resp, err := Client.R().Post("/tasks/" + strconv.Itoa(task.ID) + "/accept_task")
	if err != nil {
		Logger.Error("Error accepting task", "error", err)
		return false
	}

	if resp.IsSuccessState() {
		Logger.Debug("Task accepted")
		return true
	} else {
		if resp.StatusCode == 422 {
			Logger.Error("Task already completed", "task_id", task.ID, "status", resp.StatusCode)
			return false
		}
		Logger.Error("Error accepting task", "response", resp.String())
		return false
	}

}

func MarkTaskExhausted(task Task) {
	_, err := Client.R().Post("/tasks/" + strconv.Itoa(task.ID) + "/exhausted")
	if err != nil {
		Logger.Error("Error notifying server", "error", err)
	}

}

func SendCrackedHash(hash hashcat.HashcatResult, task Task) {
	// Send cracked hash to the server
	resp, err := Client.R().
		SetBody(hash).
		Post("/tasks/" + strconv.Itoa(task.ID) + "/submit_crack")
	if err != nil {
		Logger.Error("Error sending cracked hash", "error", err)
		return
	}

	if resp.IsSuccessState() {
		Logger.Debug("Cracked hash sent")
		if resp.StatusCode == 204 {
			Logger.Info("Hashlist completed", "hash", hash.Hash)
		}
	} else {
		Logger.Error("Error sending cracked hash", "response", resp.String())
	}

}
