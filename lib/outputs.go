package lib

import (
	"fmt"
	"time"

	"github.com/duke-git/lancet/v2/mathutil"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/dustin/go-humanize"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// Put all the functions that display output here so that they can be easily changed later

// DisplayStartup logs an informational message indicating that the CipherSwarm Agent is starting up.
func DisplayStartup() {
	shared.Logger.Info("Starting CipherSwarm Agent")
}

// DisplayAuthenticated logs an informational message indicating that the agent has successfully authenticated
// with the CipherSwarm API. This message serves as a confirmation that the authentication process was completed
// without errors and the agent is ready for further operations.
func DisplayAuthenticated() {
	shared.Logger.Info("Agent authenticated with the CipherSwarm API")
}

// DisplayNewTask logs the information about a new task.
// It uses the shared.Logger to output debug and info level logs.
// The debug log includes the entire task object, while the info log includes the task ID.
func DisplayNewTask(task *components.Task) {
	shared.Logger.Debug("New task available", "task", task)
	shared.Logger.Info("New task available", "task_id", task.GetID())
}

// DisplayNewAttack logs the details of a new attack using shared.Logger.
// It includes debug and info level logs with the attack parameters and attack ID, respectively.
func DisplayNewAttack(attack *components.Attack) {
	shared.Logger.Debug("Attack parameters", "attack", attack)
	shared.Logger.Info("New attack started", "attack_id", attack.GetID(), "attack_type", *attack.GetAttackMode())
}

// DisplayInactive logs a debug message indicating the system is sleeping for the specified duration.
// It uses the shared logger to output the message with the duration in seconds.
func DisplayInactive(sleepTime time.Duration) {
	shared.Logger.Debug("Sleeping", "seconds", sleepTime)
}

// DisplayShuttingDown logs an informational message indicating that the CipherSwarm Agent is shutting down.
func DisplayShuttingDown() {
	shared.Logger.Info("Shutting down CipherSwarm Agent")
}

// displayBenchmark logs the details of a benchmarkResult using the shared.Logger.
// It records the device name, hash type, runtime in milliseconds, and speed in hashes per second.
func displayBenchmark(result benchmarkResult) {
	shared.Logger.Info("Benchmark result", "device", result.Device,
		"hash_type", result.HashType, "runtime_ms", result.RuntimeMs, "speed_hs", result.SpeedHs)
}

// displayBenchmarkError logs a benchmark standard error line after removing non-printable characters.
// This function uses the shared.Logger object with a debug level to record the stderr line.
func displayBenchmarkError(stdErrLine string) {
	shared.Logger.Debug("Benchmark stderr", "line", strutil.RemoveNonPrintable(stdErrLine))
}

// displayJobFailed logs a job failure error message using the shared logger, including the error details.
func displayJobFailed(err error) {
	shared.Logger.Error("Job session failed", "error", err)
}

// displayJobExhausted logs an info message indicating the job session is exhausted along with the status "exhausted".
func displayJobExhausted() {
	shared.Logger.Info("Job session exhausted", "status", "exhausted")
}

// displayJobCrackedHash logs a cracked hash result at the debug level using the shared logger.
func displayJobCrackedHash(crackedHash hashcat.Result) {
	shared.Logger.Debug("Job cracked hash", "hash", crackedHash)
}

// displayJobError logs the job's standard error line after removing non-printable characters.
// Parameters:
// - stdErrLine: The line from the job's standard error output.
func displayJobError(stdErrLine string) {
	shared.Logger.Debug("Job stderr", "line", strutil.RemoveNonPrintable(stdErrLine))
}

// displayJobStatus logs the status of a job including progress, speed, and cracked hashes.
// It first logs the debug information of the status update received.
// Calculates and formats the relative progress of the job.
// Adjusts the progress text if there are multiple iterations of guesses to be made.
// Sums up the speed of all devices involved in the job and formats it as a human-readable string.
// Formats the number of recovered hashes.
// Finally, it logs the progress, speed, and number of cracked hashes as an informational log.
func displayJobStatus(update hashcat.Status) {
	shared.Logger.Debug("Job status update", "status", update)

	relativeProgress := mathutil.Percent(float64(update.Progress[0]), float64(update.Progress[1]), 2)
	progressText := fmt.Sprintf("%.2f%%", relativeProgress)

	if update.Guess.GuessBaseCount > 1 {
		progressText = fmt.Sprintf("%s for iteration %v of %v", progressText, update.Guess.GuessBaseOffset, update.Guess.GuessBaseCount)
	}

	speedSum := int64(0)
	for _, device := range update.Devices {
		speedSum += device.Speed
	}
	speedText := humanize.SI(float64(speedSum), "H/s")

	hashesText := fmt.Sprintf("%v of %v", update.RecoveredHashes[0], update.RecoveredHashes[1])

	shared.Logger.Info("Progress update", "progress", progressText, "speed", speedText, "cracked_hashes", hashesText)
}

// displayJobGetZap logs an informational message that new hashes are available and updates the job with the given task ID.
// It is used within the getZaps function to signal the initiation of updating a job with new hashes.
func displayJobGetZap(task *components.Task) {
	shared.Logger.Info("New hashes available, updating job", "task_id", task.GetID())
}

// displayAgentMetadataUpdated logs the success of the agent metadata update operation.
// It logs an informational message that the metadata update was successful, including the agent ID.
// A debug log is also created with the detailed updated metadata for further inspection.
func displayAgentMetadataUpdated(result *operations.UpdateAgentResponse) {
	shared.Logger.Info("Agent metadata updated with the CipherSwarm API", "agent_id", shared.State.AgentID)
	shared.Logger.Debug("Agent metadata", "metadata", result)
}

// displayNewCrackerAvailable logs information about a new cracker update available, including the latest version and download URL.
// Parameters:
// - result: A pointer to a CrackerUpdate object containing the information about the latest cracker update.
func displayNewCrackerAvailable(result *components.CrackerUpdate) {
	shared.Logger.Info("New cracker available", "latest_version", result.GetLatestVersion())
	shared.Logger.Info("Download URL", "url", result.GetDownloadURL())
}

// displayBenchmarkStarting logs a message indicating the start of benchmark tasks.
func displayBenchmarkStarting() {
	shared.Logger.Info("Performing benchmarks")
}

// displayBenchmarksComplete logs the completion of a benchmark session with the provided benchmark results.
func displayBenchmarksComplete(benchmarkResult []benchmarkResult) {
	shared.Logger.Debug("Benchmark session completed", "results", benchmarkResult)
}

// displayDownloadFileStart logs the start of the file download process for a provided attack.
// Parameters:
//   - attack (*components.Attack): Pointer to the Attack object containing details of the attack.
func displayDownloadFileStart(attack *components.Attack) {
	shared.Logger.Info("Downloading files for attack", "attack_id", attack.GetID())
}

// displayDownloadFileComplete logs an informational message indicating that a file download has been completed.
//
// Parameters:
// - url: The URL from which the file was downloaded.
// - path: The local file path where the downloaded file was saved.
//
// Actions:
// - Logs an information message including the URL and path of the completed download using the shared.Logger instance.
func displayDownloadFileComplete(url string, path string) {
	shared.Logger.Info("Downloaded file", "url", url, "path", path)
}

// displayDownloadFile logs the initiation of a file download with the provided URL and path.
//
// Parameters:
// - url: The URL from which the file is to be downloaded.
// - path: The local path where the file will be saved.
//
// Actions:
// - Logs an informational message indicating the start of the download process, including the URL and the path.
func displayDownloadFile(url string, path string) {
	shared.Logger.Info("Downloading file", "url", url, "path", path)
}

// displayRunTaskCompleted logs a completion message indicating that a task has finished running.
func displayRunTaskCompleted() {
	shared.Logger.Info("Attack completed")
}

// DisplayRunTaskAccepted logs the acceptance of a task by displaying the task ID using shared.Logger.
func DisplayRunTaskAccepted(task *components.Task) {
	shared.Logger.Info("Task accepted", "task_id", task.GetID())
}

// displayRunTaskStarting logs a message indicating that a task is starting.
// Parameters:
//   - task: A pointer to the Task object that is starting.
func displayRunTaskStarting(task *components.Task) {
	shared.Logger.Info("Running task", "task_id", task.GetID())
}
