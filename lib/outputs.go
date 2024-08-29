package lib

import (
	"fmt"
	"time"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"

	"github.com/duke-git/lancet/mathutil"
	"github.com/dustin/go-humanize"

	"github.com/duke-git/lancet/strutil"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// Put all the functions that display output here so that they can be easily changed later

// DisplayStartup displays a message when the agent starts up
func DisplayStartup() {
	shared.Logger.Info("Starting CipherSwarm Agent")
}

// DisplayAuthenticated displays a message when the agent is authenticated with the CipherSwarm API
func DisplayAuthenticated() {
	shared.Logger.Info("Agent authenticated with the CipherSwarm API")
}

// DisplayNewTask displays a message when a new task is available
func DisplayNewTask(task *components.Task) {
	shared.Logger.Debug("New task available", "task", task)
	shared.Logger.Info("New task available", "task_id", task.GetID())
}

// DisplayNewAttack displays a message when a new attack is started
func DisplayNewAttack(attack *components.Attack) {
	shared.Logger.Debug("Attack parameters", "attack", attack)
	shared.Logger.Info("New attack started", "attack_id", attack.GetID(), "attack_type", *attack.GetAttackMode())
}

// DisplayInactive displays a message when the agent is inactive and sleeping
func DisplayInactive(sleepTime time.Duration) {
	shared.Logger.Debug("Sleeping", "seconds", sleepTime)
}

// DisplayShuttingDown displays a message when the agent is shutting down
func DisplayShuttingDown() {
	shared.Logger.Info("Shutting down CipherSwarm Agent")
}

// displayBenchmark displays the results of a benchmark
func displayBenchmark(result benchmarkResult) {
	shared.Logger.Info("Benchmark result", "device", result.Device,
		"hash_type", result.HashType, "runtime_ms", result.RuntimeMs, "speed_hs", result.SpeedHs)
}

// displayBenchmarkError displays an error message from a benchmark
func displayBenchmarkError(stdErrLine string) {
	shared.Logger.Debug("Benchmark stderr", "line", strutil.RemoveNonPrintable(stdErrLine))
}

// displayJobFailed displays a message when a job session fails
func displayJobFailed(err error) {
	shared.Logger.Error("Job session failed", "error", err)
}

// displayJobExhausted displays a message when a job session is exhausted
func displayJobExhausted() {
	shared.Logger.Info("Job session exhausted", "status", "exhausted")
}

// displayJobCrackedHash displays a message when a job session cracks a hash
func displayJobCrackedHash(crackedHash hashcat.Result) {
	shared.Logger.Debug("Job cracked hash", "hash", crackedHash)
}

// displayJobError displays an error message from a job session
func displayJobError(stdErrLine string) {
	shared.Logger.Debug("Job stderr", "line", strutil.RemoveNonPrintable(stdErrLine))
}

// displayJobStatus displays a status update from a job session
func displayJobStatus(update hashcat.Status) {
	shared.Logger.Debug("Job status update", "status", update)
	relativeProgress := mathutil.Percent(float64(update.Progress[0]), float64(update.Progress[1]), 2)

	var speedSum int64
	for _, device := range update.Devices {
		speedSum += device.Speed
	}

	progressText := fmt.Sprintf("%.2f%%", relativeProgress)
	speedText := humanize.SI(float64(speedSum), "H/s")
	hashesText := fmt.Sprintf("%v of %v", update.RecoveredHashes[0], update.RecoveredHashes[1])

	if update.Guess.GuessBaseCount > 1 {
		// progressText = fmt.Sprintf("%.2f%%, iteration %v of %v", update.Guess.GuessBasePercent, update.Guess.GuessBaseOffset, update.Guess.GuessBaseCount)
		progressText = fmt.Sprintf("%s for iteration %v of %v", progressText, update.Guess.GuessBaseOffset, update.Guess.GuessBaseCount)

	}

	shared.Logger.Info("Progress update", "progress", progressText, "speed", speedText, "cracked_hashes", hashesText)
}

func displayJobGetZap(task *components.Task) {
	shared.Logger.Info("New hashes available, updating job", "task_id", task.GetID())
}

// displayAgentMetadataUpdated displays the results of a job session
func displayAgentMetadataUpdated(result *operations.UpdateAgentResponse) {
	shared.Logger.Info("Agent metadata updated with the CipherSwarm API", "agent_id", shared.State.AgentID)
	shared.Logger.Debug("Agent metadata", "metadata", result)
}

// displayNewCrackerAvailable displays information about a new cracker available.
// It logs the latest version and the download URL of the new cracker.
func displayNewCrackerAvailable(result *components.CrackerUpdate) {
	shared.Logger.Info("New cracker available", "latest_version", result.GetLatestVersion())
	shared.Logger.Info("Download URL", "url", result.GetDownloadURL())
}

// displayBenchmarkStarting displays a message indicating that benchmarking is starting.
func displayBenchmarkStarting() {
	shared.Logger.Info("Performing benchmarks")
}

// displayBenchmarksComplete displays the completed benchmark session results.
// It takes a slice of benchmarkResult as input and logs the results using the Logger.
func displayBenchmarksComplete(benchmarkResult []benchmarkResult) {
	shared.Logger.Debug("Benchmark session completed", "results", benchmarkResult)
}

// displayDownloadFileStart displays a log message indicating the start of file downloading for an attack.
func displayDownloadFileStart(attack *components.Attack) {
	shared.Logger.Info("Downloading files for attack", "attack_id", attack.GetID())
}

// displayDownloadFileComplete displays a message indicating that a file has been downloaded.
// It logs the URL and path of the downloaded file.
func displayDownloadFileComplete(url string, path string) {
	shared.Logger.Info("Downloaded file", "url", url, "path", path)
}

// DisplayDownloadFileStatusUpdate displays the download file status update.
// It calculates the percentage of the downloaded file and logs it using the Logger.

// displayDownloadFile downloads a file from the specified URL and saves it to the given path.
func displayDownloadFile(url string, path string) {
	shared.Logger.Info("Downloading file", "url", url, "path", path)
}

// displayRunTaskCompleted displays a message indicating that the attack has completed.
func displayRunTaskCompleted() {
	shared.Logger.Info("Attack completed")
}

// DisplayRunTaskAccepted displays a log message indicating that a task has been accepted.
func DisplayRunTaskAccepted(task *components.Task) {
	shared.Logger.Info("Task accepted", "task_id", task.GetID())
}

// displayRunTaskStarting displays a log message indicating that a task is starting.
func displayRunTaskStarting(task *components.Task) {
	shared.Logger.Info("Running task", "task_id", task.GetID())
}
