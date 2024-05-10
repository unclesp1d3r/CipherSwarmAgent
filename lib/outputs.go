package lib

import (
	"fmt"
	"time"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"

	"github.com/duke-git/lancet/mathutil"
	"github.com/dustin/go-humanize"

	"github.com/duke-git/lancet/strutil"
	"github.com/imroc/req/v3"
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
	shared.Logger.Info("New attack started", "attack_id", attack.GetID(), "attack_type", attack.GetAttackMode())
}

// DisplayInactive displays a message when the agent is inactive and sleeping
func DisplayInactive(sleepTime time.Duration) {
	shared.Logger.Info("Sleeping", "seconds", sleepTime)
}

// DisplayShuttingDown displays a message when the agent is shutting down
func DisplayShuttingDown() {
	shared.Logger.Info("Shutting down CipherSwarm Agent")
}

// DisplayBenchmark displays the results of a benchmark
func DisplayBenchmark(result BenchmarkResult) {
	shared.Logger.Info("Benchmark result", "device", result.Device,
		"hash_type", result.HashType, "runtime_ms", result.RuntimeMs, "speed_hs", result.SpeedHs)
}

// DisplayBenchmarkError displays an error message from a benchmark
func DisplayBenchmarkError(stdErrLine string) {
	shared.Logger.Debug("Benchmark stderr", "line", strutil.RemoveNonPrintable(stdErrLine))
}

// DisplayJobFailed displays a message when a job session fails
func DisplayJobFailed(err error) {
	shared.Logger.Error("Job session failed", "error", err)
}

// DisplayJobExhausted displays a message when a job session is exhausted
func DisplayJobExhausted() {
	shared.Logger.Info("Job session exhausted", "status", "exhausted")
}

// DisplayJobCrackedHash displays a message when a job session cracks a hash
func DisplayJobCrackedHash(crackedHash hashcat.Result) {
	shared.Logger.Debug("Job cracked hash", "hash", crackedHash)
}

// DisplayJobError displays an error message from a job session
func DisplayJobError(stdErrLine string) {
	shared.Logger.Debug("Job stderr", "line", strutil.RemoveNonPrintable(stdErrLine))
}

// DisplayJobStatus displays a status update from a job session
func DisplayJobStatus(update hashcat.Status) {
	shared.Logger.Debug("Job status update", "status", update)
	relativeProgress := mathutil.Percent(float64(update.Progress[0]), float64(update.Progress[1]), 2)

	var speedSum int64
	for _, device := range update.Devices {
		speedSum += device.Speed
	}

	progressText := fmt.Sprintf("%.2f%%", relativeProgress)
	speedText := humanize.SI(float64(speedSum), "H/s")
	hashesText := fmt.Sprintf("%v", len(update.RecoveredHashes))

	shared.Logger.Info("Progress update", "progress", progressText, "speed", speedText, "cracked_hashes", hashesText)
}

// DisplayAgentMetadataUpdated displays the results of a job session
func DisplayAgentMetadataUpdated(result *operations.UpdateAgentResponse) {
	shared.Logger.Info("Agent metadata updated with the CipherSwarm API", "agent_id", shared.State.AgentID)
	shared.Logger.Debug("Agent metadata", "metadata", result)
}

// DisplayNewCrackerAvailable displays information about a new cracker available.
// It logs the latest version and the download URL of the new cracker.
func DisplayNewCrackerAvailable(result *components.CrackerUpdate) {
	shared.Logger.Info("New cracker available", "latest_version", result.GetLatestVersion())
	shared.Logger.Info("Download URL", "url", result.GetDownloadURL())
}

// DisplayBenchmarkStarting displays a message indicating that benchmarking is starting.
func DisplayBenchmarkStarting() {
	shared.Logger.Info("Performing benchmarks")
}

// DisplayBenchmarksComplete displays the completed benchmark session results.
// It takes a slice of BenchmarkResult as input and logs the results using the Logger.
func DisplayBenchmarksComplete(benchmarkResult []BenchmarkResult) {
	shared.Logger.Debug("Benchmark session completed", "results", benchmarkResult)
}

// DisplayDownloadFileStart displays a log message indicating the start of file downloading for an attack.
func DisplayDownloadFileStart(attack *components.Attack) {
	shared.Logger.Info("Downloading files for attack", "attack_id", attack.GetID())
}

// DisplayDownloadFileComplete displays a message indicating that a file has been downloaded.
// It logs the URL and path of the downloaded file.
func DisplayDownloadFileComplete(url string, path string) {
	shared.Logger.Debug("Downloaded file", "url", url, "path", path)
}

// DisplayDownloadFileStatusUpdate displays the download file status update.
// It calculates the percentage of the downloaded file and logs it using the Logger.
func DisplayDownloadFileStatusUpdate(info req.DownloadInfo) {
	shared.Logger.Infof("downloaded %.2f%%\n", float64(info.DownloadedSize)/float64(info.Response.ContentLength)*100.0)
}

// DisplayDownloadFile downloads a file from the specified URL and saves it to the given path.
func DisplayDownloadFile(url string, path string) {
	shared.Logger.Info("Downloading file", "url", url, "path", path)
}

// DisplayRunTaskCompleted displays a message indicating that the attack has completed.
func DisplayRunTaskCompleted() {
	shared.Logger.Info("Attack completed")
}

// DisplayRunTaskAccepted displays a log message indicating that a task has been accepted.
func DisplayRunTaskAccepted(task *components.Task) {
	shared.Logger.Info("Task accepted", "task_id", task.GetID())
}

// DisplayRunTaskStarting displays a log message indicating that a task is starting.
func DisplayRunTaskStarting(task *components.Task) {
	shared.Logger.Info("Running task", "task_id", task.GetID())
}
