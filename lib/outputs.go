package lib

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/dustin/go-humanize"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/progress"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// Put all the functions that display output here so that they can be easily changed later

// DisplayStartup logs an informational message indicating the start of the CipherSwarm Agent.
func DisplayStartup() {
	shared.Logger.Info("Starting CipherSwarm Agent")
}

// DisplayAuthenticated logs an informational message indicating successful authentication with the CipherSwarm API.
func DisplayAuthenticated() {
	shared.Logger.Info("Agent authenticated with the CipherSwarm API")
}

// DisplayNewTask logs a new task as available using the shared.Logger instance.
// It outputs debug and info level logs with the complete task details and its ID, respectively.
func DisplayNewTask(task *components.Task) {
	shared.Logger.Debug("New task available", "task", task)
	shared.Logger.Info("New task available", "task_id", task.GetID())
}

// DisplayNewAttack logs debug and info level messages for a new attack.
// It logs attack parameters and information about the new attack initiation using shared.Logger.
func DisplayNewAttack(attack *components.Attack) {
	shared.Logger.Debug("Attack parameters", "attack", attack)
	shared.Logger.Info("New attack started", "attack_id", attack.GetID(), "attack_type", *attack.GetAttackMode())
}

// DisplayInactive logs a debug message with the provided sleepTime duration before the agent pauses its activity.
func DisplayInactive(sleepTime time.Duration) {
	shared.Logger.Debug("Sleeping", "seconds", sleepTime)
}

// DisplayShuttingDown logs an informational message indicating the shutdown of the CipherSwarm Agent.
func DisplayShuttingDown() {
	shared.Logger.Info("Shutting down CipherSwarm Agent")
}

// displayBenchmark logs the provided benchmark result using the shared Logger.
// The log includes the device, hash type, runtime in milliseconds, and speed in hashes per second.
func displayBenchmark(result benchmarkResult) {
	shared.Logger.Info("Benchmark result", "device", result.Device,
		"hash_type", result.HashType, "runtime_ms", result.RuntimeMs, "speed_hs", result.SpeedHs)
}

// displayBenchmarkError logs a debug-level message detailing a line of standard error output from a benchmark process.
func displayBenchmarkError(stdErrLine string) {
	shared.Logger.Debug("Benchmark stderr", "line", strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}

		return -1
	}, stdErrLine))
}

// displayJobFailed logs an error message indicating that a job session has failed using the shared logger.
func displayJobFailed(err error) {
	shared.Logger.Error("Job session failed", "error", err)
}

// displayJobExhausted logs a "Job session exhausted" message at the Info level with a status of "exhausted".
func displayJobExhausted() {
	shared.Logger.Info("Job session exhausted", "status", "exhausted")
}

// displayJobCrackedHash logs the cracked hash result using the shared logger.
func displayJobCrackedHash(crackedHash hashcat.Result) {
	shared.Logger.Debug("Job cracked hash", "hash", crackedHash)
}

// displayJobError logs a single line of standard error for a job after removing non-printable characters from the line.
func displayJobError(stdErrLine string) {
	shared.Logger.Debug("Job stderr", "line", strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}

		return -1
	}, stdErrLine))
}

// displayJobStatus logs the current status of a hashcat operation, including progress, speed, and cracked hashes.
func displayJobStatus(update hashcat.Status) {
	shared.Logger.Debug("Job status update", "status", update)

	relativeProgress := progress.CalculatePercentage(float64(update.Progress[0]), float64(update.Progress[1]))

	if update.Guess.GuessBaseCount > 1 {
		relativeProgress = fmt.Sprintf("%s for iteration %v of %v", relativeProgress, update.Guess.GuessBaseOffset, update.Guess.GuessBaseCount)
	}

	progressText := relativeProgress

	speedSum := int64(0)
	for _, device := range update.Devices {
		speedSum += device.Speed
	}

	speedText := humanize.SI(float64(speedSum), "H/s")

	hashesText := fmt.Sprintf("%v of %v", update.RecoveredHashes[0], update.RecoveredHashes[1])

	shared.Logger.Info("Progress update", "progress", progressText, "speed", speedText, "cracked_hashes", hashesText)
}

// displayAgentMetadataUpdated logs that the agent metadata has been updated using the CipherSwarm API.
// Logs relevant metadata and agent ID for debugging.
func displayAgentMetadataUpdated(result *operations.UpdateAgentResponse) {
	shared.Logger.Info("Agent metadata updated with the CipherSwarm API", "agent_id", shared.State.AgentID)
	shared.Logger.Debug("Agent metadata", "metadata", result)
}

// DisplayNewCrackerAvailable logs details about the newly available cracker, including the latest version and download URL.
func DisplayNewCrackerAvailable(result *components.CrackerUpdate) {
	shared.Logger.Info("New cracker available", "latest_version", result.GetLatestVersion())
	shared.Logger.Info("Download URL", "url", result.GetDownloadURL())
}

// displayBenchmarkStarting logs a message indicating that benchmark processes are starting.
func displayBenchmarkStarting() {
	shared.Logger.Info("Performing benchmarks")
}

// displayBenchmarksComplete logs the completion of a benchmark session along with the benchmark results.
func displayBenchmarksComplete(benchmarkResult []benchmarkResult) {
	shared.Logger.Debug("Benchmark session completed", "results", benchmarkResult)
}

// displayDownloadFileStart logs the start of the file download process for the provided attack.
func displayDownloadFileStart(attack *components.Attack) {
	shared.Logger.Info("Downloading files for attack", "attack_id", attack.GetID())
}

// displayRunTaskCompleted logs a message indicating that a task has been completed successfully.
func displayRunTaskCompleted() {
	shared.Logger.Info("Attack completed")
}

// DisplayRunTaskAccepted logs an informational message indicating that a task has been accepted, specifying the task ID.
func DisplayRunTaskAccepted(task *components.Task) {
	shared.Logger.Info("Task accepted", "task_id", task.GetID())
}

// displayRunTaskStarting logs a message indicating that a task is starting with the specified task ID.
func displayRunTaskStarting(task *components.Task) {
	shared.Logger.Info("Running task", "task_id", task.GetID())
}
