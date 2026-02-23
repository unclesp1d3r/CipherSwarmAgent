// Package display provides output and logging functions for the CipherSwarm agent.
package display

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/dustin/go-humanize"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/progress"
)

// MinStatusFields is the minimum number of elements required in hashcat status
// Progress and RecoveredHashes slices (current value and total).
const MinStatusFields = 2

// BenchmarkResult represents the outcome of a benchmark session.
type BenchmarkResult struct {
	Device     string `json:"device,omitempty"`     // Device is the name of the device used for the benchmark.
	HashType   string `json:"hash_type,omitempty"`  // HashType is the type of hash used for the benchmark.
	RuntimeMs  string `json:"runtime,omitempty"`    // RuntimeMs is the runtime of the benchmark in milliseconds.
	HashTimeMs string `json:"hash_time,omitempty"`  // HashTimeMs is the time taken to hash in milliseconds.
	SpeedHs    string `json:"hash_speed,omitempty"` // SpeedHs is the hash speed in hashes per second.
	Submitted  bool   `json:"submitted,omitempty"`  // Submitted indicates whether this result has been accepted by the server.
}

// Startup logs an informational message indicating the start of the CipherSwarm Agent.
func Startup() {
	agentstate.Logger.Info("Starting CipherSwarm Agent")
}

// Authenticated logs an informational message indicating successful authentication with the CipherSwarm API.
func Authenticated() {
	agentstate.Logger.Info("Agent authenticated with the CipherSwarm API")
}

// NewTask logs a new task as available using the agentstate.Logger instance.
// It outputs debug and info level logs with the complete task details and its ID, respectively.
func NewTask(task *api.Task) {
	agentstate.Logger.Debug("New task available", "task", task)
	agentstate.Logger.Info("New task available", "task_id", task.Id)
}

// NewAttack logs debug and info level messages for a new attack.
// It logs attack parameters and information about the new attack initiation using agentstate.Logger.
func NewAttack(attack *api.Attack) {
	agentstate.Logger.Debug("Attack parameters", "attack", attack)
	agentstate.Logger.Info("New attack started", "attack_id", attack.Id, "attack_type", attack.AttackMode)
}

// Inactive logs a debug message with the provided sleepTime duration before the agent pauses its activity.
func Inactive(sleepTime time.Duration) {
	agentstate.Logger.Debug("Sleeping", "seconds", sleepTime)
}

// ShuttingDown logs an informational message indicating the shutdown of the CipherSwarm Agent.
func ShuttingDown() {
	agentstate.Logger.Info("Shutting down CipherSwarm Agent")
}

// Benchmark logs the provided benchmark result using the shared Logger.
// The log includes the device, hash type, runtime in milliseconds, and speed in hashes per second.
func Benchmark(result BenchmarkResult) {
	agentstate.Logger.Info("Benchmark result", "device", result.Device,
		"hash_type", result.HashType, "runtime_ms", result.RuntimeMs, "speed_hs", result.SpeedHs)
}

// BenchmarkError logs a debug-level message detailing a line of standard error output from a benchmark process.
func BenchmarkError(stdErrLine string) {
	agentstate.Logger.Debug("Benchmark stderr", "line", strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}

		return -1
	}, stdErrLine))
}

// JobFailed logs an error message indicating that a job session has failed using the shared logger.
func JobFailed(err error) {
	agentstate.Logger.Error("Job session failed", "error", err)
}

// JobExhausted logs a "Job session exhausted" message at the Info level with a status of "exhausted".
func JobExhausted() {
	agentstate.Logger.Info("Job session exhausted", "status", "exhausted")
}

// JobCrackedHash logs the cracked hash result using the shared logger.
func JobCrackedHash(crackedHash hashcat.Result) {
	agentstate.Logger.Debug("Job cracked hash", "hash", crackedHash)
}

// JobError logs a single line of standard error for a job after removing non-printable characters from the line.
func JobError(stdErrLine string) {
	agentstate.Logger.Debug("Job stderr", "line", strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}

		return -1
	}, stdErrLine))
}

// JobStatus logs the current status of a hashcat operation, including progress, speed, and cracked hashes.
func JobStatus(update hashcat.Status) {
	agentstate.Logger.Debug("Job status update", "status", update)

	if len(update.Progress) < MinStatusFields {
		agentstate.Logger.Warn("JobStatus called with insufficient progress data",
			"progress_len", len(update.Progress))
		return
	}

	if len(update.RecoveredHashes) < MinStatusFields {
		agentstate.Logger.Warn("JobStatus called with insufficient recovered hashes data",
			"recovered_len", len(update.RecoveredHashes))
		return
	}

	relativeProgress := progress.CalculatePercentage(float64(update.Progress[0]), float64(update.Progress[1]))

	if update.Guess.GuessBaseCount > 1 {
		relativeProgress = fmt.Sprintf(
			"%s for iteration %v of %v",
			relativeProgress,
			update.Guess.GuessBaseOffset,
			update.Guess.GuessBaseCount,
		)
	}

	progressText := relativeProgress

	speedSum := int64(0)
	for _, device := range update.Devices {
		speedSum += device.Speed
	}

	speedText := humanize.SI(float64(speedSum), "H/s")

	hashesText := fmt.Sprintf("%v of %v", update.RecoveredHashes[0], update.RecoveredHashes[1])

	agentstate.Logger.Info(
		"Progress update",
		"progress",
		progressText,
		"speed",
		speedText,
		"cracked_hashes",
		hashesText,
	)
}

// AgentMetadataUpdated logs that the agent metadata has been updated using the CipherSwarm API.
// Logs relevant metadata and agent ID for debugging.
func AgentMetadataUpdated(result *api.UpdateAgentResponse) {
	agentstate.Logger.Info("Agent metadata updated with the CipherSwarm API", "agent_id", agentstate.State.AgentID)
	agentstate.Logger.Debug("Agent metadata", "metadata", result)
}

// NewCrackerAvailable logs details about the newly available cracker, including the latest version and download URL.
func NewCrackerAvailable(result *api.CrackerUpdate) {
	agentstate.Logger.Info("New cracker available", "latest_version", result.GetLatestVersion())
	agentstate.Logger.Info("Download URL", "url", result.GetDownloadURL())
}

// BenchmarkStarting logs a message indicating that benchmark processes are starting.
func BenchmarkStarting() {
	agentstate.Logger.Info("Performing benchmarks")
}

// BenchmarksComplete logs the completion of a benchmark session along with the benchmark results.
func BenchmarksComplete(benchmarkResults []BenchmarkResult) {
	agentstate.Logger.Debug("Benchmark session completed", "results", benchmarkResults)
}

// DownloadFileStart logs the start of the file download process for the provided attack.
func DownloadFileStart(attack *api.Attack) {
	agentstate.Logger.Info("Downloading files for attack", "attack_id", attack.Id)
}

// RunTaskCompleted logs a message indicating that a task has been completed successfully.
func RunTaskCompleted() {
	agentstate.Logger.Info("Attack completed")
}

// RunTaskAccepted logs an informational message indicating that a task has been accepted, specifying the task ID.
func RunTaskAccepted(task *api.Task) {
	agentstate.Logger.Info("Task accepted", "task_id", task.Id)
}

// RunTaskStarting logs a message indicating that a task is starting with the specified task ID.
func RunTaskStarting(task *api.Task) {
	agentstate.Logger.Info("Running task", "task_id", task.Id)
}
