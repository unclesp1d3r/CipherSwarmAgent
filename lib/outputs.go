package lib

import (
	"github.com/imroc/req/v3"
	"github.com/unclesp1d3r/cipherswarm-agent-go-api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
	"time"
)

// Put all the functions that display output here so that they can be easily changed later

// DisplayStartup displays a message when the agent starts up
func DisplayStartup() {
	Logger.Info("Starting CipherSwarm Agent")
}

// DisplayAuthenticated displays a message when the agent is authenticated with the CipherSwarm API
func DisplayAuthenticated() {
	Logger.Info("Agent authenticated with the CipherSwarm API")
}

// DisplayNewTask displays a message when a new task is available
func DisplayNewTask(task *cipherswarm.Task) {
	Logger.Info("New task available", "task", task)
}

// DisplayNewAttack displays a message when a new attack is started
func DisplayNewAttack(attack *cipherswarm.Attack) {
	Logger.Info("Attack parameters", "attack", attack)
}

// DisplayInactive displays a message when the agent is inactive and sleeping
func DisplayInactive(sleepTime time.Duration) {
	Logger.Info("Sleeping", "seconds", sleepTime)
}

// DisplayShuttingDown displays a message when the agent is shutting down
func DisplayShuttingDown() {
	Logger.Info("Shutting down CipherSwarm Agent")
}

// DisplayBenchmark displays the results of a benchmark
func DisplayBenchmark(result BenchmarkResult) {
	Logger.Info("Benchmark result", "device", result.Device,
		"hash_type", result.HashType, "runtime_ms", result.RuntimeMs, "speed_hs", result.SpeedHs)
}

// DisplayBenchmarkError displays an error message from a benchmark
func DisplayBenchmarkError(stdErrLine string) {
	Logger.Debug("Benchmark stderr", "line", CleanString(stdErrLine))
}

// DisplayJobFailed displays a message when a job session fails
func DisplayJobFailed(err error) {
	Logger.Error("Job session failed", "error", err)
}

// DisplayJobExhausted displays a message when a job session is exhausted
func DisplayJobExhausted() {
	Logger.Info("Job session exhausted", "status", "exhausted")
}

// DisplayJobCrackedHash displays a message when a job session cracks a hash
func DisplayJobCrackedHash(crackedHash hashcat.Result) {
	Logger.Debug("Job cracked hash", "hash", crackedHash)
}

// DisplayJobError displays an error message from a job session
func DisplayJobError(stdErrLine string) {
	Logger.Debug("Job stderr", "line", CleanString(stdErrLine))
}

// DisplayJobStatus displays a status update from a job session
func DisplayJobStatus(update hashcat.Status) {
	Logger.Debug("Job status update", "status", update)
}

func DisplayAgentMetadataUpdated(result *cipherswarm.Agent) {
	Logger.Info("Agent metadata updated with the CipherSwarm API", "agent_id", shared.SharedState.AgentID)
	Logger.Debug("Agent metadata", "metadata", result)
}

func DisplayNewCrackerAvailable(result *cipherswarm.CrackerUpdate) {
	Logger.Info("New cracker available", "latest_version", result.GetLatestVersion())
	Logger.Info("Download URL", "url", result.GetDownloadUrl())
}

func DisplayBenchmarkStarting() {
	Logger.Info("Performing benchmarks")
}

func DisplayBenchmarksComplete(benchmarkResult []BenchmarkResult) {
	Logger.Debug("Benchmark session completed", "results", benchmarkResult)
}

func DisplayDownloadFileStart(attack *cipherswarm.Attack) {
	Logger.Info("Downloading files for attack", "attack_id", attack.GetId())
}

func DisplayDownloadFileComplete(url string, path string) {
	Logger.Debug("Downloaded file", "url", url, "path", path)
}

func DisplayDownloadFileStatusUpdate(info req.DownloadInfo) {
	Logger.Infof("downloaded %.2f%%\n", float64(info.DownloadedSize)/float64(info.Response.ContentLength)*100.0)
}

func DisplayDownloadFile(url string, path string) {
	Logger.Info("Downloading file", "url", url, "path", path)
}

func DisplayRunTaskCompleted() {
	Logger.Info("Attack completed")
}

func DisplayRunTaskAccepted(task *cipherswarm.Task) {
	Logger.Info("Task accepted", "task_id", task.GetId())
}

func DisplayRunTaskStarting(task *cipherswarm.Task) {
	Logger.Info("Running task", "task_id", task.GetId())
}
