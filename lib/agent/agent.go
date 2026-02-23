// Package agent provides the main agent functionality for CipherSwarm.
package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/benchmark"
	"github.com/unclesp1d3r/cipherswarmagent/lib/config"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/task"
)

const (
	maxBenchmarkRetries = 10 // Stop retrying cached benchmark submission after this many failures
)

//nolint:gochecknoglobals // Package-level managers, initialized in StartAgent
var (
	benchmarkMgr *benchmark.Manager
	taskMgr      *task.Manager
)

// StartAgent initializes and starts the CipherSwarm agent.
func StartAgent() {
	// Ensure API URL and token are set
	if viper.GetString("api_url") == "" {
		agentstate.Logger.Fatal("API URL not set")
	}

	if viper.GetString("api_token") == "" {
		agentstate.Logger.Fatal("API token not set")
	}

	// Initialize shared state and logger
	config.SetupSharedState()
	initLogger()

	// Initialize API client
	apiClient, err := api.NewAgentClient(agentstate.State.URL, agentstate.State.APIToken)
	if err != nil {
		agentstate.Logger.Fatal("Failed to initialize API client", "error", err)
	}
	agentstate.State.APIClient = apiClient

	display.Startup()

	// Set up signal handling for graceful shutdown
	signChan := make(chan os.Signal, 1)
	signal.Notify(signChan, os.Interrupt, syscall.SIGTERM)

	// Check for an existing lock file to prevent multiple instances
	if cracker.CheckForExistingClient(agentstate.State.PidFile) {
		agentstate.Logger.Fatal("Aborting agent start, lock file found", "path", agentstate.State.PidFile)
	}

	// Create necessary data directories and lock file
	if err := cracker.CreateDataDirs(); err != nil {
		agentstate.Logger.Fatal("Error creating data directories", "error", err)
	}

	if err := cracker.CreateLockFile(); err != nil {
		agentstate.Logger.Fatal("Error creating lock file", "error", err)
	}

	defer cleanupLockFile(agentstate.State.PidFile)

	// Authenticate with the CipherSwarm API
	if err := lib.AuthenticateAgent(); err != nil {
		agentstate.Logger.Fatal("Failed to authenticate with the CipherSwarm API", "error", err)
	}

	display.Authenticated()

	// Fetch agent configuration and update metadata
	if err := fetchAgentConfig(); err != nil {
		agentstate.Logger.Fatal("Failed to fetch agent configuration", "error", err)
	}

	err = lib.UpdateAgentMetadata()
	if err != nil {
		agentstate.Logger.Fatal("Failed to update agent metadata", "error", err)
	}

	agentstate.Logger.Info("Sent agent metadata to the CipherSwarm API")

	// Create cancellable context for graceful shutdown propagation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start heartbeat loop early so UI can see agent is connected
	go startHeartbeatLoop(ctx, signChan)

	// Initialize managers
	benchmarkMgr = benchmark.NewManager(agentstate.State.APIClient.Agents())
	benchmarkMgr.BackendDevices = lib.Configuration.Config.BackendDevices
	benchmarkMgr.OpenCLDevices = lib.Configuration.Config.OpenCLDevices

	taskMgr = task.NewManager(agentstate.State.APIClient.Tasks(), agentstate.State.APIClient.Attacks())
	taskMgr.BackendDevices = lib.Configuration.Config.BackendDevices
	taskMgr.OpenCLDevices = lib.Configuration.Config.OpenCLDevices

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityBenchmarking)
	if err := benchmarkMgr.UpdateBenchmarks(); err != nil {
		agentstate.Logger.Fatal("Failed to submit initial benchmarks", "error", err)
	}

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStarting)

	// Kill any dangling hashcat processes
	if cracker.CheckForExistingClient(agentstate.State.HashcatPidFile) {
		agentstate.Logger.Info("Killed dangling hashcat process")
	}

	// Start agent loop (heartbeat loop already started above)
	go startAgentLoop(ctx)

	// Wait for termination signal
	sig := <-signChan
	cancel() // Cancel context to signal goroutines
	agentstate.Logger.Debug("Received signal", "signal", sig)
	cserrors.SendAgentError("Received signal to terminate. Shutting down", nil, api.SeverityInfo)
	lib.SendAgentShutdown()
	display.ShuttingDown()
}

func cleanupLockFile(pidFile string) {
	agentstate.Logger.Debug("Cleaning up PID file", "path", pidFile)

	if err := os.Remove(pidFile); err != nil {
		if !os.IsNotExist(err) {
			agentstate.Logger.Error("Failed to remove PID file; manually remove it before next startup",
				"path", pidFile, "error", err)
		}
	}
}

// calculateHeartbeatBackoff computes the exponential backoff duration for heartbeat retries.
// The formula is: baseInterval * 2^min(failures, maxMultiplier)
// Negative values for failures or maxMultiplier are corrected to 0 with a warning log.
func calculateHeartbeatBackoff(
	baseInterval time.Duration,
	consecutiveFailures, maxBackoffMultiplier int,
) time.Duration {
	// Guard against negative values to prevent bit shift panic
	if maxBackoffMultiplier < 0 {
		agentstate.Logger.Warn("Negative maxBackoffMultiplier corrected to 0",
			"original_value", maxBackoffMultiplier)
		maxBackoffMultiplier = 0
	}
	if consecutiveFailures < 0 {
		agentstate.Logger.Warn("Negative consecutiveFailures corrected to 0",
			"original_value", consecutiveFailures)
		consecutiveFailures = 0
	}
	// Cap the multiplier to prevent overflow
	multiplier := min(consecutiveFailures, maxBackoffMultiplier)
	// Exponential backoff: baseInterval * 2^multiplier
	return baseInterval * time.Duration(1<<multiplier)
}

// sleepWithContext blocks for the given duration or until the context is cancelled.
// Returns true if the context was cancelled (caller should return).
func sleepWithContext(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return false
	case <-ctx.Done():
		return true
	}
}

// startHeartbeatLoop runs the heartbeat loop with exponential backoff on failures.
// On consecutive failures, it backs off exponentially up to a maximum multiplier.
func startHeartbeatLoop(ctx context.Context, signChan chan os.Signal) {
	consecutiveFailures := 0
	maxBackoffMultiplier := agentstate.State.MaxHeartbeatBackoff

	for {
		err := heartbeat(ctx, signChan)
		baseInterval := time.Duration(lib.Configuration.Config.AgentUpdateInterval) * time.Second

		if err != nil {
			consecutiveFailures++
			backoff := calculateHeartbeatBackoff(baseInterval, consecutiveFailures, maxBackoffMultiplier)
			agentstate.Logger.Warn("Heartbeat failed, backing off",
				"failures", consecutiveFailures, "next_retry", backoff)

			if sleepWithContext(ctx, backoff) {
				return
			}

			continue
		}

		if consecutiveFailures > 0 {
			agentstate.Logger.Info("Heartbeat recovered after failures", "failures", consecutiveFailures)
		}

		consecutiveFailures = 0

		if sleepWithContext(ctx, baseInterval) {
			return
		}
	}
}

func startAgentLoop(ctx context.Context) {
	benchmarkRetryFailures := 0

	for {
		// Retry cached benchmark submission if benchmarks haven't been submitted yet.
		// TrySubmitCachedBenchmarks is a no-op when force-benchmark flag is set.
		if !agentstate.State.GetBenchmarksSubmitted() {
			//nolint:contextcheck // callee lacks ctx param
			if benchmarkMgr.TrySubmitCachedBenchmarks() {
				benchmarkRetryFailures = 0
			} else if benchmarkRetryFailures < maxBenchmarkRetries {
				benchmarkRetryFailures++
				if benchmarkRetryFailures >= maxBenchmarkRetries {
					agentstate.Logger.Error(
						"Benchmark cache retry limit reached, will not retry until reload",
						"attempts", benchmarkRetryFailures,
					)
					//nolint:contextcheck // callee lacks ctx param
					cserrors.SendAgentError(
						fmt.Sprintf("Benchmark submission retry limit reached after %d attempts",
							benchmarkRetryFailures),
						nil,
						api.SeverityMajor,
					)
				}
			}
		}

		if agentstate.State.GetReload() {
			handleReload(ctx)
			benchmarkRetryFailures = 0 // Reset retry counter after reload
		}

		if !lib.Configuration.Config.UseNativeHashcat {
			handleCrackerUpdate(ctx)
		}

		if !agentstate.State.GetJobCheckingStopped() {
			handleNewTask(ctx)
		}

		sleepTime := time.Duration(lib.Configuration.Config.AgentUpdateInterval) * time.Second
		display.Inactive(sleepTime)

		if sleepWithContext(ctx, sleepTime) {
			return
		}
	}
}

func handleReload(_ context.Context) {
	//nolint:contextcheck // callee lacks ctx param
	cserrors.SendAgentError("Reloading config and performing new benchmark", nil, api.SeverityInfo)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStarting)
	agentstate.Logger.Info("Reloading agent")

	//nolint:contextcheck // callee lacks ctx param
	if err := fetchAgentConfig(); err != nil {
		agentstate.Logger.Error("Failed to fetch agent configuration, skipping reload", "error", err)
		//nolint:contextcheck // callee lacks ctx param
		cserrors.SendAgentError("Failed to fetch agent configuration", nil, api.SeverityFatal)
		agentstate.State.SetReload(false)

		return
	}

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityBenchmarking)
	// Update manager configs after reload
	benchmarkMgr.BackendDevices = lib.Configuration.Config.BackendDevices
	benchmarkMgr.OpenCLDevices = lib.Configuration.Config.OpenCLDevices
	taskMgr.BackendDevices = lib.Configuration.Config.BackendDevices
	taskMgr.OpenCLDevices = lib.Configuration.Config.OpenCLDevices
	// Server-initiated reload must re-run benchmarks (not use stale cache).
	// Use defer to ensure the flag is always reset even if UpdateBenchmarks panics.
	agentstate.State.ForceBenchmarkRun = true
	defer func() { agentstate.State.ForceBenchmarkRun = false }()
	//nolint:contextcheck // callee lacks ctx param
	if err := benchmarkMgr.UpdateBenchmarks(); err != nil {
		agentstate.Logger.Error("Benchmark update failed during reload, task processing paused",
			"error", err)
		//nolint:contextcheck // callee lacks ctx param
		cserrors.SendAgentError(
			"Benchmark update failed during reload: "+err.Error(),
			nil,
			api.SeverityMajor,
		)
	}
	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStarting)
	agentstate.State.SetReload(false)
}

func handleCrackerUpdate(ctx context.Context) {
	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityUpdating)

	lib.UpdateCracker(ctx)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStarting)
}

func handleNewTask(ctx context.Context) {
	if !agentstate.State.GetBenchmarksSubmitted() {
		agentstate.Logger.Debug("Benchmarks not yet submitted, skipping task retrieval")
		return
	}

	//nolint:contextcheck // callee lacks ctx param
	newTask, err := taskMgr.GetNewTask()
	if err != nil {
		if errors.Is(err, task.ErrNoTaskAvailable) {
			agentstate.Logger.Debug("No new task available")
			return
		}

		agentstate.Logger.Error("Failed to get new task", "error", err)
		sleepWithContext(ctx, agentstate.State.SleepOnFailure)

		return
	}

	if newTask != nil {
		_ = processTask(ctx, newTask) //nolint:errcheck // Ignore error, as it is already logged and we can continue
	}
}

func processTask(ctx context.Context, t *api.Task) error {
	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityCracking)

	display.NewTask(t)

	//nolint:contextcheck // callee lacks ctx param
	attack, err := taskMgr.GetAttackParameters(t.AttackId)
	if err != nil || attack == nil {
		agentstate.Logger.Error("Failed to get attack parameters", "error", err)

		errMsg := "attack parameters are nil"
		if err != nil {
			errMsg = err.Error()
		}

		//nolint:contextcheck // callee lacks ctx param
		cserrors.SendAgentError(errMsg, t, api.SeverityFatal)
		//nolint:contextcheck // callee lacks ctx param
		taskMgr.AbandonTask(t)
		sleepWithContext(ctx, agentstate.State.SleepOnFailure)

		if err != nil {
			return err
		}

		return errors.New("attack parameters are nil")
	}

	display.NewAttack(attack)

	//nolint:contextcheck // callee lacks ctx param
	err = taskMgr.AcceptTask(t)
	if err != nil {
		agentstate.Logger.Error("Failed to accept task", "task_id", t.Id)
		task.CleanupTaskFiles(attack.Id)

		return err
	}

	display.RunTaskAccepted(t)

	if err := task.DownloadFiles(ctx, attack); err != nil {
		agentstate.Logger.Error("Failed to download files", "error", err)
		//nolint:contextcheck // callee lacks ctx param
		cserrors.SendAgentError(err.Error(), t, api.SeverityFatal)
		//nolint:contextcheck // callee lacks ctx param
		taskMgr.AbandonTask(t)
		task.CleanupTaskFiles(attack.Id)
		sleepWithContext(ctx, agentstate.State.SleepOnFailure)

		return err
	}

	//nolint:contextcheck // callee lacks ctx param
	err = taskMgr.RunTask(t, attack)
	if err != nil {
		// Note: RunTask returns nil from runAttackTask (which handles its own
		// cleanup via sess.Cleanup()). This fallback only triggers for
		// NewHashcatSession failures.
		task.CleanupTaskFiles(attack.Id)

		return err
	}

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)

	return nil
}

// heartbeat sends a heartbeat to the server and processes the response.
// It returns an error if the heartbeat failed.
func heartbeat(ctx context.Context, signChan chan os.Signal) error {
	if agentstate.State.ExtraDebugging {
		agentstate.Logger.Debug("Sending heartbeat")
	}

	state, err := lib.SendHeartBeat(ctx)
	if err != nil {
		return err
	}

	if state == nil {
		// No state change needed (HTTP 204 or similar)
		return nil
	}

	if agentstate.State.ExtraDebugging {
		agentstate.Logger.Debug("Received heartbeat response", "state", state)
	}

	switch *state {
	case api.StatePending:
		if agentstate.State.GetCurrentActivity() != agentstate.CurrentActivityBenchmarking {
			agentstate.Logger.Info("Agent is pending, performing reload")
			agentstate.State.SetReload(true)
		}
	case api.StateStopped:
		if agentstate.State.GetCurrentActivity() != agentstate.CurrentActivityCracking {
			agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStopping)
			agentstate.Logger.Debug("Agent is stopped, stopping processing")

			if !agentstate.State.GetJobCheckingStopped() {
				agentstate.Logger.Warn(
					"Job checking stopped, per server directive. Waiting for further instructions.",
				)
			}

			agentstate.State.SetJobCheckingStopped(true)
		}
	case api.StateError:
		agentstate.Logger.Info("Agent is in error state, stopping processing")

		signChan <- syscall.SIGTERM
	}

	return nil
}

func fetchAgentConfig() error {
	err := lib.GetAgentConfiguration()
	if err != nil {
		return fmt.Errorf("failed to get agent configuration from the CipherSwarm API: %w", err)
	}

	if agentstate.State.AlwaysUseNativeHashcat {
		lib.Configuration.Config.UseNativeHashcat = true
	}

	return nil
}

func initLogger() {
	if agentstate.State.Debug {
		agentstate.Logger.SetLevel(log.DebugLevel)
		agentstate.Logger.SetReportCaller(true)
	} else {
		agentstate.Logger.SetLevel(log.InfoLevel)
	}
}
