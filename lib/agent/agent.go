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

// Package-level managers — written once in StartAgent, then accessed exclusively
// from the agent-loop goroutine (startAgentLoop + handleReload). The single-goroutine
// invariant means no mutex is required, but these must NOT be accessed from the
// heartbeat goroutine or any other concurrent goroutine.
//
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

	// Create context that cancels on OS signal (SIGINT, SIGTERM)
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Wrap with a manual cancel so heartbeat StateError can trigger shutdown
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	// Authenticate with the CipherSwarm API
	if err := lib.AuthenticateAgent(ctx); err != nil {
		agentstate.Logger.Fatal("Failed to authenticate with the CipherSwarm API", "error", err)
	}

	display.Authenticated()

	// Fetch agent configuration and update metadata
	if err := fetchAgentConfig(ctx); err != nil {
		agentstate.Logger.Fatal("Failed to fetch agent configuration", "error", err)
	}

	err = lib.UpdateAgentMetadata(ctx)
	if err != nil {
		agentstate.Logger.Fatal("Failed to update agent metadata", "error", err)
	}

	agentstate.Logger.Info("Sent agent metadata to the CipherSwarm API")

	// Start heartbeat loop early so UI can see agent is connected
	go startHeartbeatLoop(ctx, cancel)

	// Initialize managers
	benchmarkMgr = benchmark.NewManager(agentstate.State.APIClient.Agents())
	benchmarkMgr.BackendDevices = lib.Configuration.Config.BackendDevices
	benchmarkMgr.OpenCLDevices = lib.Configuration.Config.OpenCLDevices

	taskMgr = task.NewManager(agentstate.State.APIClient.Tasks(), agentstate.State.APIClient.Attacks())
	taskMgr.BackendDevices = lib.Configuration.Config.BackendDevices
	taskMgr.OpenCLDevices = lib.Configuration.Config.OpenCLDevices

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityBenchmarking)
	if err := benchmarkMgr.UpdateBenchmarks(ctx); err != nil {
		agentstate.Logger.Fatal("Failed to submit initial benchmarks", "error", err)
	}

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStarting)

	// Kill any dangling hashcat processes
	if cracker.CheckForExistingClient(agentstate.State.HashcatPidFile) {
		agentstate.Logger.Info("Killed dangling hashcat process")
	}

	// Start agent loop (heartbeat loop already started above)
	go startAgentLoop(ctx)

	// Wait for context cancellation (OS signal or heartbeat StateError)
	<-ctx.Done()
	agentstate.Logger.Debug("Agent context cancelled, shutting down")
	// Use context.Background() for shutdown messages — must complete even after cancellation
	cserrors.SendAgentError(context.Background(), "Received signal to terminate. Shutting down", nil, api.SeverityInfo)
	lib.SendAgentShutdown(context.Background())
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
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return false
	case <-ctx.Done():
		return true
	}
}

// startHeartbeatLoop runs the heartbeat loop with exponential backoff on failures.
// On consecutive failures, it backs off exponentially up to a maximum multiplier.
// cancel is invoked when the server reports StateError, triggering agent shutdown.
func startHeartbeatLoop(ctx context.Context, cancel context.CancelFunc) {
	consecutiveFailures := 0
	maxBackoffMultiplier := agentstate.State.MaxHeartbeatBackoff

	for {
		err := heartbeat(ctx, cancel)
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
			if benchmarkMgr.TrySubmitCachedBenchmarks(ctx) {
				benchmarkRetryFailures = 0
			} else if benchmarkRetryFailures < maxBenchmarkRetries {
				benchmarkRetryFailures++
				if benchmarkRetryFailures >= maxBenchmarkRetries {
					agentstate.Logger.Error(
						"Benchmark cache retry limit reached, will not retry until reload",
						"attempts", benchmarkRetryFailures,
					)
					cserrors.SendAgentError(
						ctx,
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

func handleReload(ctx context.Context) {
	cserrors.SendAgentError(ctx, "Reloading config and performing new benchmark", nil, api.SeverityInfo)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStarting)
	agentstate.Logger.Info("Reloading agent")

	if err := fetchAgentConfig(ctx); err != nil {
		agentstate.Logger.Error("Failed to fetch agent configuration, skipping reload", "error", err)
		cserrors.SendAgentError(ctx, "Failed to fetch agent configuration", nil, api.SeverityFatal)
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
	if err := benchmarkMgr.UpdateBenchmarks(ctx); err != nil {
		agentstate.Logger.Error("Benchmark update failed during reload, task processing paused",
			"error", err)
		cserrors.SendAgentError(
			ctx,
			"Benchmark update failed during reload: "+err.Error(),
			nil,
			api.SeverityMajor,
		)
	}
	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStarting)
	agentstate.State.SetReload(false)
}

func handleNewTask(ctx context.Context) {
	if !agentstate.State.GetBenchmarksSubmitted() {
		agentstate.Logger.Debug("Benchmarks not yet submitted, skipping task retrieval")
		return
	}

	newTask, err := taskMgr.GetNewTask(ctx)
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

	attack, err := taskMgr.GetAttackParameters(ctx, t.AttackId)
	if err != nil || attack == nil {
		agentstate.Logger.Error("Failed to get attack parameters", "error", err)

		errMsg := "attack parameters are nil"
		if err != nil {
			errMsg = err.Error()
		}

		cserrors.SendAgentError(ctx, errMsg, t, api.SeverityFatal)
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
		//nolint:contextcheck // must-complete: prevents task starvation on server
		taskMgr.AbandonTask(context.Background(), t)
		sleepWithContext(ctx, agentstate.State.SleepOnFailure)

		if err != nil {
			return err
		}

		return errors.New("attack parameters are nil")
	}

	display.NewAttack(attack)

	err = taskMgr.AcceptTask(ctx, t)
	if err != nil {
		agentstate.Logger.Error("Failed to accept task", "task_id", t.Id)
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
		//nolint:contextcheck // must-complete: prevents task starvation on server
		taskMgr.AbandonTask(context.Background(), t)
		task.CleanupTaskFiles(attack.Id)

		return err
	}

	display.RunTaskAccepted(t)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityDownloading)

	if err := task.DownloadFiles(ctx, attack); err != nil {
		agentstate.Logger.Error("Failed to download files", "error", err)
		cserrors.SendAgentError(ctx, err.Error(), t, api.SeverityFatal)
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
		//nolint:contextcheck // must-complete: prevents task starvation on server
		taskMgr.AbandonTask(context.Background(), t)
		task.CleanupTaskFiles(attack.Id)
		sleepWithContext(ctx, agentstate.State.SleepOnFailure)

		return err
	}

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityCracking)

	err = taskMgr.RunTask(ctx, t, attack)
	if err != nil {
		// Note: RunTask returns nil from runAttackTask (which handles its own
		// cleanup via sess.Cleanup()). This fallback only triggers for
		// NewHashcatSession failures.
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
		task.CleanupTaskFiles(attack.Id)

		return err
	}

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)

	return nil
}

// heartbeat sends a heartbeat to the server and processes the response.
// It returns an error if the heartbeat failed. On StateError, it calls cancel
// to initiate agent shutdown.
func heartbeat(ctx context.Context, cancel context.CancelFunc) error {
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

		cancel()
	}

	return nil
}

func fetchAgentConfig(ctx context.Context) error {
	err := lib.GetAgentConfiguration(ctx)
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
