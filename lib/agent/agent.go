// Package agent provides the main agent functionality for CipherSwarm.
package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/apierrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/benchmark"
	"github.com/unclesp1d3r/cipherswarmagent/lib/config"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/devices"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/task"
)

const (
	maxBenchmarkRetries = 10 // Stop retrying cached benchmark submission after this many failures
	// bgBenchStopTimeout bounds how long a reload/new-task waits for the previous
	// background-benchmark goroutine to exit (its hashcat proc.Wait() teardown)
	// before giving up. On expiry the restart is skipped to avoid two benchmark
	// processes contending for the GPU.
	bgBenchStopTimeout = 600 * time.Millisecond
)

// bgBenchHandle bundles a background-benchmark goroutine's cancel func with a
// done channel that is closed when the goroutine returns. Stored atomically so
// StartAgent (main goroutine) and the agent loop can coordinate without a race.
type bgBenchHandle struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Package-level managers — written once in StartAgent, then accessed exclusively
// from the agent-loop goroutine (startAgentLoop + handleReload). The single-goroutine
// invariant means no mutex is required, but these must NOT be accessed from the
// heartbeat goroutine or any other concurrent goroutine.
//
//nolint:gochecknoglobals // Package-level managers, initialized in StartAgent
var (
	benchmarkMgr *benchmark.Manager
	taskMgr      *task.Manager
	deviceMgr    *devices.DeviceManager
)

// bgBench holds the current background-benchmark goroutine handle. Unlike the
// managers above it is written from StartAgent before the loop starts and
// swapped from the loop goroutine, so it is synchronized with atomic.Pointer.
//
//nolint:gochecknoglobals // Synchronized background-benchmark lifecycle handle
var bgBench atomic.Pointer[bgBenchHandle]

// ErrAPIURLNotSet indicates the api_url configuration value is empty.
var ErrAPIURLNotSet = errors.New("API URL not set")

// ErrAPITokenNotSet indicates the api_token configuration value is empty.
var ErrAPITokenNotSet = errors.New("API token not set")

// validateAPICredentials checks that the API URL and token are present in shared
// state. It is read AFTER SetupSharedState (not via an early viper.GetString) so the
// values reflect the fully-loaded configuration. Returned as an error rather than a
// fatal call so the check is testable without exiting the process.
func validateAPICredentials() error {
	if agentstate.State.URL == "" {
		return ErrAPIURLNotSet
	}

	if agentstate.State.APIToken == "" {
		return ErrAPITokenNotSet
	}

	return nil
}

// setupAPIClient builds the shared circuit breaker and API client transport chain
// and stores the client in shared state. Fatal on construction failure.
func setupAPIClient() {
	circuitBreaker = api.NewCircuitBreaker(
		agentstate.State.CircuitBreakerFailureThreshold,
		agentstate.State.CircuitBreakerTimeout,
	)

	apiClient, err := api.NewAgentClient(
		agentstate.State.URL,
		agentstate.State.APIToken,
		transportConfigFromState(),
	)
	if err != nil {
		agentstate.Logger.Fatal("Failed to initialize API client", "error", err)
	}
	agentstate.State.SetAPIClient(apiClient)
}

// prepareWorkspace guards against a second instance, creates data directories and
// the lock file, and clears orphaned hashcat session files from previous runs.
// The caller is responsible for deferring cleanupLockFile.
func prepareWorkspace() {
	if cracker.CheckForExistingClient(agentstate.State.PidFile) {
		agentstate.Logger.Fatal("Aborting agent start, lock file found", "path", agentstate.State.PidFile)
	}

	if err := cracker.CreateDataDirs(); err != nil {
		agentstate.Logger.Fatal("Error creating data directories", "error", err)
	}

	if err := cracker.CreateLockFile(); err != nil {
		agentstate.Logger.Fatal("Error creating lock file", "error", err)
	}

	// On POSIX, the session directory is resolved from $HOME, not the binary path,
	// so cleanup works even when hashcat is not yet installed.
	binaryPath, binaryErr := cracker.FindHashcatBinary()
	if binaryErr != nil {
		agentstate.Logger.Debug("hashcat binary not found, using empty path for session cleanup", "error", binaryErr)
	}
	hashcat.CleanupOrphanedSessionFiles(binaryPath)
}

// setupDevicesAndMetadata enumerates compute devices and pushes agent metadata to
// the server. Device enumeration is warn-only (first run may precede hashcat
// install); metadata failure is fatal.
func setupDevicesAndMetadata(ctx context.Context) {
	deviceMgr = &devices.DeviceManager{}
	if dmErr := deviceMgr.EnumerateDevices(ctx, agentstate.State.HashcatPath); dmErr != nil {
		agentstate.Logger.Warn("Device enumeration failed, metadata will report no devices", "error", dmErr)
		deviceMgr = nil
	}
	SetMetadataProvider(deviceMgr)

	if err := UpdateAgentMetadata(ctx); err != nil {
		agentstate.Logger.Fatal("Failed to update agent metadata", "error", err)
	}

	agentstate.Logger.Info("Sent agent metadata to the CipherSwarm API")
}

// runBenchmarkPhase submits benchmarks at startup. When benchmarks are needed (or
// forced) it runs either quick capability detection (deferred mode) or a full
// benchmark; otherwise it marks benchmarks submitted from the server's valid cache.
func runBenchmarkPhase(ctx context.Context, benchmarksNeeded bool) {
	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityBenchmarking)
	forceBenchmark := agentstate.State.GetForceBenchmarkRun()

	if !benchmarksNeeded && !forceBenchmark {
		agentstate.Logger.Info("Server reports valid benchmarks on file, skipping benchmark run")
		agentstate.State.SetBenchmarksSubmitted(true)

		return
	}

	if forceBenchmark && !benchmarksNeeded {
		agentstate.Logger.Info("Force-benchmark flag set, overriding server benchmark status")
	}

	if agentstate.State.DeferBenchmarks && !forceBenchmark {
		// Deferred path: run quick capability detection instead of full benchmarks.
		agentstate.Logger.Info("Deferred benchmarks enabled: running quick capability detection")

		capResults, capErr := benchmarkMgr.RunCapabilityDetection(ctx)
		if capErr != nil {
			agentstate.Logger.Fatal("Capability detection failed", "error", capErr)
		}

		if len(capResults) == 0 {
			agentstate.Logger.Fatal("Capability detection returned no hash types; " +
				"check GPU drivers and hashcat installation")
		}

		if submitErr := benchmarkMgr.SubmitCapabilityResults(ctx, capResults); submitErr != nil {
			agentstate.Logger.Fatal("Failed to submit capability detection results", "error", submitErr)
		}

		return
	}

	// Full benchmark path.
	if err := benchmarkMgr.UpdateBenchmarks(ctx); err != nil {
		agentstate.Logger.Fatal("Failed to submit initial benchmarks", "error", err)
	}
}

// StartAgent initializes and starts the CipherSwarm agent.
func StartAgent() {
	config.SetupSharedState()
	initLogger()

	if err := validateAPICredentials(); err != nil {
		agentstate.Logger.Fatal("Missing required API configuration", "error", err)
	}

	setupAPIClient()
	display.Startup()

	prepareWorkspace()
	defer cleanupLockFile(agentstate.State.PidFile)

	// Context that cancels on OS signal; manual cancel lets heartbeat StateError shut down.
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	if err := AuthenticateAgent(ctx); err != nil {
		agentstate.Logger.Fatal("Failed to authenticate with the CipherSwarm API", "error", err)
	}
	display.Authenticated()

	if err := fetchAgentConfig(ctx); err != nil {
		agentstate.Logger.Fatal("Failed to fetch agent configuration", "error", err)
	}
	if err := rebuildAPIClient(); err != nil {
		agentstate.Logger.Fatal("Failed to rebuild API client with server settings", "error", err)
	}

	setupDevicesAndMetadata(ctx)

	// Start heartbeat loop early so the UI can see the agent is connected.
	go startHeartbeatLoop(ctx, cancel)

	benchmarksNeeded := initManagers()
	runBenchmarkPhase(ctx, benchmarksNeeded)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityStarting)

	if cracker.CheckForExistingClient(agentstate.State.HashcatPidFile) {
		agentstate.Logger.Info("Killed dangling hashcat process")
	}

	// Launch background benchmarking BEFORE the loop so the bgBench handle is stored
	// (atomically) before the loop goroutine can read it on reload/new-task.
	startBackgroundBenchmarks(ctx)
	go startAgentLoop(ctx)

	// Wait for context cancellation (OS signal or heartbeat StateError), then shut down.
	<-ctx.Done()
	agentstate.Logger.Debug("Agent context cancelled, shutting down")
	// Use context.Background() for shutdown messages — must complete even after cancellation.
	cserrors.SendAgentError(context.Background(), "Received signal to terminate. Shutting down", nil, api.SeverityInfo)
	SendAgentShutdown(context.Background())
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

// agentIsIdle reports whether the agent is currently waiting (idle), reading the
// shared activity state. It is injected into background benchmarking so lib/benchmark
// does not read agentstate directly for activity.
func agentIsIdle() bool {
	return agentstate.State.GetCurrentActivity() == agentstate.CurrentActivityWaiting
}

// startBackgroundBenchmarks launches the background-benchmark goroutine when
// deferred idle benchmarking is enabled, recording a handle (cancel + done) so a
// later reload or new task can stop it deterministically. No-op when disabled.
func startBackgroundBenchmarks(ctx context.Context) {
	if !agentstate.State.DeferBenchmarks || !agentstate.State.BenchmarkWhileIdle {
		return
	}

	//nolint:gosec // G118 - cancel stored in bgBench handle, invoked by stopBackgroundBenchmarks
	bgCtx, bgCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	bgBench.Store(&bgBenchHandle{cancel: bgCancel, done: done})

	// Capture the manager in the agent-loop goroutine so the background goroutine
	// does not read the package-level benchmarkMgr (which handleReload reassigns) —
	// otherwise a reload during a still-running benchmark would race the read.
	mgr := benchmarkMgr
	go func() {
		defer close(done)
		mgr.RunBackgroundBenchmarks(bgCtx, agentIsIdle)
	}()
}

// stopBackgroundBenchmarks cancels the running background-benchmark goroutine (if
// any) and waits, bounded by bgBenchStopTimeout, for it to exit. It returns true
// when it is safe to start a new background benchmark. On timeout it returns false
// so the caller skips the restart — the old goroutine may still hold a live hashcat
// process, and overlapping two would contend for the GPU.
func stopBackgroundBenchmarks() bool {
	handle := bgBench.Swap(nil)
	if handle == nil {
		return true
	}

	handle.cancel()

	timer := time.NewTimer(bgBenchStopTimeout)
	defer timer.Stop()

	select {
	case <-handle.done:
		return true
	case <-timer.C:
		agentstate.Logger.Warn(
			"Background benchmark did not stop within timeout; skipping restart to avoid GPU overlap")
		return false
	}
}

// initManagers rebuilds the benchmark and task managers from the current API
// client, server configuration, and the package-level deviceMgr — wiring
// DeviceConfig and task.Config. Shared by StartAgent and handleReload. It reads
// agentstate (the single legitimate reader) and returns whether the server says
// benchmarks are needed.
func initManagers() bool {
	client := agentstate.State.GetAPIClient()
	cfg := getConfiguration()
	dc := devices.NewDeviceConfig(cfg.Config.BackendDevices, cfg.Config.OpenCLDevices, deviceMgr)

	benchmarkMgr = benchmark.NewManager(client.Agents())
	benchmarkMgr.DeviceConfig = dc
	benchmarkMgr.Config = benchmark.Config{
		OutPath:                   agentstate.State.OutPath,
		ZapsPath:                  agentstate.State.ZapsPath,
		RetainZapsOnCompletion:    agentstate.State.RetainZapsOnCompletion,
		EnableAdditionalHashTypes: agentstate.State.EnableAdditionalHashTypes,
	}

	taskMgr = task.NewManager(client.Tasks(), client.Attacks())
	taskMgr.DeviceConfig = dc
	taskMgr.Config = task.Config{
		HashlistPath:           agentstate.State.HashlistPath,
		RestoreFilePath:        agentstate.State.RestoreFilePath,
		FilePath:               agentstate.State.FilePath,
		OutPath:                agentstate.State.OutPath,
		ZapsPath:               agentstate.State.ZapsPath,
		StatusTimer:            agentstate.State.StatusTimer,
		RetainZapsOnCompletion: agentstate.State.RetainZapsOnCompletion,
	}

	// Log warnings for unrecognized device IDs.
	dc.WarnInvalidDevices(agentstate.Logger.Warn)

	return cfg.BenchmarksNeeded
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
	// Defensive shift cap: even if the config clamp were bypassed, the shift can
	// never overflow time.Duration into a negative value.
	multiplier = min(multiplier, config.MaxBackoffShift)
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
		baseInterval := time.Duration(getConfiguration().Config.AgentUpdateInterval) * time.Second

		if err != nil {
			consecutiveFailures++
			backoff := calculateHeartbeatBackoff(baseInterval, consecutiveFailures, maxBackoffMultiplier)

			if apierrors.IsCircuitOpen(err) {
				agentstate.Logger.Warn("Circuit breaker open, server appears unresponsive",
					"failures", consecutiveFailures, "next_retry", backoff)
			} else {
				agentstate.Logger.Warn("Heartbeat failed, backing off",
					"failures", consecutiveFailures, "next_retry", backoff)
			}

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

		sleepTime := time.Duration(getConfiguration().Config.AgentUpdateInterval) * time.Second
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

	if err := rebuildAPIClient(); err != nil {
		agentstate.Logger.Error("Failed to rebuild API client during reload, skipping reload", "error", err)
		cserrors.SendAgentError(ctx, "Failed to rebuild API client during reload", nil, api.SeverityFatal)
		agentstate.State.SetReload(false)

		return
	}

	// Cancel any running background benchmark goroutine before replacing the manager.
	// canRestartBg is false if the old goroutine did not stop in time, in which case
	// the restart below is skipped to avoid overlapping GPU work.
	canRestartBg := stopBackgroundBenchmarks()

	// Re-enumerate devices in case hashcat was upgraded or drivers changed.
	// Always create a fresh DeviceManager so stale device data is never reused.
	deviceMgr = &devices.DeviceManager{}
	if dmErr := deviceMgr.EnumerateDevices(ctx, agentstate.State.HashcatPath); dmErr != nil {
		agentstate.Logger.Warn(
			"Device re-enumeration failed during reload, managers will have no device data",
			"error",
			dmErr,
		)
		deviceMgr = nil
	}
	SetMetadataProvider(deviceMgr)

	// Recreate managers with new API client sub-clients and updated configs.
	benchmarksNeeded := initManagers()

	if benchmarksNeeded {
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityBenchmarking)
		// Server-initiated reload must re-run benchmarks (not use stale cache).
		// Use defer to ensure the flag is always reset even if UpdateBenchmarks panics.
		agentstate.State.SetForceBenchmarkRun(true)
		defer func() { agentstate.State.SetForceBenchmarkRun(false) }()
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
	} else {
		agentstate.Logger.Warn("Server reports valid benchmarks on file during reload, skipping benchmark re-run")
		agentstate.State.SetBenchmarksSubmitted(true)
	}

	// Restart background benchmarking if deferred mode is active and the prior
	// goroutine stopped cleanly (canRestartBg). If it timed out, skip the restart.
	if canRestartBg {
		startBackgroundBenchmarks(ctx)
	}

	agentstate.State.SetReload(false)
}

func handleNewTask(ctx context.Context) {
	if !agentstate.State.GetBenchmarksSubmitted() {
		agentstate.Logger.Debug("Benchmarks not yet submitted, skipping task retrieval")
		return
	}

	// Cancel background benchmarks while a task is running to avoid device contention.
	canRestartBg := stopBackgroundBenchmarks()

	newTask, err := taskMgr.GetNewTask(ctx)
	if err != nil {
		if errors.Is(err, task.ErrNoTaskAvailable) {
			agentstate.Logger.Debug("No new task available")
			return
		}

		if apierrors.IsCircuitOpen(err) {
			agentstate.Logger.Warn("Circuit breaker open, skipping task retrieval", "error", err)
		} else {
			agentstate.Logger.Error("Failed to get new task", "error", err)
		}
		sleepWithContext(ctx, agentstate.State.SleepOnFailure)

		return
	}

	if newTask != nil {
		processTask(ctx, newTask)
	}

	// Restart background benchmarks after the task completes, unless the prior
	// goroutine did not stop cleanly above.
	if canRestartBg {
		startBackgroundBenchmarks(ctx)
	}
}

func processTask(ctx context.Context, t *api.Task) {
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

		return
	}

	// cleanupFiles removes this attack's local hashlist and restore files.
	cleanupFiles := func() {
		task.CleanupTaskFiles(attack.Id, taskMgr.Config.HashlistPath, taskMgr.Config.RestoreFilePath)
	}

	display.NewAttack(attack)

	err = taskMgr.AcceptTask(ctx, t)
	if err != nil {
		agentstate.Logger.Error("Failed to accept task", "task_id", t.Id, "error", err)
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)

		if errors.Is(err, task.ErrTaskAcceptNotFound) {
			// Task vanished before we could accept it — normal race condition.
			// No server state transition needed; just clean up local files.
			cleanupFiles()

			return
		}

		//nolint:contextcheck // must-complete: prevents task starvation on server
		taskMgr.AbandonTask(context.Background(), t)
		cleanupFiles()
		sleepWithContext(ctx, agentstate.State.SleepOnFailure)

		return
	}

	display.RunTaskAccepted(t)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityDownloading)

	if err := task.DownloadFiles(ctx, attack, taskMgr.Config.FilePath); err != nil {
		agentstate.Logger.Error("Failed to download files", "error", err)
		cserrors.SendAgentError(ctx, err.Error(), t, api.SeverityFatal)
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
		//nolint:contextcheck // must-complete: prevents task starvation on server
		taskMgr.AbandonTask(context.Background(), t)
		cleanupFiles()
		sleepWithContext(ctx, agentstate.State.SleepOnFailure)

		return
	}

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityCracking)

	if err := taskMgr.RunTask(ctx, t, attack); err != nil {
		// Note: RunTask returns nil from runAttackTask (which handles its own
		// cleanup via sess.Cleanup()). This fallback only triggers for
		// NewHashcatSession failures.
		agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
		cleanupFiles()

		return
	}

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)
}

// heartbeat sends a heartbeat to the server and processes the response.
// It returns an error if the heartbeat failed. On StateError, it calls cancel
// to initiate agent shutdown.
func heartbeat(ctx context.Context, cancel context.CancelFunc) error {
	if agentstate.State.ExtraDebugging {
		agentstate.Logger.Debug("Sending heartbeat")
	}

	state, err := SendHeartBeat(ctx)
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
	err := GetAgentConfiguration(ctx)
	if err != nil {
		return fmt.Errorf("failed to get agent configuration from the CipherSwarm API: %w", err)
	}

	// This read-modify-write is safe because fetchAgentConfig is only called
	// from the single agent-loop goroutine. If this changes, use a mutex or CAS.
	if agentstate.State.AlwaysUseNativeHashcat {
		fetchedCfg := getConfiguration()
		fetchedCfg.Config.UseNativeHashcat = true
		SetConfiguration(fetchedCfg)
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
