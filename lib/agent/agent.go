// Package agent provides the main agent functionality for CipherSwarm.
package agent

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/spf13/viper"
	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib"
	"github.com/unclesp1d3r/cipherswarmagent/lib/config"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
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
	agentstate.State.SdkClient = sdk.New(
		sdk.WithSecurity(agentstate.State.APIToken),
		sdk.WithServerURL(agentstate.State.URL),
	)

	lib.DisplayStartup()

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

	lib.DisplayAuthenticated()

	// Fetch agent configuration and update metadata
	if err := fetchAgentConfig(); err != nil {
		agentstate.Logger.Fatal("Failed to fetch agent configuration", "error", err)
	}

	err := lib.UpdateAgentMetadata()
	if err != nil {
		return // Error already logged
	}

	agentstate.Logger.Info("Sent agent metadata to the CipherSwarm API")

	// Start heartbeat loop early so UI can see agent is connected
	go startHeartbeatLoop(signChan)

	// Submit initial benchmarks to the server
	agentstate.State.CurrentActivity = agentstate.CurrentActivityBenchmarking
	if err := lib.UpdateBenchmarks(); err != nil {
		agentstate.Logger.Fatal("Failed to submit initial benchmarks", "error", err)
	}

	agentstate.State.CurrentActivity = agentstate.CurrentActivityStarting

	// Kill any dangling hashcat processes
	if cracker.CheckForExistingClient(agentstate.State.HashcatPidFile) {
		agentstate.Logger.Info("Killed dangling hashcat process")
	}

	// Start agent loop (heartbeat loop already started above)
	go startAgentLoop()

	// Wait for termination signal
	sig := <-signChan
	agentstate.Logger.Debug("Received signal", "signal", sig)
	lib.SendAgentError("Received signal to terminate. Shutting down", nil, operations.SeverityInfo)
	lib.SendAgentShutdown()
	lib.DisplayShuttingDown()
}

func cleanupLockFile(pidFile string) {
	agentstate.Logger.Debug("Cleaning up PID file", "path", pidFile)

	if err := os.Remove(pidFile); err != nil {
		if os.IsNotExist(err) {
			// PID file is already gone, nothing to clean up
			return
		}
		agentstate.Logger.Error("Failed to remove PID file", "error", err)
	}
}

func startHeartbeatLoop(signChan chan os.Signal) {
	for {
		heartbeat(signChan)
		// Use the same interval as the agent update interval from server configuration
		sleepTime := time.Duration(lib.Configuration.Config.AgentUpdateInterval) * time.Second
		time.Sleep(sleepTime)
	}
}

func startAgentLoop() {
	for {
		if agentstate.State.Reload {
			handleReload()
		}

		if !lib.Configuration.Config.UseNativeHashcat {
			handleCrackerUpdate()
		}

		if !agentstate.State.JobCheckingStopped {
			handleNewTask()
		}

		sleepTime := time.Duration(lib.Configuration.Config.AgentUpdateInterval) * time.Second
		lib.DisplayInactive(sleepTime)
		time.Sleep(sleepTime)
	}
}

func handleReload() {
	lib.SendAgentError("Reloading config and performing new benchmark", nil, operations.SeverityInfo)

	agentstate.State.CurrentActivity = agentstate.CurrentActivityStarting
	agentstate.Logger.Info("Reloading agent")

	if err := fetchAgentConfig(); err != nil {
		agentstate.Logger.Error("Failed to fetch agent configuration", "error", err)
		lib.SendAgentError("Failed to fetch agent configuration", nil, operations.SeverityFatal)
	}

	agentstate.State.CurrentActivity = agentstate.CurrentActivityBenchmarking
	_ = lib.UpdateBenchmarks() //nolint:errcheck // Ignore error, as it is already logged and we can continue
	agentstate.State.CurrentActivity = agentstate.CurrentActivityStarting
	agentstate.State.Reload = false
}

func handleCrackerUpdate() {
	agentstate.State.CurrentActivity = agentstate.CurrentActivityUpdating

	lib.UpdateCracker()

	agentstate.State.CurrentActivity = agentstate.CurrentActivityStarting
}

func handleNewTask() {
	if !agentstate.State.BenchmarksSubmitted {
		agentstate.Logger.Debug("Benchmarks not yet submitted, skipping task retrieval")
		return
	}

	task, err := lib.GetNewTask()
	if err != nil {
		if errors.Is(err, lib.ErrNoTaskAvailable) {
			agentstate.Logger.Debug("No new task available")
			return
		}

		agentstate.Logger.Error("Failed to get new task", "error", err)
		time.Sleep(viper.GetDuration("sleep_on_failure"))

		return
	}

	if task != nil {
		_ = processTask(task) //nolint:errcheck // Ignore error, as it is already logged and we can continue
	}
}

func processTask(task *components.Task) error {
	agentstate.State.CurrentActivity = agentstate.CurrentActivityCracking

	lib.DisplayNewTask(task)

	attack, err := lib.GetAttackParameters(task.GetAttackID())
	if err != nil || attack == nil {
		agentstate.Logger.Error("Failed to get attack parameters", "error", err)
		lib.SendAgentError(err.Error(), task, operations.SeverityFatal)
		lib.AbandonTask(task)
		time.Sleep(viper.GetDuration("sleep_on_failure"))

		return err
	}

	lib.DisplayNewAttack(attack)

	err = lib.AcceptTask(task)
	if err != nil {
		agentstate.Logger.Error("Failed to accept task", "task_id", task.GetID())

		return err
	}

	lib.DisplayRunTaskAccepted(task)

	if err := lib.DownloadFiles(attack); err != nil {
		agentstate.Logger.Error("Failed to download files", "error", err)
		lib.SendAgentError(err.Error(), task, operations.SeverityFatal)
		lib.AbandonTask(task)
		time.Sleep(viper.GetDuration("sleep_on_failure"))

		return err
	}

	err = lib.RunTask(task, attack)
	if err != nil {
		return err
	}

	agentstate.State.CurrentActivity = agentstate.CurrentActivityWaiting

	return nil
}

func heartbeat(signChan chan os.Signal) {
	if agentstate.State.ExtraDebugging {
		agentstate.Logger.Debug("Sending heartbeat")
	}

	state := lib.SendHeartBeat()
	if state != nil {
		if agentstate.State.ExtraDebugging {
			agentstate.Logger.Debug("Received heartbeat response", "state", state)
		}

		switch *state {
		case operations.StatePending:
			if agentstate.State.CurrentActivity != agentstate.CurrentActivityBenchmarking {
				agentstate.Logger.Info("Agent is pending, performing reload")
				agentstate.State.Reload = true
			}
		case operations.StateStopped:
			if agentstate.State.CurrentActivity != agentstate.CurrentActivityCracking {
				agentstate.State.CurrentActivity = agentstate.CurrentActivityStopping
				agentstate.Logger.Debug("Agent is stopped, stopping processing")

				if !agentstate.State.JobCheckingStopped {
					agentstate.Logger.Warn(
						"Job checking stopped, per server directive. Waiting for further instructions.",
					)
				}

				agentstate.State.JobCheckingStopped = true
			}
		case operations.StateError:
			agentstate.Logger.Info("Agent is in error state, stopping processing")

			signChan <- syscall.SIGTERM
		}
	}
}

func fetchAgentConfig() error {
	err := lib.GetAgentConfiguration()
	if err != nil {
		agentstate.Logger.Fatal("Failed to get agent configuration from the CipherSwarm API", "error", err)
	}

	if viper.GetBool("always_use_native_hashcat") {
		lib.Configuration.Config.UseNativeHashcat = true
	}

	return err
}

func initLogger() {
	if agentstate.State.Debug {
		agentstate.Logger.SetLevel(log.DebugLevel) // Set the logger level to debug
		agentstate.Logger.SetReportCaller(true)    // Report the caller for debugging
	} else {
		agentstate.Logger.SetLevel(log.InfoLevel)
	}
}
