package agent

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/log"

	"github.com/spf13/viper"
	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib"
	"github.com/unclesp1d3r/cipherswarmagent/lib/config"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

func StartAgent() {
	// Ensure API URL and token are set
	if viper.GetString("api_url") == "" {
		shared.Logger.Fatal("API URL not set")
	}
	if viper.GetString("api_token") == "" {
		shared.Logger.Fatal("API token not set")
	}

	// Initialize shared state and logger
	config.SetupSharedState()
	initLogger()

	// Initialize API client
	shared.State.SdkClient = sdk.New(sdk.WithServerURL(shared.State.URL), sdk.WithSecurity(shared.State.APIToken))
	shared.State.Context = context.Background()

	lib.DisplayStartup()

	// Set up signal handling for graceful shutdown
	signChan := make(chan os.Signal, 1)
	signal.Notify(signChan, os.Interrupt, syscall.SIGTERM)

	// Check for an existing lock file to prevent multiple instances
	if cracker.CheckForExistingClient(shared.State.PidFile) {
		shared.Logger.Fatal("Aborting agent start, lock file found", "path", shared.State.PidFile)
	}

	// Create necessary data directories and lock file
	if err := cracker.CreateDataDirs(); err != nil {
		shared.Logger.Fatal("Error creating data directories", "error", err)
	}
	if err := cracker.CreateLockFile(); err != nil {
		shared.Logger.Fatal("Error creating lock file", "error", err)
	}
	defer cleanupLockFile(shared.State.PidFile)

	// Authenticate with the CipherSwarm API
	if err := lib.AuthenticateAgent(); err != nil {
		shared.Logger.Fatal("Failed to authenticate with the CipherSwarm API", "error", err)
	}
	lib.DisplayAuthenticated()

	// Fetch agent configuration and update metadata
	if err := fetchAgentConfig(); err != nil {
		shared.Logger.Fatal("Failed to fetch agent configuration", "error", err)
	}
	err := lib.UpdateAgentMetadata()
	if err != nil {
		return // Error already logged
	}
	shared.Logger.Info("Sent agent metadata to the CipherSwarm API")

	// Kill any dangling hashcat processes
	if cracker.CheckForExistingClient(shared.State.HashcatPidFile) {
		shared.Logger.Info("Killed dangling hashcat process")
	}

	// Start heartbeat and agent loops
	go startHeartbeatLoop(signChan)
	go startAgentLoop()

	// Wait for termination signal
	sig := <-signChan
	shared.Logger.Debug("Received signal", "signal", sig)
	lib.SendAgentError("Received signal to terminate. Shutting down", nil, operations.SeverityInfo)
	lib.SendAgentShutdown()
	lib.DisplayShuttingDown()
}

func cleanupLockFile(pidFile string) {
	shared.Logger.Debug("Cleaning up PID file", "path", pidFile)
	if err := os.Remove(pidFile); err != nil {
		shared.Logger.Fatal("Failed to remove PID file", "error", err)
	}
}

func startHeartbeatLoop(signChan chan os.Signal) {
	for {
		heartbeat(signChan)
		time.Sleep(viper.GetDuration("heartbeat_interval"))
	}
}

func startAgentLoop() {
	for {
		if shared.State.Reload {
			handleReload()
		}

		if !lib.Configuration.Config.UseNativeHashcat {
			handleCrackerUpdate()
		}

		if !shared.State.JobCheckingStopped {
			handleNewTask()
		}

		sleepTime := time.Duration(lib.Configuration.Config.AgentUpdateInterval) * time.Second
		lib.DisplayInactive(sleepTime)
		time.Sleep(sleepTime)
	}
}

func handleReload() {
	lib.SendAgentError("Reloading config and performing new benchmark", nil, operations.SeverityInfo)
	shared.State.CurrentActivity = shared.CurrentActivityStarting
	shared.Logger.Info("Reloading agent")
	if err := fetchAgentConfig(); err != nil {
		shared.Logger.Error("Failed to fetch agent configuration", "error", err)
		lib.SendAgentError("Failed to fetch agent configuration", nil, operations.SeverityFatal)
	}
	shared.State.CurrentActivity = shared.CurrentActivityBenchmarking
	_ = lib.UpdateBenchmarks() // Ignore error, as it is already logged and we can continue
	shared.State.CurrentActivity = shared.CurrentActivityStarting
	shared.State.Reload = false
}

func handleCrackerUpdate() {
	shared.State.CurrentActivity = shared.CurrentActivityUpdating
	lib.UpdateCracker()
	shared.State.CurrentActivity = shared.CurrentActivityStarting
}

func handleNewTask() {
	task, err := lib.GetNewTask()
	if err != nil {
		shared.Logger.Error("Failed to get new task", "error", err)
		time.Sleep(viper.GetDuration("sleep_on_failure"))

		return
	}

	if task != nil {
		_ = processTask(task) // Ignore error, as it is already logged and we can continue
	} else {
		shared.Logger.Info("No new task available")
	}
}

func processTask(task *components.Task) error {
	shared.State.CurrentActivity = shared.CurrentActivityCracking
	lib.DisplayNewTask(task)

	attack, err := lib.GetAttackParameters(task.GetAttackID())
	if err != nil || attack == nil {
		shared.Logger.Error("Failed to get attack parameters", "error", err)
		lib.SendAgentError(err.Error(), task, operations.SeverityFatal)
		lib.AbandonTask(task)
		time.Sleep(viper.GetDuration("sleep_on_failure"))

		return err
	}

	lib.DisplayNewAttack(attack)

	err = lib.AcceptTask(task)
	if err != nil {
		shared.Logger.Error("Failed to accept task", "task_id", task.GetID())

		return err
	}

	lib.DisplayRunTaskAccepted(task)

	if err := lib.DownloadFiles(attack); err != nil {
		shared.Logger.Error("Failed to download files", "error", err)
		lib.SendAgentError(err.Error(), task, operations.SeverityFatal)
		lib.AbandonTask(task)
		time.Sleep(viper.GetDuration("sleep_on_failure"))

		return err
	}

	err = lib.RunTask(task, attack)
	if err != nil {
		return err
	}
	shared.State.CurrentActivity = shared.CurrentActivityWaiting

	return nil
}

func heartbeat(signChan chan os.Signal) {
	if shared.State.ExtraDebugging {
		shared.Logger.Debug("Sending heartbeat")
	}
	state := lib.SendHeartBeat()
	if state != nil {
		if shared.State.ExtraDebugging {
			shared.Logger.Debug("Received heartbeat response", "state", state)
		}
		switch *state {
		case operations.StatePending:
			if shared.State.CurrentActivity != shared.CurrentActivityBenchmarking {
				shared.Logger.Info("Agent is pending, performing reload")
				shared.State.Reload = true
			}
		case operations.StateStopped:
			if shared.State.CurrentActivity != shared.CurrentActivityCracking {
				shared.State.CurrentActivity = shared.CurrentActivityStopping
				shared.Logger.Debug("Agent is stopped, stopping processing")
				if !shared.State.JobCheckingStopped {
					shared.Logger.Warn("Job checking stopped, per server directive. Waiting for further instructions.")
				}
				shared.State.JobCheckingStopped = true
			}
		case operations.StateError:
			shared.Logger.Info("Agent is in error state, stopping processing")
			signChan <- syscall.SIGTERM
		}
	}
}

func fetchAgentConfig() error {
	err := lib.GetAgentConfiguration()
	if err != nil {
		shared.Logger.Fatal("Failed to get agent configuration from the CipherSwarm API", "error", err)
	}

	if viper.GetBool("always_use_native_hashcat") {
		lib.Configuration.Config.UseNativeHashcat = true
	}

	return err
}

func initLogger() {
	if shared.State.Debug {
		shared.Logger.SetLevel(log.DebugLevel) // Set the logger level to debug
		shared.Logger.SetReportCaller(true)    // Report the caller for debugging
	} else {
		shared.Logger.SetLevel(log.InfoLevel)
	}
}
