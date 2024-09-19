// Package cmd
package cmd

import (
	"context"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/duke-git/lancet/v2/fileutil"
	gap "github.com/muesli/go-app-paths"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

var (
	cfgFile     string
	enableDebug bool
	scope       = gap.NewScope(gap.User, "CipherSwarm")
)

// rootCmd represents the base command when called without any subcommands.
// Use: "cipherswarm-agent", Version: lib.AgentVersion, Short: "CipherSwarm Agent"
// Long: "CipherSwarm Agent is the agent for connecting to the CipherSwarm system."
// Run: Executes the startAgent function to initialize and start the agent.
var rootCmd = &cobra.Command{
	Use:     "cipherswarm-agent",
	Version: lib.AgentVersion,
	Short:   "CipherSwarm Agent",
	Long:    "CipherSwarm Agent is the agent for connecting to the CipherSwarm system.",
	Run:     startAgent,
}

// Execute runs the root command for the CipherSwarm Agent.
// It calls the `Execute` method on `rootCmd` to start processing commands.
// Errors encountered during execution are checked and handled using `cobra.CheckErr`.
func Execute() {
	err := rootCmd.Execute()
	cobra.CheckErr(err)
}

// init sets up the initial configuration for the application by initializing the Cobra commands and Viper configuration.
// It performs the following actions:
// 1. Calls initConfig to initialize configuration settings.
// 2. Sets up persistent flags for configuration file path and debug mode.
// 3. Binds the debug flag to Viper for configuration management.
// 4. Sets default configuration values.
func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cipherswarmagent.yaml)")
	rootCmd.PersistentFlags().BoolVar(&enableDebug, "debug", false, "Enable debug mode")
	err := viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	cobra.CheckErr(err)

	setDefaultConfigValues()
}

// setDefaultConfigValues sets default values for configuration settings using Viper.
// It retrieves the current working directory and assigns default paths and settings for
// data path, GPU temperature threshold, native Hashcat usage, failure sleep duration,
// file trust, files path, debugging, status timer, zap file writing, zap path, zap retention,
// additional hash types, and legacy device technique usage.
func setDefaultConfigValues() {
	cwd, err := os.Getwd()
	cobra.CheckErr(err)

	viper.SetDefault("data_path", path.Join(cwd, "data"))
	viper.SetDefault("gpu_temp_threshold", 80)
	viper.SetDefault("always_use_native_hashcat", false)
	viper.SetDefault("sleep_on_failure", 60*time.Second)
	viper.SetDefault("always_trust_files", false)
	viper.SetDefault("files_path", path.Join(viper.GetString("data_path"), "files"))
	viper.SetDefault("extra_debugging", false)
	viper.SetDefault("status_timer", 3)
	viper.SetDefault("write_zaps_to_file", false)
	viper.SetDefault("zap_path", path.Join(viper.GetString("data_path"), "zaps"))
	viper.SetDefault("retain_zaps_on_completion", false)
	viper.SetDefault("enable_additional_hash_types", true)
	viper.SetDefault("use_legacy_device_technique", false)
}

// setupSharedState initializes the global shared state configuration using parameters from Viper configuration.
// It sets various file paths and flags in the shared state structure.
// The function performs the following actions:
// 1. Sets the API URL and API token.
// 2. Retrieves and sets the data path and other directory paths.
// 3. Configures file paths for PID and hashcat PID files.
// 4. Sets paths for crackers, files, hashlists, zaps, preprocessors, tools, output, and restore data.
// 5. Configures various boolean flags related to debug, file trust, and zap handling.
// 6. Sets additional configuration values like status timer and enabling additional hash types.
func setupSharedState() {
	// Set the API URL and token
	shared.State.URL = viper.GetString("api_url")
	shared.State.APIToken = viper.GetString("api_token")

	dataRoot := viper.GetString("data_path")                                                        // Get the data path from the configuration
	shared.State.DataPath = dataRoot                                                                // Set the data path in the shared state
	shared.State.PidFile = path.Join(dataRoot, "lock.pid")                                          // Set the default PID file path
	shared.State.HashcatPidFile = path.Join(dataRoot, "hashcat.pid")                                // Set the default hashcat PID file path
	shared.State.CrackersPath = path.Join(dataRoot, "crackers")                                     // Set the crackers path in the shared state
	shared.State.FilePath = viper.GetString("files_path")                                           // Set the file path in the shared state
	shared.State.HashlistPath = path.Join(dataRoot, "hashlists")                                    // Set the hashlist path in the shared state
	shared.State.ZapsPath = viper.GetString("zap_path")                                             // Set the zaps path in the shared state
	shared.State.PreprocessorsPath = path.Join(dataRoot, "preprocessors")                           // Set the preprocessors path in the shared state
	shared.State.ToolsPath = path.Join(dataRoot, "tools")                                           // Set the tools path in the shared state
	shared.State.OutPath = path.Join(dataRoot, "output")                                            // Set the output path in the shared state
	shared.State.RestoreFilePath = path.Join(dataRoot, "restore")                                   // Set the restore file path in the shared state
	shared.State.Debug = enableDebug                                                                // Set the debug flag in the shared state
	shared.State.AlwaysTrustFiles = viper.GetBool("always_trust_files")                             // Set the always trust files flag in the shared state
	shared.State.ExtraDebugging = viper.GetBool("extra_debugging")                                  // Set the extra debugging flag in the shared state
	shared.State.StatusTimer = viper.GetInt("status_timer")                                         // Set the status timer in the shared state to 3 seconds
	shared.State.WriteZapsToFile = viper.GetBool("write_zaps_to_file")                              // Set the write zaps to file flag in the shared state
	shared.State.RetainZapsOnCompletion = viper.GetBool("retain_zaps_on_completion")                // Set the retain zaps on completion flag in the shared state
	shared.State.EnableAdditionalHashTypes = viper.GetBool("enable_additional_hash_types")          // Set the enable additional hash types flag in the shared state
	shared.State.UseLegacyDeviceIdentificationMethod = viper.GetBool("use_legacy_device_technique") // Set the use legacy device identification method flag in the shared state
}

// initConfig initializes configuration settings for the application.
// It sets up error logging, determines configuration directories, and reads configuration files, prioritizing user configurations.
func initConfig() {
	shared.ErrorLogger.SetReportCaller(true)

	home, err := os.UserConfigDir()
	cobra.CheckErr(err)

	cwd, err := os.Getwd()
	cobra.CheckErr(err)
	viper.AddConfigPath(cwd)

	configDirs, err := scope.ConfigDirs()
	cobra.CheckErr(err)
	for _, dir := range configDirs {
		viper.AddConfigPath(dir)
	}

	viper.AddConfigPath(home)
	viper.SetConfigType("yaml")
	viper.SetConfigName("cipherswarmagent")

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		shared.Logger.Info("Using config file", "config_file", viper.ConfigFileUsed())
	} else {
		shared.Logger.Warn("No config file found, attempting to write a new one")
		if err := viper.SafeWriteConfig(); err != nil && err.Error() != "config file already exists" {
			shared.Logger.Error("Error writing config file", "error", err)
		}
	}
}

// startAgent starts the CipherSwarm agent, performing a series of initialization steps, such as:
// ensuring that API URL and token are set, initializing shared state and logger,
// setting up signal handling for graceful shutdown, initializing API client,
// checking for existing lock file to prevent multiple instances, creating necessary data directories and lock file,
// authenticating with the CipherSwarm API, fetching agent configuration and updating metadata,
// killing any dangling hashcat processes, starting heartbeat and agent loops,
// and waiting for a termination signal to shut down the agent gracefully.
func startAgent(_ *cobra.Command, _ []string) {
	// Ensure API URL and token are set
	if viper.GetString("api_url") == "" {
		shared.Logger.Fatal("API URL not set")
	}
	if viper.GetString("api_token") == "" {
		shared.Logger.Fatal("API token not set")
	}

	// Initialize shared state and logger
	setupSharedState()
	initLogger()

	// Set up signal handling for graceful shutdown
	signChan := make(chan os.Signal, 1)
	signal.Notify(signChan, os.Interrupt, syscall.SIGTERM)

	// Initialize API client and display startup info
	setupAPI()
	lib.DisplayStartup()

	// Check for existing lock file to prevent multiple instances
	if lib.CheckForExistingClient(shared.State.PidFile) {
		shared.Logger.Fatal("Aborting agent start, lock file found", "path", shared.State.PidFile)
	}

	// Create necessary data directories and lock file
	if err := lib.CreateDataDirs(); err != nil {
		shared.Logger.Fatal("Error creating data directories", "error", err)
	}
	if err := lib.CreateLockFile(); err != nil {
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
	if lib.CheckForExistingClient(shared.State.HashcatPidFile) {
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

// cleanupLockFile removes the specified PID file and logs the operation. On failure, it logs a fatal error and exits the program.
func cleanupLockFile(pidFile string) {
	shared.Logger.Debug("Cleaning up PID file", "path", pidFile)
	if err := fileutil.RemoveFile(pidFile); err != nil {
		shared.Logger.Fatal("Failed to remove PID file", "error", err)
	}
}

// startHeartbeatLoop continuously sends heartbeat signals at regular intervals.
// It logs the status of heartbeats and determines appropriate actions based on server responses.
func startHeartbeatLoop(signChan chan os.Signal) {
	for {
		heartbeat(signChan)
		time.Sleep(60 * time.Second)
	}
}

// startAgentLoop runs the main loop of the agent, managing its state and tasks.
// It handles configuration reloads, cracker updates, and new task assignments.
// During each iteration, it checks and executes actions based on the agent's current state:
// 1. If the agent's state indicates a reload, it calls handleReload() to refresh the configuration.
// 2. If the agent is not using native Hashcat, it calls handleCrackerUpdate() to update the cracker software.
// 3. If job-checking is not stopped, it calls handleNewTask() to fetch and process new tasks.
// After performing these checks and actions, it sets a sleep duration defined by the agent's update interval,
// uses DisplayInactive() to log the sleep period, and pauses for the specified duration.
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

// handleReload reloads the agent configuration and performs a new benchmark.
// It updates the current activity state and logs information and errors.
//
// Steps performed:
// 1. Send an info message indicating the start of the reload process.
// 2. Set the current activity state to 'starting' and log the reload action.
// 3. Fetch the new agent configuration, logging and sending a fatal error if it fails.
// 4. Update the current activity state to 'benchmarking' and perform benchmark updates.
// 5. Ignore any errors from updating benchmarks as they are already logged.
// 6. Revert the activity state to 'starting' and reset the reload flag.
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

// handleCrackerUpdate updates the cracker software, setting the current activity to updating and starting.
func handleCrackerUpdate() {
	shared.State.CurrentActivity = shared.CurrentActivityUpdating
	lib.UpdateCracker()
	shared.State.CurrentActivity = shared.CurrentActivityStarting
}

// handleNewTask fetches a new task using lib.GetNewTask and processes it.
// If fetching the task fails, it logs an error and sleeps for a configured duration before returning.
// If a new task is available, it proceeds to process the task.
// If no new task is available, it logs that information.
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

// processTask processes a given task by executing the following sequence of steps:
//  1. Sets the current activity to "cracking".
//  2. Displays the new task information.
//  3. Retrieves attack parameters for the task based on attack ID. If it fails, logs the error, sends error report,
//     abandons the task, sleeps for a specified duration, and returns the error.
//  4. Displays attack details.
//  5. Accepts the task. If it fails, logs the error and returns the error.
//  6. Displays the log for task acceptance.
//  7. Downloads required files for the attack. If it fails, logs the error, sends error report,
//     abandons the task, sleeps for a specified duration, and returns the error.
//  8. Runs the task with the provided attack parameters. If it fails, returns the error.
//  9. Sets the current activity to "waiting".
//  10. Returns nil if successful.
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

// heartbeat sends a heartbeat signal to the server and processes the server response.
// If a valid state is returned, it takes actions based on that state, including pending, stopped, and error states.
// For pending state: If the agent is not benchmarking, it sets a flag to reload the agent.
// For stopped state: If the agent is not cracking, it marks the agent as stopping and processes job checking status.
// For error state: It logs an error message and sends a termination signal.
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

// fetchAgentConfig retrieves the configuration of the agent from the CipherSwarm API and handles related errors.
// If the configuration specifies the use of native Hashcat, it sets the appropriate flag in the configuration.
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

// initLogger initializes the logging configuration based on the current debug state.
// If the debug mode is enabled, it sets the logging level to debug and enables caller reporting.
// Otherwise, it sets the logging level to info.
func initLogger() {
	if shared.State.Debug {
		shared.Logger.SetLevel(log.DebugLevel) // Set the logger level to debug
		shared.Logger.SetReportCaller(true)    // Report the caller for debugging
	} else {
		shared.Logger.SetLevel(log.InfoLevel)
	}
}

// setupAPI initializes the SDK client and background context required for API interactions.
func setupAPI() {
	lib.SdkClient = sdk.New(sdk.WithServerURL(shared.State.URL), sdk.WithSecurity(shared.State.APIToken))
	lib.Context = context.Background()
}
