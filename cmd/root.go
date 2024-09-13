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

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "cipherswarm-agent",
	Version: lib.AgentVersion,
	Short:   "CipherSwarm Agent",
	Long:    "CipherSwarm Agent is the agent for connecting to the CipherSwarm system.",
	Run:     startAgent,
}

// Execute runs the root command.
// It executes the rootCmd and exits with code 1 if there is an error.
func Execute() {
	err := rootCmd.Execute()
	cobra.CheckErr(err)
}

// init is a function that is automatically called before the execution of the main function.
// It initializes the configuration and sets up the command-line flags for the root command.
func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cipherswarmagent.yaml)")
	rootCmd.PersistentFlags().BoolVar(&enableDebug, "debug", false, "Enable debug mode")
	err := viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	cobra.CheckErr(err)

	setDefaultConfigValues()
}

// setDefaultConfigValues sets the default configuration values for the application using Viper.
// It initializes various configuration parameters such as paths, thresholds, and flags with their default values.
// The function retrieves the current working directory and uses it to set default paths for data, files, and zaps.
//
// Default configuration values set by this function:
// - data_path: Path to the data directory (default: current working directory + "/data")
// - gpu_temp_threshold: GPU temperature threshold (default: 80)
// - always_use_native_hashcat: Flag to always use native hashcat (default: false)
// - sleep_on_failure: Sleep time on failure (default: 60 seconds)
// - always_trust_files: Flag to always trust files (default: false)
// - files_path: Path to the files directory within the data directory (default: data_path + "/files")
// - extra_debugging: Flag to enable extra debugging (default: false)
// - status_timer: Status timer in seconds (default: 3)
// - write_zaps_to_file: Flag to write zaps to file (default: false)
// - zap_path: Path to the zaps directory within the data directory (default: data_path + "/zaps")
// - retain_zaps_on_completion: Flag to retain zaps on completion (default: false)
// - enable_additional_hash_types: Flag to enable additional hash types when benchmarking (default: true)
// - use_legacy_device_technique: Flag to use the legacy device technique (default: false)
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

// setupSharedState initializes the shared state of the application.
// It sets the API URL, token, data paths, file paths, and other configuration options in the shared state.
// The shared state is used to store global variables and settings that are accessed by multiple parts of the application.
// This function reads the configuration values from the viper instance and assigns them to the corresponding fields in the shared state.
// It also sets default values for some paths and flags.
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

// initConfig initializes the configuration for the CipherSwarmAgent.
// It checks if a configuration file is provided, and if not, it sets the default configuration file path.
// It also reads environment variables and attempts to read the configuration file.
// If a configuration file is found, it logs the file path.
// If no configuration file is found, it writes a new one.
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

// startAgent initializes and starts the CipherSwarm agent. It performs the following steps:
// 1. Checks if the API URL and API token are set, and logs a fatal error if they are not.
// 2. Sets up shared state and initializes the logger.
// 3. Sets up a signal handler to catch SIGINT and SIGTERM for cleanup purposes.
// 4. Configures the logger level based on the debug state.
// 5. Sets up the API and displays startup information.
// 6. Checks for an existing lock file and aborts if one is found.
// 7. Creates necessary data directories and a lock file to prevent multiple instances.
// 8. Authenticates with the CipherSwarm API and logs the result.
// 9. Fetches the agent configuration and updates agent metadata.
// 10. Kills any dangling hashcat processes.
// 11. Starts a heartbeat loop to send a heartbeat to the CipherSwarm API every 60 seconds.
// 12. Starts the agent loop to request and process new tasks from the CipherSwarm API.
// 13. Waits for a termination signal to clean up and shut down the agent.
//
// Parameters:
// - _ *cobra.Command: The command that triggered this function (unused).
// - _ []string: Additional arguments (unused).
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
	lib.UpdateAgentMetadata()
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

// cleanupLockFile removes the PID file during shutdown
func cleanupLockFile(pidFile string) {
	shared.Logger.Debug("Cleaning up PID file", "path", pidFile)
	if err := fileutil.RemoveFile(pidFile); err != nil {
		shared.Logger.Fatal("Failed to remove PID file", "error", err)
	}
}

// startHeartbeatLoop initiates an infinite loop that sends heartbeat signals at regular intervals.
// It takes a channel of os.Signal as an argument, which is used to send the heartbeat signals.
// The function calls the heartbeat function and then sleeps for 60 seconds before repeating the process.
func startHeartbeatLoop(signChan chan os.Signal) {
	for {
		heartbeat(signChan)
		time.Sleep(60 * time.Second)
	}
}

// startAgentLoop continuously runs the agent's main loop, performing various tasks based on the current state and configuration.
// It handles reloading the agent, updating the cracker, and checking for new tasks. The loop sleeps for a configured interval
// between iterations.
//
// The loop performs the following actions:
// 1. If the agent's state indicates a reload is needed, it calls handleReload().
// 2. If the configuration specifies not to use the native Hashcat, it calls handleCrackerUpdate().
// 3. If job checking is not stopped, it calls handleNewTask().
// 4. It calculates the sleep time based on the configured AgentUpdateInterval and sleeps for that duration.
//
// This function runs indefinitely until the program is terminated.
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
// It updates the agent's state and logs the process. If fetching the agent
// configuration fails, it logs an error and sends a fatal error notification.
func handleReload() {
	lib.SendAgentError("Reloading config and performing new benchmark", nil, operations.SeverityInfo)
	shared.State.CurrentActivity = shared.CurrentActivityStarting
	shared.Logger.Info("Reloading agent")
	if err := fetchAgentConfig(); err != nil {
		shared.Logger.Error("Failed to fetch agent configuration", "error", err)
		lib.SendAgentError("Failed to fetch agent configuration", nil, operations.SeverityFatal)
	}
	shared.State.CurrentActivity = shared.CurrentActivityBenchmarking
	lib.UpdateBenchmarks()
	shared.State.CurrentActivity = shared.CurrentActivityStarting
	shared.State.Reload = false
}

// handleCrackerUpdate updates the cracker if not using native Hashcat
func handleCrackerUpdate() {
	shared.State.CurrentActivity = shared.CurrentActivityUpdating
	lib.UpdateCracker()
	shared.State.CurrentActivity = shared.CurrentActivityStarting
}

// handleNewTask fetches and processes a new task from the CipherSwarm API
// If an error occurs during retrieval, it logs the error and sleeps for a duration
// specified by the "sleep_on_failure" configuration before returning.
// If a new task is successfully retrieved, it processes the task using the processTask function.
// If no new task is available, it logs an informational message.
func handleNewTask() {
	task, err := lib.GetNewTask()
	if err != nil {
		shared.Logger.Error("Failed to get new task", "error", err)
		time.Sleep(viper.GetDuration("sleep_on_failure"))
		return
	}

	if task != nil {
		processTask(task)
	} else {
		shared.Logger.Info("No new task available")
	}
}

// processTask processes a given task by performing several steps including
// displaying the task, retrieving attack parameters, accepting the task,
// downloading necessary files, and running the task. If any step fails, it logs
// the error, sends an agent error, abandons the task, and sleeps for a specified
// duration before returning.
//
// Parameters:
//   - task (*components.Task): The task to be processed.
func processTask(task *components.Task) {
	shared.State.CurrentActivity = shared.CurrentActivityCracking
	lib.DisplayNewTask(task)

	attack, err := lib.GetAttackParameters(task.GetAttackID())
	if err != nil || attack == nil {
		shared.Logger.Error("Failed to get attack parameters", "error", err)
		lib.SendAgentError(err.Error(), task, operations.SeverityFatal)
		lib.AbandonTask(task)
		time.Sleep(viper.GetDuration("sleep_on_failure"))
		return
	}

	lib.DisplayNewAttack(attack)

	if !lib.AcceptTask(task) {
		shared.Logger.Error("Failed to accept task", "task_id", task.GetID())
		return
	}
	lib.DisplayRunTaskAccepted(task)

	if err := lib.DownloadFiles(attack); err != nil {
		shared.Logger.Error("Failed to download files", "error", err)
		lib.SendAgentError(err.Error(), task, operations.SeverityFatal)
		lib.AbandonTask(task)
		time.Sleep(viper.GetDuration("sleep_on_failure"))
		return
	}

	lib.RunTask(task, attack)
	shared.State.CurrentActivity = shared.CurrentActivityWaiting
}

// heartbeat sends a heartbeat signal and handles the response.
// It logs the heartbeat status and performs certain actions based on the response state.
// If the response state is "Pending" and the current activity is not benchmarking,
// it sets the reload flag to true.
// If the response state is "Stopped", it logs the status, sends an agent error,
// and sends a termination signal to the signChan channel.
// If the response state is "Error", it logs the status and stops processing.
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

// fetchAgentConfig fetches the agent configuration from the CipherSwarm API.
// If the configuration retrieval fails, it logs a fatal error.
// If the "always_use_native_hashcat" flag is set to true in the configuration,
// it enables the use of native Hashcat.
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

// initLogger initializes the logger based on the debug flag in the shared state.
// If the debug flag is set, the logger level is set to debug and the caller is reported for debugging.
// Otherwise, the logger level is set to info.
func initLogger() {
	if shared.State.Debug {
		shared.Logger.SetLevel(log.DebugLevel) // Set the logger level to debug
		shared.Logger.SetReportCaller(true)    // Report the caller for debugging
	} else {
		shared.Logger.SetLevel(log.InfoLevel)
	}
}

// setupAPI initializes the SDK client and context for the application.
// It sets up the SdkClient with the server URL and API token from the shared state,
// and creates a new background context.
func setupAPI() {
	lib.SdkClient = sdk.New(sdk.WithServerURL(shared.State.URL), sdk.WithSecurity(shared.State.APIToken))
	lib.Context = context.Background()
}
