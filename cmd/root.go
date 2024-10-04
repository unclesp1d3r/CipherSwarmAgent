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

// rootCmd represents the base command for the CipherSwarm Agent CLI application.
var rootCmd = &cobra.Command{
	Use:     "cipherswarm-agent",
	Version: lib.AgentVersion,
	Short:   "CipherSwarm Agent",
	Long:    "CipherSwarm Agent is the agent for connecting to the CipherSwarm system.",
	Run:     startAgent,
}

// Execute runs the root command and checks for any errors that occur during its execution.
func Execute() {
	err := rootCmd.Execute()
	cobra.CheckErr(err)
}

// init initializes the root command and binds various flags to the configuration using Viper.
// It sets up the required flags and binds them to configuration variables for easy access throughout the application.
func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cipherswarmagent.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&enableDebug, "debug", "d", false, "Enable debug mode")
	err := viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().StringP("api_token", "a", "", "API token for the CipherSwarm server")
	err = viper.BindPFlag("api_token", rootCmd.PersistentFlags().Lookup("api_token"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().StringP("api_url", "u", "", "URL of the CipherSwarm server")
	err = viper.BindPFlag("api_url", rootCmd.PersistentFlags().Lookup("api_url"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().StringP("data_path", "p", "", "Path to the directory where the agent will store data")
	err = viper.BindPFlag("data_path", rootCmd.PersistentFlags().Lookup("data_path"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().IntP("gpu_temp_threshold", "g", 80, "Temperature threshold for the GPU in degrees Celsius")
	err = viper.BindPFlag("gpu_temp_threshold", rootCmd.PersistentFlags().Lookup("gpu_temp_threshold"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().BoolP("always_use_native_hashcat", "n", false, "Force using the native hashcat binary")
	err = viper.BindPFlag("always_use_native_hashcat", rootCmd.PersistentFlags().Lookup("always_use_native_hashcat"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().DurationP("sleep_on_failure", "s", 60*time.Second, "Duration of sleep after a task failure")
	err = viper.BindPFlag("sleep_on_failure", rootCmd.PersistentFlags().Lookup("sleep_on_failure"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().StringP("files_path", "f", "", "Path to the directory where the agent will store task files")
	err = viper.BindPFlag("files_path", rootCmd.PersistentFlags().Lookup("files_path"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().BoolP("extra_debugging", "e", false, "Enable additional debugging information")
	err = viper.BindPFlag("extra_debugging", rootCmd.PersistentFlags().Lookup("extra_debugging"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().IntP("status_timer", "t", 3, "Interval in seconds for sending status updates to the server")
	err = viper.BindPFlag("status_timer", rootCmd.PersistentFlags().Lookup("status_timer"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().BoolP("write_zaps_to_file", "w", false, "Write zap output to a file in the zaps directory")
	err = viper.BindPFlag("write_zaps_to_file", rootCmd.PersistentFlags().Lookup("write_zaps_to_file"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().StringP("zap_path", "z", "", "Path to the directory where the agent will store zap output files")
	err = viper.BindPFlag("zap_path", rootCmd.PersistentFlags().Lookup("zap_path"))
	cobra.CheckErr(err)

	rootCmd.PersistentFlags().BoolP("retain_zaps_on_completion", "r", false, "Retain zap files after completing a task")
	err = viper.BindPFlag("retain_zaps_on_completion", rootCmd.PersistentFlags().Lookup("retain_zaps_on_completion"))
	cobra.CheckErr(err)

	setDefaultConfigValues()
}

// setDefaultConfigValues sets default configuration values using the Viper package.
// It configures various default values such as "data_path", "gpu_temp_threshold", "always_use_native_hashcat", and others.
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

// setupSharedState initializes the global configuration and runtime state of the application based on settings from viper.
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

// initConfig initializes and loads the configuration for the application.
// It sets up the error logger, determines the config directory, adds config paths,
// and attempts to read the configuration from a YAML file.
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

// startAgent initializes the agent, ensuring the necessary settings are configured, creating the necessary directories, and starting loops.
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

	// Check for an existing lock file to prevent multiple instances
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

// cleanupLockFile removes the specified PID file. Logs an error and shuts down the application if removal fails.
func cleanupLockFile(pidFile string) {
	shared.Logger.Debug("Cleaning up PID file", "path", pidFile)
	if err := fileutil.RemoveFile(pidFile); err != nil {
		shared.Logger.Fatal("Failed to remove PID file", "error", err)
	}
}

// startHeartbeatLoop runs an infinite loop that sends a heartbeat signal every 60 seconds.
// It pauses for 60 seconds between each call to `heartbeat`.
func startHeartbeatLoop(signChan chan os.Signal) {
	for {
		heartbeat(signChan)
		time.Sleep(60 * time.Second)
	}
}

// startAgentLoop runs the main loop for the agent, managing its state and handling various conditions periodically.
// It continuously checks and reacts to the agent's runtime state flags, such as reload and task handling status.
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

// handleReload handles the reloading of agent's configuration and updating benchmarks.
// It sends an informational message about the reload, sets the agent's activity state to start,
// logs the reload action, fetches the agent configuration, and processes errors accordingly.
// Upon successful configuration fetch, it sets the agent's activity state to benchmarking, updates benchmarks,
// ignores potential errors from the update, reverts the activity state to starting, and resets the reload flag.
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

// handleNewTask fetches a new task, logs any errors encountered, and processes the task if it is not nil.
// It sleeps for a configured duration on failure, logs the absence of a new task if none is available.
// It ensures that execution continues by ignoring processing errors which have been logged already.
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

// processTask processes a task, updates the current activity status, and handles possible errors.
// First, it logs the new task and retrieves attack parameters. If retrieval fails, it logs, reports the error, and sleeps.
// Next, it logs information about the attack and accepts the task. If task acceptance fails, it logs and returns the error.
// The function then downloads the necessary files for the attack. Any errors in download are logged, reported, and the process sleeps.
// If downloads succeed, it runs the task using the provided attack details, updates the current activity status, and returns any error.
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

// heartbeat sends a heartbeat signal to the server and processes the response.
// If `ExtraDebugging` is enabled, it logs the sending and receipt of the heartbeat.
// Based on the received state, it either performs a reload, stops processing,
// sets the job checking to stopped, or sends a termination signal.
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

// fetchAgentConfig retrieves and applies the agent configuration from the CipherSwarm API.
// If the "always_use_native_hashcat" flag is set, it enforces using the native Hashcat binary.
// Logs a fatal error if it fails to collect configuration data.
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

// initLogger initializes the logger based on the application's debug state.
// If debugging is enabled, it sets the logger level to debug and enables caller reporting.
// Otherwise, it sets the logger level to info.
func initLogger() {
	if shared.State.Debug {
		shared.Logger.SetLevel(log.DebugLevel) // Set the logger level to debug
		shared.Logger.SetReportCaller(true)    // Report the caller for debugging
	} else {
		shared.Logger.SetLevel(log.InfoLevel)
	}
}

// setupAPI initializes the SdkClient using the API URL and token from the shared state and sets the background context.
func setupAPI() {
	lib.SdkClient = sdk.New(sdk.WithServerURL(shared.State.URL), sdk.WithSecurity(shared.State.APIToken))
	lib.Context = context.Background()
}
