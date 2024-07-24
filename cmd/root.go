// Package cmd /*
package cmd

import (
	"context"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/duke-git/lancet/fileutil"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarmagent/lib"
	"github.com/unclesp1d3r/cipherswarmagent/shared"

	"github.com/charmbracelet/log"
	gap "github.com/muesli/go-app-paths"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
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

	cwd, err := os.Getwd()
	cobra.CheckErr(err)

	viper.SetDefault("data_path", path.Join(cwd, "data"))                            // Set the default data path
	viper.SetDefault("gpu_temp_threshold", 80)                                       // Set the default GPU temperature threshold
	viper.SetDefault("always_use_native_hashcat", false)                             // Set the default to not always use native hashcat
	viper.SetDefault("sleep_on_failure", time.Duration(60*time.Second))              // Set the default sleep time on failure
	viper.SetDefault("always_trust_files", false)                                    // Set the default to not always trust files
	viper.SetDefault("files_path", path.Join(viper.GetString("data_path"), "files")) // Set the default files path in the data directory if not set
	viper.SetDefault("extra_debugging", false)                                       // Set the default to not enable extra debugging
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

	dataRoot := viper.GetString("data_path")                              // Get the data path from the configuration
	shared.State.DataPath = dataRoot                                      // Set the data path in the shared state
	shared.State.PidFile = path.Join(dataRoot, "lock.pid")                // Set the default PID file path
	shared.State.HashcatPidFile = path.Join(dataRoot, "hashcat.pid")      // Set the default hashcat PID file path
	shared.State.CrackersPath = path.Join(dataRoot, "crackers")           // Set the crackers path in the shared state
	shared.State.FilePath = viper.GetString("files_path")                 // Set the file path in the shared state
	shared.State.HashlistPath = path.Join(dataRoot, "hashlists")          // Set the hashlist path in the shared state
	shared.State.ZapsPath = path.Join(dataRoot, "zaps")                   // Set the zaps path in the shared state
	shared.State.PreprocessorsPath = path.Join(dataRoot, "preprocessors") // Set the preprocessors path in the shared state
	shared.State.ToolsPath = path.Join(dataRoot, "tools")                 // Set the tools path in the shared state
	shared.State.OutPath = path.Join(dataRoot, "output")                  // Set the output path in the shared state
	shared.State.Debug = enableDebug                                      // Set the debug flag in the shared state
	shared.State.AlwaysTrustFiles = viper.GetBool("always_trust_files")   // Set the always trust files flag in the shared state
	shared.State.ExtraDebugging = viper.GetBool("extra_debugging")        // Set the extra debugging flag in the shared state
	shared.State.StatusTimer = 3                                          // Set the status timer in the shared state to 3 seconds
}

// initConfig initializes the configuration for the CipherSwarmAgent.
// It checks if a configuration file is provided, and if not, it sets the default configuration file path.
// It also reads environment variables and attempts to read the configuration file.
// If a configuration file is found, it logs the file path.
// If no configuration file is found, it writes a new one.
func initConfig() {
	home, err := os.UserConfigDir()
	cobra.CheckErr(err) // Check for errors

	cwd, err := os.Getwd()   // Get the current working directory
	cobra.CheckErr(err)      // Check for errors
	viper.AddConfigPath(cwd) // Add the current working directory to the configuration path

	configDirs, err := scope.ConfigDirs()
	cobra.CheckErr(err)              // Check for errors
	for _, dir := range configDirs { // Add the config directories to the configuration path
		shared.Logger.Info("Adding config path", "path", dir)
	}

	viper.AddConfigPath(home)               // Add the home directory to the configuration path
	viper.SetConfigType("yaml")             // Set the configuration type to YAML
	viper.SetConfigName("cipherswarmagent") // Set the configuration name

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in. Otherwise, write a new one.
	if err := viper.ReadInConfig(); err == nil {
		shared.Logger.Info("Using config file", "config_file", viper.ConfigFileUsed())
	} else {
		err := viper.SafeWriteConfig()
		if err != nil {
			if err.Error() != "config file already exists" {
				shared.Logger.Error("Error writing config file: ", "error", err)
			}
		}
	}
}

// startAgent is a function that starts the CipherSwarm Agent.
//
//goland:noinspection GoUnusedParameter
func startAgent(cmd *cobra.Command, args []string) {
	if viper.GetString("api_url") == "" {
		shared.Logger.Fatal("API URL not set")
	}
	if viper.GetString("api_token") == "" {
		shared.Logger.Fatal("API token not set")
	}

	setupSharedState()

	initLogger()

	signChan := make(chan os.Signal, 1)
	// Set up a signal handler to catch SIGINT and SIGTERM
	// This will allow us to clean up the PID file when the agent is stopped
	// We'll also use this to clean up any dangling hashcat processes
	signal.Notify(signChan, os.Interrupt, syscall.SIGTERM)
	if shared.State.Debug {
		shared.Logger.SetLevel(log.DebugLevel)
	} else {
		shared.Logger.SetLevel(log.InfoLevel)
	}

	setupAPI()

	lib.DisplayStartup()

	lockFound := lib.CheckForExistingClient(shared.State.PidFile)
	if lockFound {
		shared.Logger.Fatal("Aborting agent start, lock file found", "path", shared.State.PidFile)
	}

	err := lib.CreateDataDirs() // Create the data directories
	if err != nil {
		shared.Logger.Fatal("Error creating data directories", "error", err)
	}

	// Create a lock file to prevent multiple instances of the agent from running
	err = lib.CreateLockFile()
	if err != nil {
		shared.Logger.Fatal("Error creating lock file", "error", err)
	}

	defer func(pidFile string) {
		shared.Logger.Debug("Cleaning up PID file", "path", pidFile)

		err := fileutil.RemoveFile(pidFile)
		if err != nil {
			shared.Logger.Fatal("Failed to remove PID file", "error", err)
		}
	}(shared.State.PidFile)

	// Connect to the CipherSwarm API URL and authenticate
	// Right now, we're just logging the result of the authentication.
	// Failure to authenticate will result in a fatal error.
	err = lib.AuthenticateAgent()
	if err != nil {
		shared.Logger.Fatal("Failed to authenticate with the CipherSwarm API", "error", err)
	}
	lib.DisplayAuthenticated()

	// Get the configuration
	// Override the configuration with the always_use_native_hashcat setting
	err = fetchAgentConfig()

	// Update the agent metadata with the CipherSwarm API
	lib.UpdateAgentMetadata()
	shared.Logger.Info("Sent agent metadata to the CipherSwarm API")

	// Kill any dangling hashcat processes
	processFound := lib.CheckForExistingClient(shared.State.HashcatPidFile)
	if err != nil {
		shared.Logger.Fatal("Error checking for dangling hashcat processes", "error", err)
	}
	if processFound {
		shared.Logger.Info("Killed dangling hashcat process")
	}

	// Start the heartbeat loop
	// This will send a heartbeat to the CipherSwarm API every 60 seconds
	go func() {
		for {
			heartbeat(signChan)
			time.Sleep(60 * time.Second)
		}
	}()

	// Start the agent loop
	go func() {
		for {
			heartbeat(signChan)

			if shared.State.Reload {
				lib.SendAgentError("Reloading config and performing new benchmark", nil, components.SeverityInfo)
				shared.State.CurrentActivity = shared.CurrentActivityStarting
				shared.Logger.Info("Reloading agent")
				err = fetchAgentConfig()
				if err != nil {
					shared.Logger.Error("Failed to fetch agent configuration", "error", err)
					lib.SendAgentError("Failed to fetch agent configuration", nil, components.SeverityFatal)
				}
				shared.State.CurrentActivity = shared.CurrentActivityBenchmarking
				lib.UpdateBenchmarks()
				shared.State.CurrentActivity = shared.CurrentActivityStarting
				shared.State.Reload = false
				heartbeat(signChan)
			}
			if !lib.Configuration.Config.UseNativeHashcat {
				shared.State.CurrentActivity = shared.CurrentActivityUpdating
				lib.UpdateCracker() // Should we update the cracker on every loop? It doesn't change often
				shared.State.CurrentActivity = shared.CurrentActivityStarting
				heartbeat(signChan)
			}

			// - Request a new job from the CipherSwarm API
			//   - If a job is available, download the job and start processing it
			task, err := lib.GetNewTask()
			if err != nil {
				shared.Logger.Error("Failed to get new task", "error", err)
				time.Sleep(viper.GetDuration("sleep_on_failure"))
				continue
			}
			if task != nil {
				shared.State.CurrentActivity = shared.CurrentActivityCracking
				lib.DisplayNewTask(task)

				// Process the task
				// - Get the attack parameters
				attack, err := lib.GetAttackParameters(task.GetAttackID())
				if err != nil || attack == nil {
					shared.Logger.Error("Failed to get attack parameters", "error", err)
					lib.SendAgentError(err.Error(), task, components.SeverityFatal)
					lib.AbandonTask(task)
					time.Sleep(viper.GetDuration("sleep_on_failure"))
					continue
				}

				lib.DisplayNewAttack(attack)

				// - Accept the task
				if lib.AcceptTask(task) {
					lib.DisplayRunTaskAccepted(task)
				} else {
					shared.Logger.Error("Failed to accept task", "task_id", task.GetID())
					return
				}
				// - Download the files
				err = lib.DownloadFiles(attack)
				if err != nil {
					shared.Logger.Error("Failed to download files", "error", err)
					lib.SendAgentError(err.Error(), task, components.SeverityFatal)
					lib.AbandonTask(task)
					time.Sleep(viper.GetDuration("sleep_on_failure"))
					continue
				} else {
					lib.RunTask(task, attack)
				}
				shared.State.CurrentActivity = shared.CurrentActivityWaiting
			} else {
				shared.Logger.Info("No new task available")
			}
			heartbeat(signChan)
			sleepTime := time.Duration(lib.Configuration.Config.AgentUpdateInterval) * time.Second
			lib.DisplayInactive(sleepTime)
			time.Sleep(sleepTime)
		}
	}()

	sig := <-signChan // Wait for a signal to shut down the agent
	shared.Logger.Debug("Received signal", "signal", sig)
	lib.SendAgentError("Received signal to terminate. Shutting down", nil, components.SeverityInfo)
	lib.SendAgentShutdown()
	lib.DisplayShuttingDown()
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
		case components.AgentHeartbeatResponseStatePending:
			if shared.State.CurrentActivity != shared.CurrentActivityBenchmarking {
				shared.Logger.Info("Agent is pending, performing reload")
				shared.State.Reload = true
			}
		case components.AgentHeartbeatResponseStateStopped:
			shared.Logger.Info("Agent is stopped, shutting down")
			lib.SendAgentError("Agent is stopped, shutting down", nil, components.SeverityMajor)
			signChan <- syscall.SIGTERM
		case components.AgentHeartbeatResponseStateError:
			shared.Logger.Info("Agent is in error state, stopping processing")
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

// setupAPI initializes the API configuration and context for the CipherSwarm Agent.
func setupAPI() {
	lib.SdkClient = sdk.New(sdk.WithServerURL(shared.State.URL), sdk.WithSecurity(shared.State.APIToken))
	lib.Context = context.Background()
}
