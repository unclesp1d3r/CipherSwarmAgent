// Package cmd /*
package cmd

import (
	"context"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/unclesp1d3r/cipherswarm-agent-go-api"
	"github.com/unclesp1d3r/cipherswarmagent/lib"

	"github.com/charmbracelet/log"
	gap "github.com/muesli/go-app-paths"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	Long:    "CipherSwarm Agent is a command line tool for managing the CipherSwarm.\nIf this is the first run, you need to run the init command to initialize the agent.",
	Run:     startAgent,
}

// Execute runs the root command.
// It executes the rootCmd and exits with code 1 if there is an error.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		lib.Logger.Fatal(err)
	}
}

// init is a function that is automatically called before the execution of the main function.
// It initializes the configuration and sets up the command-line flags for the root command.
func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cipherswarmagent.yaml)")
	rootCmd.PersistentFlags().BoolVar(&enableDebug, "debug", false, "Enable debug mode")

	cwd, err := os.Getwd()
	if err != nil {
		lib.Logger.Fatal("Failed to get current working directory", err)
	}

	viper.SetDefault("data_path", path.Join(cwd, "data"))                        // Set the default data path
	dataRoot := viper.GetString("data_path")                                     // Get the data path
	viper.SetDefault("pid_file", path.Join(dataRoot, "lock.pid"))                // Set the default PID file path
	viper.SetDefault("hashcat_pid_file", path.Join(dataRoot, "hashcat.pid"))     // Set the default hashcat PID file path
	viper.SetDefault("file_path", path.Join(dataRoot, "files"))                  // Set the default file path
	viper.SetDefault("crackers_path", path.Join(dataRoot, "crackers"))           // Set the default crackers path
	viper.SetDefault("hashlist_path", path.Join(dataRoot, "hashlists"))          // Set the default hashlists path
	viper.SetDefault("zaps_path", path.Join(dataRoot, "zaps"))                   // Set the default zaps path
	viper.SetDefault("preprocessors_path", path.Join(dataRoot, "preprocessors")) // Set the default preprocessors path
	viper.SetDefault("tools_path", path.Join(dataRoot, "tools"))                 // Set the default tools path
	viper.SetDefault("out_path", path.Join(dataRoot, "out"))                     // Set the default output path
	viper.SetDefault("debug", false)                                             // Set the default debug mode
	viper.SetDefault("gpu_temp_threshold", 80)                                   // Set the default GPU temperature threshold
	viper.SetDefault("benchmark_update_frequency", 168*time.Hour)                // Set the default benchmark age in hours (7 days)
	viper.SetDefault("always_use_native_hashcat", false)                         // Set the default to not always use native hashcat

	if viper.GetBool("debug") {
		lib.Logger.SetLevel(log.DebugLevel) // Set the logger level to debug
		lib.Logger.SetReportCaller(true)    // Report the caller for debugging
	} else {
		lib.Logger.SetLevel(log.InfoLevel)
	}
}

// initConfig initializes the configuration for the CipherSwarmAgent.
// It checks if a configuration file is provided, and if not, it sets the default configuration file path.
// It also reads environment variables and attempts to read the configuration file.
// If a configuration file is found, it logs the file path.
// If no configuration file is found, it writes a new one.
func initConfig() {
	home, err := os.UserConfigDir()
	cobra.CheckErr(err) // Check for errors
	configDirs, err := scope.ConfigDirs()
	cobra.CheckErr(err)              // Check for errors
	cwd, err := os.Getwd()           // Get the current working directory
	cobra.CheckErr(err)              // Check for errors
	viper.AddConfigPath(cwd)         // Add the current working directory to the configuration path
	for _, dir := range configDirs { // Add the config directories to the configuration path
		viper.AddConfigPath(dir)
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
		lib.Logger.Info("Using config file", "config_file", viper.ConfigFileUsed())
	} else {
		err := viper.SafeWriteConfig()
		if err != nil {
			if err.Error() != "config file already exists" {
				lib.Logger.Error("Error writing config file: ", "error", err)
			}
		}
	}
}

// startAgent is a function that starts the CipherSwarm Agent.
//
//goland:noinspection GoUnusedParameter,GoUnusedParameter
func startAgent(cmd *cobra.Command, args []string) {
	if viper.GetString("api_url") == "" {
		lib.Logger.Fatal("API URL not set")
	}
	if viper.GetString("api_token") == "" {
		lib.Logger.Fatal("API token not set")
	}

	signChan := make(chan os.Signal, 1)
	// Set up a signal handler to catch SIGINT and SIGTERM
	// This will allow us to clean up the PID file when the agent is stopped
	// We'll also use this to clean up any dangling hashcat processes
	signal.Notify(signChan, os.Interrupt, syscall.SIGTERM)
	if enableDebug {
		lib.Logger.SetLevel(log.DebugLevel)
	} else {
		lib.Logger.SetLevel(log.InfoLevel)
	}

	setupAPI()

	lib.Logger.Info("Starting CipherSwarm Agent")

	pidFilePath := viper.GetString("pid_file")
	// Check if the agent is already running
	// I don't think this works the way I thought it would. I will probably need to change this.
	lockFound, err := lib.CleanUpDanglingProcess(pidFilePath)
	if err != nil {
		lib.Logger.Fatal("Error checking for dangling processes", "error", err)
	}
	if lockFound {
		lib.Logger.Fatal("Aborting agent start, lock file found", "path", pidFilePath)
	}

	err = lib.CreateDataDirs() // Create the data directories
	if err != nil {
		lib.Logger.Fatal("Error creating data directories", "error", err)
	}

	// Write the PID file
	pidFile, _ := lib.CreateLockFile()
	defer cleanUpPidFile()(pidFile.Name())

	// Connect to the CipherSwarm API URL and authenticate
	// Right now, we're just logging the result of the authentication.
	// Failure to authenticate will result in a fatal error.
	agentID, err := lib.AuthenticateAgent()
	if err != nil {
		lib.Logger.Fatal("Failed to authenticate with the CipherSwarm API", "error", err)
	}
	lib.Logger.Info("Agent authenticated with the CipherSwarm API")

	// Get the configuration
	lib.Configuration, err = lib.GetAgentConfiguration()
	if err != nil {
		lib.Logger.Fatal("Failed to get agent configuration from the CipherSwarm API", "error", err)
	}

	// Update the configuration
	lib.UpdateClientConfig()
	lib.Logger.Info("Configuration updated from server")
	// Update the agent metadata with the CipherSwarm API
	lib.UpdateAgentMetadata(agentID)
	lib.Logger.Info("Sent agent metadata to the CipherSwarm API")

	// Kill any dangling hashcat processes
	processFound, err := lib.CleanUpDanglingProcess(viper.GetString("hashcat_pid_file"))
	if err != nil {
		lib.Logger.Fatal("Error checking for dangling hashcat processes", "error", err)
	}
	if processFound {
		lib.Logger.Info("Killed dangling hashcat process")
	}

	// Start the agent loop
	go func() {
		for {
			// The agent loop will:
			// - Check if any files are no longer needed and delete them
			// - Check for a new version of hashcat
			//   - If a new version of hashcat is available, download and install it
			// - Request a new job from the CipherSwarm API

			if !lib.Configuration.Config.UseNativeHashcat {
				lib.UpdateCracker() // Should we update the cracker on every loop? It doesn't change often
			}

			// - Check for an updated version of the agent
			//   - If an updated version is available, download and install it

			// - Check if we need to update the agent benchmarks
			//   - If we need to update the benchmarks, run the benchmarks and upload the results to the CipherSwarm API
			benchmarkUpdateCheck(agentID)

			// - Request a new job from the CipherSwarm API
			//   - If a job is available, download the job and start processing it
			task, err := lib.GetNewTask()

			if err != nil {
				lib.Logger.Error("Failed to get new task", "error", err)
			}
			if task != nil {
				lib.Logger.Info("New task available", "task", task)

				// Process the task
				// - Get the attack parameters
				attack, err := lib.GetAttackParameters(task.GetAttackId())
				if err != nil {
					lib.Logger.Error("Failed to get attack parameters", "error", err)
				}
				lib.Logger.Info("Attack parameters", "attack", attack)

				// - Download the files
				err = lib.DownloadFiles(attack)
				if err != nil {
					lib.Logger.Error("Failed to download files", "error", err)
				}

				// - Run the job
				lib.RunTask(task, attack)
				// - Upload the results
				// - Update the CipherSwarm API with the status of the job

				// For the job processing, we'll set up hashcat and run it in a separate goroutine
				// We'll track the hashcat process and update the CipherSwarm API with the status of the job
				// Once the job is complete, we'll upload the results to the CipherSwarm API
				// We'll also track the resource usage of the machine and the temperature of the GPUs and update the CipherSwarm API with the data
			} else {
				lib.Logger.Info("No new task available")
			}
			sleepTime := time.Duration(lib.Configuration.Config.AgentUpdateInterval) * time.Second
			lib.Logger.Info("Sleeping", "seconds", sleepTime)
			lib.SendHeartBeat(agentID)
			time.Sleep(sleepTime)
		}
	}()

	sig := <-signChan // Wait for a signal to shut down the agent
	lib.Logger.Debug("Received signal", "signal", sig)
	lib.Logger.Info("Shutting down CipherSwarm Agent")
}

func benchmarkUpdateCheck(agentID int64) {
	benchmarkFrequency := viper.GetDuration("benchmark_update_frequency")
	oldestUpdate := time.Now().Add(-benchmarkFrequency)
	lastBenchmarkDate, err := lib.GetLastBenchmarkDate(agentID)
	if err != nil {
		lib.Logger.Error("Failed to get last benchmark date", "error", err)
		return
	}
	lib.Logger.Debug("Got benchmark age", "benchmark_age", time.Since(lastBenchmarkDate).String())

	if lastBenchmarkDate.Before(oldestUpdate) {
		lib.Logger.Info("Benchmarks out of date", "benchmark_age", time.Since(lastBenchmarkDate).String(),
			"maximum_age", oldestUpdate.String())
		lib.UpdateBenchmarks(agentID)
		lib.Logger.Info("Updated benchmarks")
	} else {
		lib.Logger.Info("Benchmarks up to date")
	}
}

// setupAPI initializes the API configuration and context for the CipherSwarm Agent.
func setupAPI() {
	lib.APIConfiguration.Debug = enableDebug
	lib.APIConfiguration.UserAgent = "CipherSwarm Agent/" + lib.AgentVersion
	lib.APIConfiguration.Servers = cipherswarm.ServerConfigurations{
		{
			URL: viper.GetString("api_url"),
		},
	}
	lib.Context = context.WithValue(context.Background(), cipherswarm.ContextAccessToken, viper.GetString("api_token"))

}

// cleanUpPidFile returns a function that can be used to clean up a PID file.
// The returned function takes a `pidFile` string parameter and removes the file from the file system.
// If an error occurs while removing the file, it logs a fatal error.
func cleanUpPidFile() func(pidFile string) {
	return func(pidFile string) {
		lib.Logger.Debug("Cleaning up PID file", "path", pidFile)

		err := lib.AppFs.Remove(pidFile)
		if err != nil {
			lib.Logger.Fatal("Failed to remove PID file", "error", err)
		}
	}
}
