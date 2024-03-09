/*
Copyright © 2024 UncleSp1d3r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/lib"

	"github.com/charmbracelet/log"
	"github.com/imroc/req/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var enableDebug bool
var logger = *lib.Logger // Set the logger to the global logger instance

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
		logger.Fatal(err)
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
		logger.Fatal("Failed to get current working directory", err)
	}
	viper.SetDefault("data_path", cwd)                                           // Set the default data path
	dataRoot := viper.GetString("data_path")                                     // Get the data path
	viper.SetDefault("pid_file", path.Join(dataRoot, "lock.pid"))                // Set the default PID file path
	viper.SetDefault("hashcat_pid_file", path.Join(dataRoot, "hashcat.pid"))     // Set the default hashcat PID file path
	viper.SetDefault("file_path", path.Join(dataRoot, "files"))                  // Set the default file path
	viper.SetDefault("crackers_path", path.Join(dataRoot, "crackers"))           // Set the default crackers path
	viper.SetDefault("hashlist_path", path.Join(dataRoot, "hashlists"))          // Set the default hashlists path
	viper.SetDefault("zaps_path", path.Join(dataRoot, "zaps"))                   // Set the default zaps path
	viper.SetDefault("preprocessors_path", path.Join(dataRoot, "preprocessors")) // Set the default preprocessors path
	viper.SetDefault("debug", false)                                             // Set the default debug mode
	viper.SetDefault("gpu_temp_threshold", 80)                                   // Set the default GPU temperature threshold

	if viper.GetBool("debug") {
		logger.SetLevel(log.DebugLevel) // Set the logger level to debug
		logger.SetReportCaller(true)    // Report the caller for debugging
	} else {
		logger.SetLevel(log.InfoLevel)
	}
}

// initConfig initializes the configuration for the CipherSwarmAgent.
// It checks if a configuration file is provided, and if not, it sets the default configuration file path.
// It also reads environment variables and attempts to read the configuration file.
// If a configuration file is found, it logs the file path.
// If no configuration file is found, it writes a new one.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)                      // Check for errors
		viper.AddConfigPath(home)                // Add the home directory to the configuration path
		viper.SetConfigType("yaml")              // Set the configuration type to YAML
		viper.SetConfigName(".cipherswarmagent") // Set the configuration name
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in. Otherwise, write a new one.
	if err := viper.ReadInConfig(); err == nil {
		logger.Debug("Using config file:", viper.ConfigFileUsed())
	} else {
		err := viper.SafeWriteConfig()
		if err != nil {
			if err.Error() != "config file already exists" {
				logger.Error("Error writing config file: ", "error", err)
			}
		}
	}
}

// startAgent is a function that starts the CipherSwarm Agent.
func startAgent(cmd *cobra.Command, args []string) {
	if viper.GetString("api_url") == "" {
		logger.Fatal("API URL not set")
	}
	if viper.GetString("api_token") == "" {
		logger.Fatal("API token not set")
	}

	signChan := make(chan os.Signal, 1)
	// Set up a signal handler to catch SIGINT and SIGTERM
	// This will allow us to clean up the PID file when the agent is stopped
	// We'll also use this to clean up any dangling hashcat processes
	signal.Notify(signChan, os.Interrupt, syscall.SIGTERM)

	client := req.SetTimeout(5*time.Second). // Set a 5-second timeout
							SetUserAgent("CipherSwarm Agent/"+lib.AgentVersion).          // Set a common user agent
							SetCommonHeader("Accept", "application/json").                // Accept only JSON responses
							SetBaseURL(viper.GetString("api_url")).                       // Set the base URL for the API
							SetCommonBearerAuthToken(viper.GetString("api_token")).       // Set the API token as a common bearer token
							SetCommonRetryCount(5).                                       // Retry 5 times
							SetCommonRetryBackoffInterval(5*time.Second, 30*time.Second). // Retry with exponential backoff
							AddCommonRetryCondition(func(resp *req.Response, err error) bool {
			// Retry on 5xx status codes, 408, and 429, and on error
			// 500-599: Server error
			// 408: Request timeout
			// 429: Too many requests
			return err != nil || resp.StatusCode >= 500 || resp.StatusCode == 408 || resp.StatusCode == 429
		}).
		SetLogger(&logger) // Set the logger to the global logger instance

	if enableDebug {
		logger.SetLevel(log.DebugLevel)
		client.DevMode()
	} else {
		logger.SetLevel(log.InfoLevel)
	}

	logger.Info("Starting CipherSwarm Agent")

	pidFilePath := viper.GetString("pid_file")
	// Check if the agent is already running
	lockFound, err := lib.CleanUpDanglingProcess(pidFilePath, false)
	if err != nil {
		logger.Fatal("Error checking for dangling processes", "error", err)
	}
	if lockFound {
		logger.Info("Agent already running", "pid_file", pidFilePath)
		logger.Fatal("Aborting agent start, remove the PID file to start the agent again")
	}

	// Write the PID file
	pidFile, _ := lib.CreateLockFile()
	defer cleanUpPidFile()(pidFile.Name())

	// Connect to the CipherSwarm API URL and authenticate
	// Right now, we're just logging the result of the authentication.
	// Failure to authenticate will result in a fatal error.
	agentID, err := lib.AuthenticateAgent(client)
	if err != nil {
		logger.Fatal("Failed to authenticate with the CipherSwarm API", "error", err)
	}
	logger.Info("Agent authenticated with the CipherSwarm API")

	// Get the configuration
	lib.Configuration, err = lib.GetAgentConfiguration(client)
	if err != nil {
		logger.Fatal("Failed to get agent configuration from the CipherSwarm API", "error", err)
	}
	// Update the configuration
	lib.UpdateClientConfig()
	logger.Info("Configuration updated from server")

	// Update the agent metadata with the CipherSwarm API
	lib.UpdateAgentMetadata(client, agentID)

	// Kill any dangling hashcat processes
	processFound, err := lib.CleanUpDanglingProcess(viper.GetString("hashcat_pid_file"), true)
	if err != nil {
		logger.Fatal("Error checking for dangling hashcat processes", "error", err)
	}
	if processFound {
		logger.Info("Killed dangling hashcat process")
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
				lib.UpdateCracker(client)
			}

			// - Check for an updated version of the agent
			//   - If an updated version is available, download and install it
			// - Request a new job from the CipherSwarm API
			//   - If a job is available, download the job and start processing it
			// - If no job is available, sleep for a few seconds and check again
			// For the job processing, we'll set up hashcat and run it in a separate goroutine
			// We'll track the hashcat process and update the CipherSwarm API with the status of the job
			// Once the job is complete, we'll upload the results to the CipherSwarm API
			// We'll also track the resource usage of the machine and the temperature of the GPUs and update the CipherSwarm API with the data

			logger.Info("No job available, sleeping for 5 seconds")
			time.Sleep(5 * time.Second)
		}
	}()

	sig := <-signChan // Wait for a signal to shut down the agent
	logger.Debug("Received signal", "signal", sig)
	logger.Info("Shutting down CipherSwarm Agent")
}

// cleanUpPidFile returns a function that can be used to clean up a PID file.
// The returned function takes a `pidFile` string parameter and removes the file from the file system.
// If an error occurs while removing the file, it logs a fatal error.
func cleanUpPidFile() func(pidFile string) {
	return func(pidFile string) {
		logger.Debug("Cleaning up PID file", "path", pidFile)

		err := lib.AppFs.Remove(pidFile)
		if err != nil {
			logger.Fatal("Failed to remove PID file", "error", err)
		}
	}
}
