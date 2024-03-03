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
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/lib"

	"github.com/imroc/req/v3"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

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
		os.Exit(1)
	}
}

// init is a function that is automatically called before the execution of the main function.
// It initializes the configuration and sets up the command-line flags for the root command.
func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cipherswarmagent.yaml)")
	viper.SetDefault("pid_file", "lock.pid")
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
		cobra.CheckErr(err)
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".cipherswarmagent")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in. Otherwise, write a new one.
	if err := viper.ReadInConfig(); err == nil {
		log.Debugln("Using config file:", viper.ConfigFileUsed())
	} else {
		err := viper.SafeWriteConfig()
		if err != nil {
			log.Errorln("Error writing config file: ", err)
		}
	}
}

// startAgent is a function that starts the CipherSwarm Agent.
func startAgent(cmd *cobra.Command, args []string) {
	client := req.SetTimeout(5*time.Second).
		SetUserAgent("CipherSwarm Agent/"+lib.AgentVersion).
		SetCommonHeader("Accept", "application/json").
		SetCommonQueryParam("token", viper.GetString("api_token")).
		SetBaseURL(viper.GetString("api_url")).
		DevMode() // Enable development mode TODO: Remove this line in production

	log.Infoln("Starting CipherSwarm Agent")

	// Connect to the CipherSwarm API URL and authenticate
	// Right now, we're just logging the result of the authentication.
	// Failure to authenticate will result in a fatal error.
	agentId, err := lib.AuthenticateAgent(client)
	if err != nil {
		log.Fatalln("Failed to authenticate with the CipherSwarm API")
		os.Exit(1)
	}
	log.Infoln("Agent authenticated with the CipherSwarm API")

	// Get the configuration
	lib.Configuration = lib.GetAgentConfiguration(client)
	log.Infoln("Configuration updated from server")

	// Update the configuration
	lib.UpdateClientConfig()

	// Update the agent metadata with the CipherSwarm API
	lib.UpdateAgentMetadata(client, agentId)
	log.Infoln("Agent metadata updated with the CipherSwarm API")

	// Kill any dangling hashcat processes
	log.Infoln("Checking for dangling hashcat processes")
	CleanUpRunningHashcat()

	// Start the agent loop
	// The agent loop will:
	// - Check if any files are no longer needed and delete them
	// - Check for a new version of hashcat
	//   - If a new version of hashcat is available, download and install it
	// - Check for an updated version of the agent
	//   - If an updated version is available, download and install it
	// - Request a new job from the CipherSwarm API
	//   - If a job is available, download the job and start processing it
	// - If no job is available, sleep for a few seconds and check again
	// For the job processing, we'll set up hashcat and run it in a separate goroutine
	// We'll track the hashcat process and update the CipherSwarm API with the status of the job
	// Once the job is complete, we'll upload the results to the CipherSwarm API
	// We'll also track the resource usage of the machine and the temperature of the GPUs and update the CipherSwarm API with the data
}

// CleanUpRunningHashcat checks for any dangling hashcat processes and kills them if necessary.
// It reads the pid file, checks if the process is running, and kills it using os.FindProcess and os.Process.Kill.
// After killing the process, it removes the pid file.
func CleanUpRunningHashcat() {
	// Check to see if any dangling hashcat processes are running
	// Find the pid file, check for a running process, and kill it if necessary
	if fileExists(viper.GetString("pid_file")) {
		pid_data, err := os.ReadFile(viper.GetString("pid_file"))
		if err != nil {
			log.Errorln("Error reading pid file: ", err)
		}
		log.Debugf("Read pid file: %s", pid_data)

		pid := int(pid_data[0])

		// Check if the process is running
		process, err := os.FindProcess(pid)
		if err != nil {
			log.Errorln("Error finding process: ", err)
		}

		// Kill the process
		err = process.Kill()
		if err != nil {
			if err.Error() == "os: process already finished" {
				log.Debugln("Process already finished")
			} else {
				log.Fatalln("Error killing process: ", err)
				os.Exit(1)
			}
		}

		// Remove the pid file
		err = os.Remove(viper.GetString("pid_file"))
		if err != nil {
			log.Errorln("Error removing pid file: ", err)
		}

		log.Infoln("Killed dangling hashcat process: ", pid)
	}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
