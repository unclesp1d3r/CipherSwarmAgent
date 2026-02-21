// Package cmd provides the command-line interface for the CipherSwarm Agent.
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib"
	"github.com/unclesp1d3r/cipherswarmagent/lib/agent"
	"github.com/unclesp1d3r/cipherswarmagent/lib/config"
)

var (
	cfgFile           string //nolint:gochecknoglobals // CLI flag variable
	enableDebug       bool   //nolint:gochecknoglobals // CLI flag variable
	forceBenchmarkRun bool   //nolint:gochecknoglobals // CLI flag variable
)

// RootCmd represents the base command for the CipherSwarm Agent CLI application.
var RootCmd = &cobra.Command{ //nolint:gochecknoglobals // CLI root command
	Use:     "cipherswarm-agent",
	Version: lib.AgentVersion,
	Short:   "CipherSwarm Agent",
	Long:    "CipherSwarm Agent is the agent for connecting to the CipherSwarm system.",
	Run: func(_ *cobra.Command, _ []string) {
		agent.StartAgent()
	},
}

// Execute runs the root command and checks for any errors that occur during its execution.
func Execute() {
	err := RootCmd.Execute()
	cobra.CheckErr(err)
}

// init initializes the root command and binds various flags to the configuration using Viper.
// It sets up the required flags and binds them to configuration variables for easy access throughout the application.
func init() {
	cobra.OnInitialize(func() {
		config.InitConfig(cfgFile)
	})
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cipherswarmagent.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&enableDebug, "debug", "d", false, "Enable debug mode")
	err := viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("debug"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().StringP("api_token", "a", "", "API token for the CipherSwarm server")
	err = viper.BindPFlag("api_token", RootCmd.PersistentFlags().Lookup("api_token"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().StringP("api_url", "u", "", "URL of the CipherSwarm server")
	err = viper.BindPFlag("api_url", RootCmd.PersistentFlags().Lookup("api_url"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().StringP("data_path", "p", "", "Path to the directory where the agent will store data")
	err = viper.BindPFlag("data_path", RootCmd.PersistentFlags().Lookup("data_path"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		IntP("gpu_temp_threshold", "g", config.DefaultGPUTempThreshold, "Temperature threshold for the GPU in degrees Celsius")
	err = viper.BindPFlag("gpu_temp_threshold", RootCmd.PersistentFlags().Lookup("gpu_temp_threshold"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().BoolP("always_use_native_hashcat", "n", false, "Force using the native hashcat binary")
	err = viper.BindPFlag("always_use_native_hashcat", RootCmd.PersistentFlags().Lookup("always_use_native_hashcat"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		DurationP("sleep_on_failure", "s", config.DefaultSleepOnFailure, "Duration of sleep after a task failure")
	err = viper.BindPFlag("sleep_on_failure", RootCmd.PersistentFlags().Lookup("sleep_on_failure"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		StringP("files_path", "f", "", "Path to the directory where the agent will store task files")
	err = viper.BindPFlag("files_path", RootCmd.PersistentFlags().Lookup("files_path"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().BoolP("extra_debugging", "e", false, "Enable additional debugging information")
	err = viper.BindPFlag("extra_debugging", RootCmd.PersistentFlags().Lookup("extra_debugging"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		IntP("status_timer", "t", config.DefaultStatusTimer, "Interval in seconds for sending status updates to the server")
	err = viper.BindPFlag("status_timer", RootCmd.PersistentFlags().Lookup("status_timer"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		DurationP("heartbeat_interval", "", config.DefaultHeartbeatInterval, "Interval between heartbeat messages to the server")
	err = viper.BindPFlag("heartbeat_interval", RootCmd.PersistentFlags().Lookup("heartbeat_interval"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		BoolP("write_zaps_to_file", "w", false, "Write zap output to a file in the zaps directory")
	err = viper.BindPFlag("write_zaps_to_file", RootCmd.PersistentFlags().Lookup("write_zaps_to_file"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		StringP("zap_path", "z", "", "Path to the directory where the agent will store zap output files")
	err = viper.BindPFlag("zap_path", RootCmd.PersistentFlags().Lookup("zap_path"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().BoolP("retain_zaps_on_completion", "r", false, "Retain zap files after completing a task")
	err = viper.BindPFlag("retain_zaps_on_completion", RootCmd.PersistentFlags().Lookup("retain_zaps_on_completion"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Duration("task_timeout", config.DefaultTaskTimeout, "Maximum time for a single task before timeout")
	err = viper.BindPFlag("task_timeout", RootCmd.PersistentFlags().Lookup("task_timeout"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Int("download_max_retries", config.DefaultDownloadMaxRetries, "Maximum number of download retry attempts")
	err = viper.BindPFlag("download_max_retries", RootCmd.PersistentFlags().Lookup("download_max_retries"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Duration("download_retry_delay", config.DefaultDownloadRetryDelay, "Base delay between download retries (exponential backoff)")
	err = viper.BindPFlag("download_retry_delay", RootCmd.PersistentFlags().Lookup("download_retry_delay"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Bool("insecure_downloads", false, "Skip TLS certificate verification for downloads (insecure)")
	err = viper.BindPFlag("insecure_downloads", RootCmd.PersistentFlags().Lookup("insecure_downloads"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Int("max_heartbeat_backoff", config.DefaultMaxHeartbeatBackoff, "Maximum heartbeat backoff multiplier (caps exponential backoff)")
	err = viper.BindPFlag("max_heartbeat_backoff", RootCmd.PersistentFlags().Lookup("max_heartbeat_backoff"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		BoolVar(&forceBenchmarkRun, "force-benchmark", false, "Force re-run of benchmarks, bypassing cache")
	err = viper.BindPFlag("force_benchmark_run", RootCmd.PersistentFlags().Lookup("force-benchmark"))
	cobra.CheckErr(err)

	config.SetDefaultConfigValues()
}
