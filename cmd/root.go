// Package cmd provides the command-line interface for the CipherSwarm Agent.
package cmd

import (
	"fmt"

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
	PersistentPreRun: func(cmd *cobra.Command, _ []string) {
		bridgeDeprecatedFlags(cmd)
	},
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

	RootCmd.PersistentFlags().StringP("api-token", "a", "", "API token for the CipherSwarm server")
	err = viper.BindPFlag("api_token", RootCmd.PersistentFlags().Lookup("api-token"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().StringP("api-url", "u", "", "URL of the CipherSwarm server")
	err = viper.BindPFlag("api_url", RootCmd.PersistentFlags().Lookup("api-url"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().StringP("data-path", "p", "", "Path to the directory where the agent will store data")
	err = viper.BindPFlag("data_path", RootCmd.PersistentFlags().Lookup("data-path"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		IntP("gpu-temp-threshold", "g", config.DefaultGPUTempThreshold, "Temperature threshold for the GPU in degrees Celsius")
	err = viper.BindPFlag("gpu_temp_threshold", RootCmd.PersistentFlags().Lookup("gpu-temp-threshold"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().BoolP("always-use-native-hashcat", "n", false, "Force using the native hashcat binary")
	err = viper.BindPFlag("always_use_native_hashcat", RootCmd.PersistentFlags().Lookup("always-use-native-hashcat"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		DurationP("sleep-on-failure", "s", config.DefaultSleepOnFailure, "Duration of sleep after a task failure")
	err = viper.BindPFlag("sleep_on_failure", RootCmd.PersistentFlags().Lookup("sleep-on-failure"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		StringP("files-path", "f", "", "Path to the directory where the agent will store task files")
	err = viper.BindPFlag("files_path", RootCmd.PersistentFlags().Lookup("files-path"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().BoolP("extra-debugging", "e", false, "Enable additional debugging information")
	err = viper.BindPFlag("extra_debugging", RootCmd.PersistentFlags().Lookup("extra-debugging"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		IntP("status-timer", "t", config.DefaultStatusTimer, "Interval in seconds for sending status updates to the server")
	err = viper.BindPFlag("status_timer", RootCmd.PersistentFlags().Lookup("status-timer"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Duration("heartbeat-interval", config.DefaultHeartbeatInterval, "Interval between heartbeat messages to the server")
	err = viper.BindPFlag("heartbeat_interval", RootCmd.PersistentFlags().Lookup("heartbeat-interval"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		BoolP("write-zaps-to-file", "w", false, "Write zap output to a file in the zaps directory")
	err = viper.BindPFlag("write_zaps_to_file", RootCmd.PersistentFlags().Lookup("write-zaps-to-file"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		StringP("zap-path", "z", "", "Path to the directory where the agent will store zap output files")
	err = viper.BindPFlag("zap_path", RootCmd.PersistentFlags().Lookup("zap-path"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().BoolP("retain-zaps-on-completion", "r", false, "Retain zap files after completing a task")
	err = viper.BindPFlag("retain_zaps_on_completion", RootCmd.PersistentFlags().Lookup("retain-zaps-on-completion"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Duration("task-timeout", config.DefaultTaskTimeout, "Maximum time for a single task before timeout")
	err = viper.BindPFlag("task_timeout", RootCmd.PersistentFlags().Lookup("task-timeout"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Int("download-max-retries", config.DefaultDownloadMaxRetries, "Maximum number of download retry attempts")
	err = viper.BindPFlag("download_max_retries", RootCmd.PersistentFlags().Lookup("download-max-retries"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Duration("download-retry-delay", config.DefaultDownloadRetryDelay, "Base delay between download retries (exponential backoff)")
	err = viper.BindPFlag("download_retry_delay", RootCmd.PersistentFlags().Lookup("download-retry-delay"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Bool("insecure-downloads", false, "Skip TLS certificate verification for downloads (insecure)")
	err = viper.BindPFlag("insecure_downloads", RootCmd.PersistentFlags().Lookup("insecure-downloads"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Int("max-heartbeat-backoff", config.DefaultMaxHeartbeatBackoff, "Maximum heartbeat backoff multiplier (caps exponential backoff)")
	err = viper.BindPFlag("max_heartbeat_backoff", RootCmd.PersistentFlags().Lookup("max-heartbeat-backoff"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		BoolVar(&forceBenchmarkRun, "force-benchmark", false, "Force re-run of benchmarks, bypassing cache")
	err = viper.BindPFlag("force_benchmark_run", RootCmd.PersistentFlags().Lookup("force-benchmark"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Bool("always-trust-files", false, "Skip checksum verification for downloaded files (not recommended)")
	err = viper.BindPFlag("always_trust_files", RootCmd.PersistentFlags().Lookup("always-trust-files"))
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Bool("enable-additional-hash-types", true, "Enable support for additional hash types during benchmarking")
	err = viper.BindPFlag(
		"enable_additional_hash_types",
		RootCmd.PersistentFlags().Lookup("enable-additional-hash-types"),
	)
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		Bool("use-legacy-device-technique", false, "Use legacy device identification method (not recommended)")
	err = viper.BindPFlag(
		"use_legacy_device_technique",
		RootCmd.PersistentFlags().Lookup("use-legacy-device-technique"),
	)
	cobra.CheckErr(err)

	RootCmd.PersistentFlags().
		String("hashcat-path", "", "Path to custom hashcat binary (overrides automatic detection)")
	err = viper.BindPFlag("hashcat_path", RootCmd.PersistentFlags().Lookup("hashcat-path"))
	cobra.CheckErr(err)

	// Register deprecated underscore aliases for backward compatibility.
	registerDeprecatedAliases()

	config.SetDefaultConfigValues()
}

// deprecatedAlias maps a deprecated underscore flag to its canonical kebab-case replacement.
type deprecatedAlias struct {
	oldName  string
	newName  string
	flagType string
}

// deprecatedFlags lists all underscore-style flag aliases and their kebab-case replacements.
//
//nolint:gochecknoglobals // package-level lookup table for deprecated flag aliases
var deprecatedFlags = []deprecatedAlias{
	{"api_token", "api-token", "string"},
	{"api_url", "api-url", "string"},
	{"data_path", "data-path", "string"},
	{"gpu_temp_threshold", "gpu-temp-threshold", "int"},
	{"always_use_native_hashcat", "always-use-native-hashcat", "bool"},
	{"sleep_on_failure", "sleep-on-failure", "duration"},
	{"files_path", "files-path", "string"},
	{"extra_debugging", "extra-debugging", "bool"},
	{"status_timer", "status-timer", "int"},
	{"heartbeat_interval", "heartbeat-interval", "duration"},
	{"write_zaps_to_file", "write-zaps-to-file", "bool"},
	{"zap_path", "zap-path", "string"},
	{"retain_zaps_on_completion", "retain-zaps-on-completion", "bool"},
	{"task_timeout", "task-timeout", "duration"},
	{"download_max_retries", "download-max-retries", "int"},
	{"download_retry_delay", "download-retry-delay", "duration"},
	{"insecure_downloads", "insecure-downloads", "bool"},
	{"max_heartbeat_backoff", "max-heartbeat-backoff", "int"},
}

// registerDeprecatedAliases registers hidden, deprecated underscore-style flag aliases.
// These flags are NOT bound to Viper — the canonical kebab-case flags retain their bindings.
// Values are bridged to canonical flags via bridgeDeprecatedFlags in PersistentPreRun.
func registerDeprecatedAliases() {
	flags := RootCmd.PersistentFlags()
	for _, df := range deprecatedFlags {
		// Zero-value defaults are safe: bridgeDeprecatedFlags only copies when
		// old.Changed is true (user explicitly passed the flag on the CLI).
		switch df.flagType {
		case "string":
			flags.String(df.oldName, "", "")
		case "bool":
			flags.Bool(df.oldName, false, "")
		case "int":
			flags.Int(df.oldName, 0, "")
		case "duration":
			flags.Duration(df.oldName, 0, "")
		default:
			panic("unknown flag type " + df.flagType + " for deprecated alias " + df.oldName)
		}

		cobra.CheckErr(flags.MarkDeprecated(df.oldName, "use --"+df.newName+" instead"))
	}
}

// bridgeDeprecatedFlags copies explicitly-set deprecated underscore flag values
// into their canonical kebab-case counterparts so Viper picks them up.
// If both the deprecated and canonical flag are set, the canonical value takes precedence.
func bridgeDeprecatedFlags(cmd *cobra.Command) {
	flags := cmd.Root().PersistentFlags()
	for _, df := range deprecatedFlags {
		old := flags.Lookup(df.oldName)
		if old == nil || !old.Changed {
			continue
		}

		canonical := flags.Lookup(df.newName)
		if canonical == nil || canonical.Changed {
			continue
		}

		// Copy value from deprecated flag to canonical flag only when
		// the canonical flag was not explicitly set by the user.
		if err := canonical.Value.Set(old.Value.String()); err != nil {
			cobra.CheckErr(fmt.Errorf("bridging deprecated flag --%s to --%s: %w", df.oldName, df.newName, err))
		}
		canonical.Changed = true
	}
}
