// Package config provides configuration management for the CipherSwarm agent.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	gap "github.com/muesli/go-app-paths"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// Default configuration values — the single source of truth for all defaults.
// cmd/root.go references these exported constants for CLI flag defaults.
const (
	// DefaultGPUTempThreshold is the GPU temperature threshold in Celsius.
	DefaultGPUTempThreshold = 80
	// DefaultSleepOnFailure is the sleep duration after task failure.
	DefaultSleepOnFailure = 60 * time.Second
	// DefaultStatusTimer is the status update interval in seconds.
	DefaultStatusTimer = 10
	// DefaultHeartbeatInterval is the heartbeat interval.
	DefaultHeartbeatInterval = 10 * time.Second
	// DefaultTaskTimeout is the task timeout (long-running tasks are expected).
	DefaultTaskTimeout = 24 * time.Hour
	// DefaultDownloadMaxRetries is the max download retry attempts.
	DefaultDownloadMaxRetries = 3
	// DefaultDownloadRetryDelay is the base delay between download retries.
	DefaultDownloadRetryDelay = 2 * time.Second
	// DefaultInsecureDownloads controls TLS certificate verification for downloads.
	DefaultInsecureDownloads = false
	// DefaultMaxHeartbeatBackoff is the max heartbeat backoff multiplier (caps at 64x).
	DefaultMaxHeartbeatBackoff = 6
)

var scope = gap.NewScope(gap.User, "CipherSwarm") //nolint:gochecknoglobals // Configuration scope

// InitConfig initializes the configuration from various sources.
func InitConfig(cfgFile string) {
	agentstate.ErrorLogger.SetReportCaller(true)

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
		agentstate.Logger.Info("Using config file", "config_file", viper.ConfigFileUsed())
	} else {
		var notFoundErr viper.ConfigFileNotFoundError
		if errors.As(err, &notFoundErr) {
			agentstate.Logger.Warn("No config file found, attempting to write a new one")

			var alreadyExistsErr viper.ConfigFileAlreadyExistsError
			if writeErr := viper.SafeWriteConfig(); writeErr != nil && !errors.As(writeErr, &alreadyExistsErr) {
				agentstate.Logger.Error("Error writing config file", "error", writeErr)
			}
		} else {
			agentstate.Logger.Error("Error reading config file", "error", err)
		}
	}
}

// SetupSharedState configures the shared state from configuration values.
func SetupSharedState() {
	// Set the API URL and token
	agentstate.State.URL = viper.GetString("api_url")
	agentstate.State.APIToken = viper.GetString("api_token")

	dataRoot := viper.GetString(
		"data_path",
	) // Get the data path from the configuration
	agentstate.State.DataPath = dataRoot // Set the data path in the shared state
	agentstate.State.PidFile = filepath.Join(
		dataRoot,
		"lock.pid",
	) // Set the default PID file path
	agentstate.State.HashcatPidFile = filepath.Join(
		dataRoot,
		"hashcat.pid",
	) // Set the default hashcat PID file path
	agentstate.State.CrackersPath = filepath.Join(
		dataRoot,
		"crackers",
	) // Set the crackers path in the shared state
	agentstate.State.FilePath = viper.GetString("files_path")
	if agentstate.State.FilePath == "" {
		agentstate.State.FilePath = filepath.Join(dataRoot, "files")
	}
	agentstate.State.HashlistPath = filepath.Join(
		dataRoot,
		"hashlists",
	) // Set the hashlist path in the shared state
	agentstate.State.ZapsPath = viper.GetString("zap_path")
	if agentstate.State.ZapsPath == "" {
		agentstate.State.ZapsPath = filepath.Join(dataRoot, "zaps")
	}
	agentstate.State.PreprocessorsPath = filepath.Join(
		dataRoot,
		"preprocessors",
	) // Set the preprocessors path in the shared state
	agentstate.State.ToolsPath = filepath.Join(
		dataRoot,
		"tools",
	) // Set the tools path in the shared state
	agentstate.State.OutPath = filepath.Join(
		dataRoot,
		"output",
	) // Set the output path in the shared state
	agentstate.State.RestoreFilePath = filepath.Join(
		dataRoot,
		"restore",
	) // Set the restore file path in the shared state
	agentstate.State.BenchmarkCachePath = filepath.Join(
		dataRoot,
		"benchmark_cache.json",
	) // Set the benchmark cache file path in the shared state
	agentstate.State.Debug = viper.GetBool(
		"debug",
	) // Set the debug flag in the shared state
	agentstate.State.AlwaysTrustFiles = viper.GetBool(
		"always_trust_files",
	) // Set the always trust files flag in the shared state
	agentstate.State.ExtraDebugging = viper.GetBool(
		"extra_debugging",
	) // Set the extra debugging flag in the shared state
	agentstate.State.StatusTimer = viper.GetInt(
		"status_timer",
	) // Set the status timer in the shared state
	agentstate.State.WriteZapsToFile = viper.GetBool(
		"write_zaps_to_file",
	) // Set the write zaps to file flag in the shared state
	agentstate.State.RetainZapsOnCompletion = viper.GetBool(
		"retain_zaps_on_completion",
	) // Set the retain zaps on completion flag in the shared state
	agentstate.State.EnableAdditionalHashTypes = viper.GetBool(
		"enable_additional_hash_types",
	) // Set the enable additional hash types flag in the shared state
	agentstate.State.HashcatPath = viper.GetString(
		"hashcat_path",
	) // Set the hashcat binary path in the shared state
	agentstate.State.UseLegacyDeviceIdentificationMethod = viper.GetBool(
		"use_legacy_device_technique",
	) // Set the use legacy device identification method flag in the shared state
	agentstate.State.ForceBenchmarkRun = viper.GetBool("force_benchmark_run")
	agentstate.State.InsecureDownloads = viper.GetBool("insecure_downloads")
	agentstate.State.AlwaysUseNativeHashcat = viper.GetBool("always_use_native_hashcat")

	// Validate numeric/duration config fields — clamp to defaults with a warning.
	agentstate.State.DownloadMaxRetries = viper.GetInt("download_max_retries")
	if agentstate.State.DownloadMaxRetries < 1 {
		agentstate.Logger.Warn("download_max_retries must be >= 1, using default",
			"configured", agentstate.State.DownloadMaxRetries, "default", DefaultDownloadMaxRetries)
		agentstate.State.DownloadMaxRetries = DefaultDownloadMaxRetries
	}

	agentstate.State.DownloadRetryDelay = viper.GetDuration("download_retry_delay")

	agentstate.State.TaskTimeout = viper.GetDuration("task_timeout")
	if agentstate.State.TaskTimeout <= 0 {
		agentstate.Logger.Warn("task_timeout must be > 0, using default",
			"configured", agentstate.State.TaskTimeout, "default", DefaultTaskTimeout)
		agentstate.State.TaskTimeout = DefaultTaskTimeout
	}

	agentstate.State.MaxHeartbeatBackoff = viper.GetInt("max_heartbeat_backoff")
	if agentstate.State.MaxHeartbeatBackoff < 0 {
		agentstate.Logger.Warn("max_heartbeat_backoff must be >= 0, using default",
			"configured", agentstate.State.MaxHeartbeatBackoff, "default", DefaultMaxHeartbeatBackoff)
		agentstate.State.MaxHeartbeatBackoff = DefaultMaxHeartbeatBackoff
	}

	agentstate.State.SleepOnFailure = viper.GetDuration("sleep_on_failure")
}

// SetDefaultConfigValues sets default configuration values.
func SetDefaultConfigValues() {
	cwd, err := os.Getwd()
	cobra.CheckErr(err)

	viper.SetDefault("data_path", filepath.Join(cwd, "data"))
	viper.SetDefault("gpu_temp_threshold", DefaultGPUTempThreshold)
	viper.SetDefault("always_use_native_hashcat", false)
	viper.SetDefault("hashcat_path", "")
	viper.SetDefault("sleep_on_failure", DefaultSleepOnFailure)
	viper.SetDefault("always_trust_files", false)
	// files_path and zap_path are derived from data_path in SetupSharedState
	// when not explicitly set (avoids eagerly reading data_path before config is loaded).
	viper.SetDefault("extra_debugging", false)
	viper.SetDefault("status_timer", DefaultStatusTimer)
	viper.SetDefault("heartbeat_interval", DefaultHeartbeatInterval)
	viper.SetDefault("write_zaps_to_file", false)
	viper.SetDefault("retain_zaps_on_completion", false)
	viper.SetDefault("enable_additional_hash_types", true)
	viper.SetDefault("use_legacy_device_technique", false)
	viper.SetDefault("task_timeout", DefaultTaskTimeout)
	viper.SetDefault("download_max_retries", DefaultDownloadMaxRetries)
	viper.SetDefault("download_retry_delay", DefaultDownloadRetryDelay)
	viper.SetDefault("insecure_downloads", DefaultInsecureDownloads)
	viper.SetDefault("max_heartbeat_backoff", DefaultMaxHeartbeatBackoff)
	viper.SetDefault("force_benchmark_run", false)
}
