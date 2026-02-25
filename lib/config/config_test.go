package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

func TestSetDefaultConfigValues(t *testing.T) {
	// Reset viper before setting defaults to ensure clean state
	viper.Reset()

	// Call the function under test
	SetDefaultConfigValues()

	// Get the current working directory for path-based assertions
	cwd, err := os.Getwd()
	require.NoError(t, err, "failed to get current working directory")

	t.Run("fault tolerance defaults", func(t *testing.T) {
		tests := []struct {
			name     string
			key      string
			expected any
			getter   func(string) any
		}{
			{
				name:     "task_timeout defaults to 24 hours",
				key:      "task_timeout",
				expected: 24 * time.Hour,
				getter:   func(k string) any { return viper.GetDuration(k) },
			},
			{
				name:     "download_max_retries defaults to 3",
				key:      "download_max_retries",
				expected: 3,
				getter:   func(k string) any { return viper.GetInt(k) },
			},
			{
				name:     "download_retry_delay defaults to 2 seconds",
				key:      "download_retry_delay",
				expected: 2 * time.Second,
				getter:   func(k string) any { return viper.GetDuration(k) },
			},
			{
				name:     "insecure_downloads defaults to false",
				key:      "insecure_downloads",
				expected: false,
				getter:   func(k string) any { return viper.GetBool(k) },
			},
			{
				name:     "max_heartbeat_backoff defaults to 6",
				key:      "max_heartbeat_backoff",
				expected: 6,
				getter:   func(k string) any { return viper.GetInt(k) },
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				actual := tt.getter(tt.key)
				assert.Equal(t, tt.expected, actual, "config key %q mismatch", tt.key)
			})
		}
	})

	t.Run("general defaults", func(t *testing.T) {
		tests := []struct {
			name     string
			key      string
			expected any
			getter   func(string) any
		}{
			{
				name:     "gpu_temp_threshold defaults to 80",
				key:      "gpu_temp_threshold",
				expected: 80,
				getter:   func(k string) any { return viper.GetInt(k) },
			},
			{
				name:     "always_use_native_hashcat defaults to false",
				key:      "always_use_native_hashcat",
				expected: false,
				getter:   func(k string) any { return viper.GetBool(k) },
			},
			{
				name:     "sleep_on_failure defaults to 60 seconds",
				key:      "sleep_on_failure",
				expected: 60 * time.Second,
				getter:   func(k string) any { return viper.GetDuration(k) },
			},
			{
				name:     "always_trust_files defaults to false",
				key:      "always_trust_files",
				expected: false,
				getter:   func(k string) any { return viper.GetBool(k) },
			},
			{
				name:     "extra_debugging defaults to false",
				key:      "extra_debugging",
				expected: false,
				getter:   func(k string) any { return viper.GetBool(k) },
			},
			{
				name:     "status_timer defaults to 10",
				key:      "status_timer",
				expected: 10,
				getter:   func(k string) any { return viper.GetInt(k) },
			},
			{
				name:     "heartbeat_interval defaults to 10 seconds",
				key:      "heartbeat_interval",
				expected: 10 * time.Second,
				getter:   func(k string) any { return viper.GetDuration(k) },
			},
			{
				name:     "write_zaps_to_file defaults to false",
				key:      "write_zaps_to_file",
				expected: false,
				getter:   func(k string) any { return viper.GetBool(k) },
			},
			{
				name:     "retain_zaps_on_completion defaults to false",
				key:      "retain_zaps_on_completion",
				expected: false,
				getter:   func(k string) any { return viper.GetBool(k) },
			},
			{
				name:     "enable_additional_hash_types defaults to true",
				key:      "enable_additional_hash_types",
				expected: true,
				getter:   func(k string) any { return viper.GetBool(k) },
			},
			{
				name:     "use_legacy_device_technique defaults to false",
				key:      "use_legacy_device_technique",
				expected: false,
				getter:   func(k string) any { return viper.GetBool(k) },
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				actual := tt.getter(tt.key)
				assert.Equal(t, tt.expected, actual, "config key %q mismatch", tt.key)
			})
		}
	})

	t.Run("path defaults", func(t *testing.T) {
		expectedDataPath := filepath.Join(cwd, "data")

		t.Run("data_path defaults to cwd/data", func(t *testing.T) {
			actual := viper.GetString("data_path")
			assert.Equal(t, expectedDataPath, actual)
		})

		// files_path and zap_path are derived in SetupSharedState, not in SetDefaultConfigValues.
		// See TestSetupSharedState_DerivedPathsFromDataRoot for coverage.
	})
}

func TestSetDefaultConfigValues_ResetBetweenCalls(t *testing.T) {
	// This test verifies that calling SetDefaultConfigValues after viper.Reset
	// correctly resets all values to defaults

	// First, set defaults
	viper.Reset()
	SetDefaultConfigValues()

	// Override some values
	viper.Set("download_max_retries", 10)
	viper.Set("task_timeout", 1*time.Hour)
	viper.Set("insecure_downloads", true)

	// Verify overrides took effect
	assert.Equal(t, 10, viper.GetInt("download_max_retries"))
	assert.Equal(t, 1*time.Hour, viper.GetDuration("task_timeout"))
	assert.True(t, viper.GetBool("insecure_downloads"))

	// Reset and set defaults again
	viper.Reset()
	SetDefaultConfigValues()

	// Verify defaults are restored
	assert.Equal(t, 3, viper.GetInt("download_max_retries"), "download_max_retries should be reset to default")
	assert.Equal(t, 24*time.Hour, viper.GetDuration("task_timeout"), "task_timeout should be reset to default")
	assert.False(t, viper.GetBool("insecure_downloads"), "insecure_downloads should be reset to default")
}

func TestSetupSharedState_ValidationClampsInvalidValues(t *testing.T) {
	viper.Reset()
	SetDefaultConfigValues()

	// Set invalid values
	viper.Set("download_max_retries", 0)
	viper.Set("task_timeout", 0)
	viper.Set("max_heartbeat_backoff", -1)

	SetupSharedState()

	// Should be clamped to defaults
	assert.Equal(t, DefaultDownloadMaxRetries, agentstate.State.DownloadMaxRetries,
		"download_max_retries should be clamped to default when < 1")
	assert.Equal(t, DefaultTaskTimeout, agentstate.State.TaskTimeout,
		"task_timeout should be clamped to default when <= 0")
	assert.Equal(t, DefaultMaxHeartbeatBackoff, agentstate.State.MaxHeartbeatBackoff,
		"max_heartbeat_backoff should be clamped to default when < 0")
}

func TestSetupSharedState_ValidationAcceptsValidValues(t *testing.T) {
	viper.Reset()
	SetDefaultConfigValues()

	// Set valid non-default values
	viper.Set("download_max_retries", 10)
	viper.Set("task_timeout", 1*time.Hour)
	viper.Set("max_heartbeat_backoff", 10)

	SetupSharedState()

	assert.Equal(t, 10, agentstate.State.DownloadMaxRetries)
	assert.Equal(t, 1*time.Hour, agentstate.State.TaskTimeout)
	assert.Equal(t, 10, agentstate.State.MaxHeartbeatBackoff)
}

func TestSetupSharedState_DerivedPathsFromDataRoot(t *testing.T) {
	t.Run("default data_path derives files_path and zap_path", func(t *testing.T) {
		viper.Reset()
		SetDefaultConfigValues()
		SetupSharedState()

		cwd, err := os.Getwd()
		require.NoError(t, err)

		expectedDataPath := filepath.Join(cwd, "data")
		assert.Equal(t, filepath.Join(expectedDataPath, "files"), agentstate.State.FilePath)
		assert.Equal(t, filepath.Join(expectedDataPath, "zaps"), agentstate.State.ZapsPath)
	})

	t.Run("custom data_path is honoured for derived paths", func(t *testing.T) {
		viper.Reset()
		SetDefaultConfigValues()
		customDataPath := filepath.Join("custom", "data")
		viper.Set("data_path", customDataPath)
		SetupSharedState()

		assert.Equal(t, filepath.Join(customDataPath, "files"), agentstate.State.FilePath)
		assert.Equal(t, filepath.Join(customDataPath, "zaps"), agentstate.State.ZapsPath)
	})

	t.Run("explicit files_path overrides derivation", func(t *testing.T) {
		viper.Reset()
		SetDefaultConfigValues()
		customDataPath := filepath.Join("custom", "data")
		explicitFilesPath := filepath.Join("explicit", "files")
		viper.Set("data_path", customDataPath)
		viper.Set("files_path", explicitFilesPath)
		SetupSharedState()

		assert.Equal(t, explicitFilesPath, agentstate.State.FilePath)
		assert.Equal(t, filepath.Join(customDataPath, "zaps"), agentstate.State.ZapsPath)
	})

	t.Run("explicit zap_path overrides derivation", func(t *testing.T) {
		viper.Reset()
		SetDefaultConfigValues()
		customDataPath := filepath.Join("custom", "data")
		explicitZapsPath := filepath.Join("explicit", "zaps")
		viper.Set("data_path", customDataPath)
		viper.Set("zap_path", explicitZapsPath)
		SetupSharedState()

		assert.Equal(t, filepath.Join(customDataPath, "files"), agentstate.State.FilePath)
		assert.Equal(t, explicitZapsPath, agentstate.State.ZapsPath)
	})
}
