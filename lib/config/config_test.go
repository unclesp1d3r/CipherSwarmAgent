package config

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			expected interface{}
			getter   func(string) interface{}
		}{
			{
				name:     "task_timeout defaults to 24 hours",
				key:      "task_timeout",
				expected: 24 * time.Hour,
				getter:   func(k string) interface{} { return viper.GetDuration(k) },
			},
			{
				name:     "download_max_retries defaults to 3",
				key:      "download_max_retries",
				expected: 3,
				getter:   func(k string) interface{} { return viper.GetInt(k) },
			},
			{
				name:     "download_retry_delay defaults to 2 seconds",
				key:      "download_retry_delay",
				expected: 2 * time.Second,
				getter:   func(k string) interface{} { return viper.GetDuration(k) },
			},
			{
				name:     "insecure_downloads defaults to false",
				key:      "insecure_downloads",
				expected: false,
				getter:   func(k string) interface{} { return viper.GetBool(k) },
			},
			{
				name:     "max_heartbeat_backoff defaults to 6",
				key:      "max_heartbeat_backoff",
				expected: 6,
				getter:   func(k string) interface{} { return viper.GetInt(k) },
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
			expected interface{}
			getter   func(string) interface{}
		}{
			{
				name:     "gpu_temp_threshold defaults to 80",
				key:      "gpu_temp_threshold",
				expected: 80,
				getter:   func(k string) interface{} { return viper.GetInt(k) },
			},
			{
				name:     "always_use_native_hashcat defaults to false",
				key:      "always_use_native_hashcat",
				expected: false,
				getter:   func(k string) interface{} { return viper.GetBool(k) },
			},
			{
				name:     "sleep_on_failure defaults to 60 seconds",
				key:      "sleep_on_failure",
				expected: 60 * time.Second,
				getter:   func(k string) interface{} { return viper.GetDuration(k) },
			},
			{
				name:     "always_trust_files defaults to false",
				key:      "always_trust_files",
				expected: false,
				getter:   func(k string) interface{} { return viper.GetBool(k) },
			},
			{
				name:     "extra_debugging defaults to false",
				key:      "extra_debugging",
				expected: false,
				getter:   func(k string) interface{} { return viper.GetBool(k) },
			},
			{
				name:     "status_timer defaults to 10",
				key:      "status_timer",
				expected: 10,
				getter:   func(k string) interface{} { return viper.GetInt(k) },
			},
			{
				name:     "heartbeat_interval defaults to 10 seconds",
				key:      "heartbeat_interval",
				expected: 10 * time.Second,
				getter:   func(k string) interface{} { return viper.GetDuration(k) },
			},
			{
				name:     "write_zaps_to_file defaults to false",
				key:      "write_zaps_to_file",
				expected: false,
				getter:   func(k string) interface{} { return viper.GetBool(k) },
			},
			{
				name:     "retain_zaps_on_completion defaults to false",
				key:      "retain_zaps_on_completion",
				expected: false,
				getter:   func(k string) interface{} { return viper.GetBool(k) },
			},
			{
				name:     "enable_additional_hash_types defaults to true",
				key:      "enable_additional_hash_types",
				expected: true,
				getter:   func(k string) interface{} { return viper.GetBool(k) },
			},
			{
				name:     "use_legacy_device_technique defaults to false",
				key:      "use_legacy_device_technique",
				expected: false,
				getter:   func(k string) interface{} { return viper.GetBool(k) },
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
		expectedDataPath := path.Join(cwd, "data")

		t.Run("data_path defaults to cwd/data", func(t *testing.T) {
			actual := viper.GetString("data_path")
			assert.Equal(t, expectedDataPath, actual)
		})

		t.Run("files_path defaults to data_path/files", func(t *testing.T) {
			expected := path.Join(expectedDataPath, "files")
			actual := viper.GetString("files_path")
			assert.Equal(t, expected, actual)
		})

		t.Run("zap_path defaults to data_path/zaps", func(t *testing.T) {
			expected := path.Join(expectedDataPath, "zaps")
			actual := viper.GetString("zap_path")
			assert.Equal(t, expected, actual)
		})
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
