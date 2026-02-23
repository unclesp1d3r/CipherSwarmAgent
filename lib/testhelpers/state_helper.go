// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"os"
	"path/filepath"

	"github.com/jarcoal/httpmock"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

const dirPerm os.FileMode = 0o755

func mustMkdirAll(path string) {
	if err := os.MkdirAll(path, dirPerm); err != nil {
		panic(err)
	}
}

// SetupTestState initializes agentstate.State with test values.
// It creates temporary directories for all path fields, sets up the API client,
// and returns a cleanup function that removes temporary directories and resets state.
func SetupTestState(agentID int64, apiURL, apiToken string) func() {
	// Create temporary directories for all path fields
	tempDir := os.TempDir()
	testDataDir, err := os.MkdirTemp(tempDir, "cipherswarm-test-*")
	if err != nil {
		panic(err)
	}

	agentstate.State.AgentID = agentID
	agentstate.State.URL = apiURL
	agentstate.State.APIToken = apiToken
	agentstate.State.DataPath = filepath.Join(testDataDir, "data")
	agentstate.State.CrackersPath = filepath.Join(testDataDir, "crackers")
	agentstate.State.HashlistPath = filepath.Join(testDataDir, "hashlists")
	agentstate.State.ZapsPath = filepath.Join(testDataDir, "zaps")
	agentstate.State.PreprocessorsPath = filepath.Join(testDataDir, "preprocessors")
	agentstate.State.ToolsPath = filepath.Join(testDataDir, "tools")
	agentstate.State.OutPath = filepath.Join(testDataDir, "out")
	agentstate.State.FilePath = filepath.Join(testDataDir, "files")
	agentstate.State.RestoreFilePath = filepath.Join(testDataDir, "restore")
	agentstate.State.BenchmarkCachePath = filepath.Join(testDataDir, "benchmark_cache.json")
	agentstate.State.Debug = false
	agentstate.State.ExtraDebugging = false
	// Initialize API client using generated client wrapper
	apiClient, err := api.NewAgentClient(apiURL, apiToken)
	if err != nil {
		panic(err)
	}
	agentstate.State.APIClient = apiClient

	// Create directories
	mustMkdirAll(agentstate.State.DataPath)
	mustMkdirAll(agentstate.State.CrackersPath)
	mustMkdirAll(agentstate.State.HashlistPath)
	mustMkdirAll(agentstate.State.ZapsPath)
	mustMkdirAll(agentstate.State.PreprocessorsPath)
	mustMkdirAll(agentstate.State.ToolsPath)
	mustMkdirAll(agentstate.State.OutPath)
	mustMkdirAll(agentstate.State.FilePath)
	mustMkdirAll(agentstate.State.RestoreFilePath)

	return func() {
		// Cleanup: remove temporary directories
		_ = os.RemoveAll(testDataDir)
		// Reset agentstate.State to zero values
		agentstate.State.PidFile = ""
		agentstate.State.HashcatPidFile = ""
		agentstate.State.DataPath = ""
		agentstate.State.CrackersPath = ""
		agentstate.State.HashlistPath = ""
		agentstate.State.ZapsPath = ""
		agentstate.State.PreprocessorsPath = ""
		agentstate.State.ToolsPath = ""
		agentstate.State.OutPath = ""
		agentstate.State.FilePath = ""
		agentstate.State.RestoreFilePath = ""
		agentstate.State.BenchmarkCachePath = ""
		agentstate.State.Debug = false
		agentstate.State.AgentID = 0
		agentstate.State.URL = ""
		agentstate.State.APIToken = ""
		agentstate.State.AlwaysTrustFiles = false
		agentstate.State.ExtraDebugging = false
		agentstate.State.StatusTimer = 0
		agentstate.State.WriteZapsToFile = false
		agentstate.State.RetainZapsOnCompletion = false
		agentstate.State.EnableAdditionalHashTypes = false
		agentstate.State.UseLegacyDeviceIdentificationMethod = false
		agentstate.State.APIClient = nil
		agentstate.State.ForceBenchmarkRun = false
		agentstate.State.InsecureDownloads = false
		agentstate.State.DownloadMaxRetries = 0
		agentstate.State.DownloadRetryDelay = 0
		agentstate.State.TaskTimeout = 0
		agentstate.State.MaxHeartbeatBackoff = 0
		agentstate.State.SleepOnFailure = 0
		agentstate.State.AlwaysUseNativeHashcat = false
		agentstate.State.Platform = ""
		agentstate.State.AgentVersion = ""
		// Reset synchronized fields via setters
		agentstate.State.SetReload(false)
		agentstate.State.SetCurrentActivity("")
		agentstate.State.SetJobCheckingStopped(false)
		agentstate.State.SetBenchmarksSubmitted(false)
		// Deactivate httpmock
		httpmock.DeactivateAndReset()
	}
}

// ResetTestState resets agentstate.State to zero values without cleanup.
// Useful for tests that need to reset state between subtests.
func ResetTestState() {
	agentstate.State.PidFile = ""
	agentstate.State.HashcatPidFile = ""
	agentstate.State.DataPath = ""
	agentstate.State.CrackersPath = ""
	agentstate.State.HashlistPath = ""
	agentstate.State.ZapsPath = ""
	agentstate.State.PreprocessorsPath = ""
	agentstate.State.ToolsPath = ""
	agentstate.State.OutPath = ""
	agentstate.State.FilePath = ""
	agentstate.State.RestoreFilePath = ""
	agentstate.State.BenchmarkCachePath = ""
	agentstate.State.Debug = false
	agentstate.State.AgentID = 0
	agentstate.State.URL = ""
	agentstate.State.APIToken = ""
	agentstate.State.AlwaysTrustFiles = false
	agentstate.State.ExtraDebugging = false
	agentstate.State.StatusTimer = 0
	agentstate.State.WriteZapsToFile = false
	agentstate.State.RetainZapsOnCompletion = false
	agentstate.State.EnableAdditionalHashTypes = false
	agentstate.State.UseLegacyDeviceIdentificationMethod = false
	agentstate.State.APIClient = nil
	agentstate.State.ForceBenchmarkRun = false
	agentstate.State.InsecureDownloads = false
	agentstate.State.DownloadMaxRetries = 0
	agentstate.State.DownloadRetryDelay = 0
	agentstate.State.TaskTimeout = 0
	agentstate.State.MaxHeartbeatBackoff = 0
	agentstate.State.SleepOnFailure = 0
	agentstate.State.AlwaysUseNativeHashcat = false
	agentstate.State.Platform = ""
	agentstate.State.AgentVersion = ""
	// Reset synchronized fields via setters
	agentstate.State.SetReload(false)
	agentstate.State.SetCurrentActivity("")
	agentstate.State.SetJobCheckingStopped(false)
	agentstate.State.SetBenchmarksSubmitted(false)
}

// SetupMinimalTestState sets up minimal state (just AgentID and basic paths)
// for tests that don't need full initialization. It returns a cleanup function
// to remove the temporary directory and reset the updated state fields.
func SetupMinimalTestState(agentID int64) func() {
	tempDir := os.TempDir()
	testDataDir, err := os.MkdirTemp(tempDir, "cipherswarm-test-*")
	if err != nil {
		panic(err)
	}

	agentstate.State.AgentID = agentID
	agentstate.State.DataPath = filepath.Join(testDataDir, "data")
	agentstate.State.CrackersPath = filepath.Join(testDataDir, "crackers")
	agentstate.State.HashlistPath = filepath.Join(testDataDir, "hashlists")
	agentstate.State.ZapsPath = filepath.Join(testDataDir, "zaps")
	agentstate.State.PreprocessorsPath = filepath.Join(testDataDir, "preprocessors")
	agentstate.State.ToolsPath = filepath.Join(testDataDir, "tools")
	agentstate.State.OutPath = filepath.Join(testDataDir, "out")
	agentstate.State.FilePath = filepath.Join(testDataDir, "files")
	agentstate.State.RestoreFilePath = filepath.Join(testDataDir, "restore")
	agentstate.State.BenchmarkCachePath = filepath.Join(testDataDir, "benchmark_cache.json")

	return func() {
		_ = os.RemoveAll(testDataDir)
		agentstate.State.AgentID = 0
		agentstate.State.DataPath = ""
		agentstate.State.CrackersPath = ""
		agentstate.State.HashlistPath = ""
		agentstate.State.ZapsPath = ""
		agentstate.State.PreprocessorsPath = ""
		agentstate.State.ToolsPath = ""
		agentstate.State.OutPath = ""
		agentstate.State.FilePath = ""
		agentstate.State.RestoreFilePath = ""
		agentstate.State.BenchmarkCachePath = ""
	}
}

// WithTestState is a convenience wrapper that sets up state, runs the test function,
// and cleans up automatically.
func WithTestState(agentID int64, apiURL, apiToken string, testFunc func()) {
	cleanup := SetupTestState(agentID, apiURL, apiToken)
	defer cleanup()
	testFunc()
}
