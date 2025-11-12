// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"os"
	"path/filepath"

	"github.com/jarcoal/httpmock"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

const dirPerm os.FileMode = 0o755

func mustMkdirAll(path string) {
	if err := os.MkdirAll(path, dirPerm); err != nil {
		panic(err)
	}
}

// SetupTestState initializes shared.State with test values.
// It creates temporary directories for all path fields, sets up the SDK client,
// stubs device discovery to avoid requiring hashcat binary,
// and returns a cleanup function that removes temporary directories and resets state.
func SetupTestState(agentID int64, apiURL, apiToken string) func() {
	// Create temporary directories for all path fields
	tempDir := os.TempDir()
	testDataDir, err := os.MkdirTemp(tempDir, "cipherswarm-test-*")
	if err != nil {
		panic(err)
	}

	shared.State.AgentID = agentID
	shared.State.URL = apiURL
	shared.State.APIToken = apiToken
	shared.State.DataPath = filepath.Join(testDataDir, "data")
	shared.State.CrackersPath = filepath.Join(testDataDir, "crackers")
	shared.State.HashlistPath = filepath.Join(testDataDir, "hashlists")
	shared.State.ZapsPath = filepath.Join(testDataDir, "zaps")
	shared.State.PreprocessorsPath = filepath.Join(testDataDir, "preprocessors")
	shared.State.ToolsPath = filepath.Join(testDataDir, "tools")
	shared.State.OutPath = filepath.Join(testDataDir, "out")
	shared.State.FilePath = filepath.Join(testDataDir, "files")
	shared.State.RestoreFilePath = filepath.Join(testDataDir, "restore")
	shared.State.Debug = false
	shared.State.ExtraDebugging = false
	shared.State.SdkClient = NewTestSDKClient(apiURL)

	// Create directories
	mustMkdirAll(shared.State.DataPath)
	mustMkdirAll(shared.State.CrackersPath)
	mustMkdirAll(shared.State.HashlistPath)
	mustMkdirAll(shared.State.ZapsPath)
	mustMkdirAll(shared.State.PreprocessorsPath)
	mustMkdirAll(shared.State.ToolsPath)
	mustMkdirAll(shared.State.OutPath)
	mustMkdirAll(shared.State.FilePath)
	mustMkdirAll(shared.State.RestoreFilePath)

	return func() {
		// Cleanup: remove temporary directories
		_ = os.RemoveAll(testDataDir)
		// Reset shared.State to zero values by setting each field individually
		shared.State.PidFile = ""
		shared.State.HashcatPidFile = ""
		shared.State.DataPath = ""
		shared.State.CrackersPath = ""
		shared.State.HashlistPath = ""
		shared.State.ZapsPath = ""
		shared.State.PreprocessorsPath = ""
		shared.State.ToolsPath = ""
		shared.State.OutPath = ""
		shared.State.FilePath = ""
		shared.State.RestoreFilePath = ""
		shared.State.Debug = false
		shared.State.AgentID = 0
		shared.State.URL = ""
		shared.State.APIToken = ""
		shared.State.Reload = false
		shared.State.CurrentActivity = ""
		shared.State.AlwaysTrustFiles = false
		shared.State.ExtraDebugging = false
		shared.State.StatusTimer = 0
		shared.State.WriteZapsToFile = false
		shared.State.RetainZapsOnCompletion = false
		shared.State.EnableAdditionalHashTypes = false
		shared.State.JobCheckingStopped = false
		shared.State.UseLegacyDeviceIdentificationMethod = false
		shared.State.BenchmarksSubmitted = false
		shared.State.SdkClient = nil
		// Deactivate httpmock
		httpmock.DeactivateAndReset()
	}
}

// ResetTestState resets shared.State to zero values without cleanup.
// Useful for tests that need to reset state between subtests.
func ResetTestState() {
	shared.State.PidFile = ""
	shared.State.HashcatPidFile = ""
	shared.State.DataPath = ""
	shared.State.CrackersPath = ""
	shared.State.HashlistPath = ""
	shared.State.ZapsPath = ""
	shared.State.PreprocessorsPath = ""
	shared.State.ToolsPath = ""
	shared.State.OutPath = ""
	shared.State.FilePath = ""
	shared.State.RestoreFilePath = ""
	shared.State.Debug = false
	shared.State.AgentID = 0
	shared.State.URL = ""
	shared.State.APIToken = ""
	shared.State.Reload = false
	shared.State.CurrentActivity = ""
	shared.State.AlwaysTrustFiles = false
	shared.State.ExtraDebugging = false
	shared.State.StatusTimer = 0
	shared.State.WriteZapsToFile = false
	shared.State.RetainZapsOnCompletion = false
	shared.State.EnableAdditionalHashTypes = false
	shared.State.JobCheckingStopped = false
	shared.State.UseLegacyDeviceIdentificationMethod = false
	shared.State.BenchmarksSubmitted = false
	shared.State.SdkClient = nil
}

// SetupMinimalTestState sets up minimal state (just AgentID and basic paths)
// for tests that don't need full initialization.
func SetupMinimalTestState(agentID int64) {
	tempDir := os.TempDir()
	testDataDir, err := os.MkdirTemp(tempDir, "cipherswarm-test-*")
	if err != nil {
		panic(err)
	}

	shared.State.AgentID = agentID
	shared.State.DataPath = filepath.Join(testDataDir, "data")
	shared.State.CrackersPath = filepath.Join(testDataDir, "crackers")
	shared.State.HashlistPath = filepath.Join(testDataDir, "hashlists")
	shared.State.ZapsPath = filepath.Join(testDataDir, "zaps")
	shared.State.PreprocessorsPath = filepath.Join(testDataDir, "preprocessors")
	shared.State.ToolsPath = filepath.Join(testDataDir, "tools")
	shared.State.OutPath = filepath.Join(testDataDir, "out")
	shared.State.FilePath = filepath.Join(testDataDir, "files")
	shared.State.RestoreFilePath = filepath.Join(testDataDir, "restore")
}

// WithTestState is a convenience wrapper that sets up state, runs the test function,
// and cleans up automatically.
func WithTestState(agentID int64, apiURL, apiToken string, testFunc func()) {
	cleanup := SetupTestState(agentID, apiURL, apiToken)
	defer cleanup()
	testFunc()
}
