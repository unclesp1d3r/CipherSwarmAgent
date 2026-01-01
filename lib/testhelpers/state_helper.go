// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

const dirPerm os.FileMode = 0o755

// setupTestStateMutex serializes SetupTestState to prevent data races when tests run in parallel.
// TODO: Remove this mutex when agentstate.State is refactored to use instances instead of global state.
var setupTestStateMutex sync.Mutex

func mkdirAll(path string) error {
	if err := os.MkdirAll(path, dirPerm); err != nil {
		return err
	}
	return nil
}

// SetupTestState initializes agentstate.State with test values.
// It creates temporary directories for all path fields, sets up the SDK client,
// stubs device discovery to avoid requiring hashcat binary,
// and returns a cleanup function that removes temporary directories and resets state.
// Tests must not run in parallel until the global state is refactored to instances.
func SetupTestState(agentID int64, apiURL, apiToken string) (func(), error) {
	setupTestStateMutex.Lock()
	// Create temporary directories for all path fields
	tempDir := os.TempDir()
	testDataDir, err := os.MkdirTemp(tempDir, "cipherswarm-test-*")
	if err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
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
	agentstate.State.Debug = false
	agentstate.State.ExtraDebugging = false
	agentstate.State.SdkClient = NewTestSDKClient(apiURL)

	// Create directories
	if err := mustMkdirAll(agentstate.State.DataPath); err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.CrackersPath); err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.HashlistPath); err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.ZapsPath); err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.PreprocessorsPath); err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.ToolsPath); err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.OutPath); err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.FilePath); err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.RestoreFilePath); err != nil {
		setupTestStateMutex.Unlock()
		return nil, err
	}

	return func() {
		// Cleanup: remove temporary directories
		_ = os.RemoveAll(testDataDir)
		// Reset agentstate.State to zero values by setting each field individually
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
		agentstate.State.Debug = false
		agentstate.State.AgentID = 0
		agentstate.State.URL = ""
		agentstate.State.APIToken = ""
		agentstate.State.Reload = false
		agentstate.State.CurrentActivity = ""
		agentstate.State.AlwaysTrustFiles = false
		agentstate.State.ExtraDebugging = false
		agentstate.State.StatusTimer = 0
		agentstate.State.WriteZapsToFile = false
		agentstate.State.RetainZapsOnCompletion = false
		agentstate.State.EnableAdditionalHashTypes = false
		agentstate.State.JobCheckingStopped = false
		agentstate.State.UseLegacyDeviceIdentificationMethod = false
		agentstate.State.BenchmarksSubmitted = false
		agentstate.State.SdkClient = nil
		// Deactivate httpmock
		httpmock.DeactivateAndReset()
		setupTestStateMutex.Unlock()
	}, nil
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
	agentstate.State.Debug = false
	agentstate.State.AgentID = 0
	agentstate.State.URL = ""
	agentstate.State.APIToken = ""
	agentstate.State.Reload = false
	agentstate.State.CurrentActivity = ""
	agentstate.State.AlwaysTrustFiles = false
	agentstate.State.ExtraDebugging = false
	agentstate.State.StatusTimer = 0
	agentstate.State.WriteZapsToFile = false
	agentstate.State.RetainZapsOnCompletion = false
	agentstate.State.EnableAdditionalHashTypes = false
	agentstate.State.JobCheckingStopped = false
	agentstate.State.UseLegacyDeviceIdentificationMethod = false
	agentstate.State.BenchmarksSubmitted = false
	agentstate.State.SdkClient = nil
}

// SetupMinimalTestState sets up minimal state (just AgentID and basic paths)
// for tests that don't need full initialization.
func SetupMinimalTestState(agentID int64) (func(), error) {
	tempDir := os.TempDir()
	testDataDir, err := os.MkdirTemp(tempDir, "cipherswarm-test-*")
	if err != nil {
		return nil, err
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

	// Create directories
	if err := mustMkdirAll(agentstate.State.DataPath); err != nil {
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.CrackersPath); err != nil {
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.HashlistPath); err != nil {
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.ZapsPath); err != nil {
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.PreprocessorsPath); err != nil {
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.ToolsPath); err != nil {
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.OutPath); err != nil {
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.FilePath); err != nil {
		return nil, err
	}
	if err := mustMkdirAll(agentstate.State.RestoreFilePath); err != nil {
		return nil, err
	}

	return func() {
		// Cleanup: remove temporary directories
		_ = os.RemoveAll(testDataDir)
		// Reset agentstate.State to zero values by setting each field individually
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
	}, nil
}

// WithTestState is a convenience wrapper that sets up state, runs the test function,
// and cleans up automatically.
func WithTestState(tb testing.TB, agentID int64, apiURL, apiToken string, testFunc func()) {
	tb.Helper()
	cleanup, err := SetupTestState(agentID, apiURL, apiToken)
	if err != nil {
		tb.Fatalf("failed to setup test state: %v", err)
	}
	defer cleanup()
	testFunc()
}
