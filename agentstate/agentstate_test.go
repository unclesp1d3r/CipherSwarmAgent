package agentstate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestState_DefaultValues(t *testing.T) {
	// Verify State is initialized as empty struct
	// Most fields should have zero values
	assert.Empty(t, State.PidFile)
	assert.Empty(t, State.HashcatPidFile)
	assert.Empty(t, State.DataPath)
	assert.Empty(t, State.CrackersPath)
	assert.Empty(t, State.HashlistPath)
	assert.Empty(t, State.ZapsPath)
	assert.Empty(t, State.PreprocessorsPath)
	assert.Empty(t, State.ToolsPath)
	assert.Empty(t, State.OutPath)
	assert.Empty(t, State.FilePath)
	assert.Empty(t, State.RestoreFilePath)
	assert.False(t, State.Debug)
	assert.Equal(t, int64(0), State.AgentID)
	assert.Empty(t, State.URL)
	assert.Empty(t, State.APIToken)
	assert.False(t, State.Reload)
	assert.False(t, State.AlwaysTrustFiles)
	assert.False(t, State.ExtraDebugging)
	assert.Equal(t, 0, State.StatusTimer)
	assert.False(t, State.WriteZapsToFile)
	assert.False(t, State.RetainZapsOnCompletion)
	assert.False(t, State.EnableAdditionalHashTypes)
	assert.False(t, State.JobCheckingStopped)
	assert.False(t, State.UseLegacyDeviceIdentificationMethod)
	assert.False(t, State.BenchmarksSubmitted)
}

func TestState_Modification(t *testing.T) {
	// Save original values
	original := State

	// Modify state
	State.AgentID = 12345
	State.URL = "https://api.example.com"
	State.APIToken = "test-token-123"
	State.Debug = true
	State.StatusTimer = 10
	State.WriteZapsToFile = true

	// Verify modifications
	assert.Equal(t, int64(12345), State.AgentID)
	assert.Equal(t, "https://api.example.com", State.URL)
	assert.Equal(t, "test-token-123", State.APIToken)
	assert.True(t, State.Debug)
	assert.Equal(t, 10, State.StatusTimer)
	assert.True(t, State.WriteZapsToFile)

	// Restore original
	State = original
}

func TestActivityConstants(t *testing.T) {
	assert.Equal(t, CurrentActivityStarting, activity("starting"))
	assert.Equal(t, CurrentActivityBenchmarking, activity("benchmarking"))
	assert.Equal(t, CurrentActivityUpdating, activity("updating"))
	assert.Equal(t, CurrentActivityWaiting, activity("waiting"))
	assert.Equal(t, CurrentActivityCracking, activity("cracking"))
	assert.Equal(t, CurrentActivityStopping, activity("stopping"))
}

func TestState_ActivityTracking(t *testing.T) {
	// Save original
	original := State.CurrentActivity

	// Test activity transitions
	State.CurrentActivity = CurrentActivityStarting
	assert.Equal(t, CurrentActivityStarting, State.CurrentActivity)

	State.CurrentActivity = CurrentActivityBenchmarking
	assert.Equal(t, CurrentActivityBenchmarking, State.CurrentActivity)

	State.CurrentActivity = CurrentActivityWaiting
	assert.Equal(t, CurrentActivityWaiting, State.CurrentActivity)

	State.CurrentActivity = CurrentActivityCracking
	assert.Equal(t, CurrentActivityCracking, State.CurrentActivity)

	State.CurrentActivity = CurrentActivityStopping
	assert.Equal(t, CurrentActivityStopping, State.CurrentActivity)

	// Restore
	State.CurrentActivity = original
}

func TestState_PathConfiguration(t *testing.T) {
	// Save original values
	originalDataPath := State.DataPath
	originalCrackersPath := State.CrackersPath
	originalFilePath := State.FilePath

	// Configure paths
	State.DataPath = "/var/lib/cipherswarm"
	State.CrackersPath = "/var/lib/cipherswarm/crackers"
	State.FilePath = "/var/lib/cipherswarm/files"

	// Verify
	assert.Equal(t, "/var/lib/cipherswarm", State.DataPath)
	assert.Equal(t, "/var/lib/cipherswarm/crackers", State.CrackersPath)
	assert.Equal(t, "/var/lib/cipherswarm/files", State.FilePath)

	// Restore
	State.DataPath = originalDataPath
	State.CrackersPath = originalCrackersPath
	State.FilePath = originalFilePath
}

func TestLogger_NotNil(t *testing.T) {
	assert.NotNil(t, Logger)
}

func TestErrorLogger_NotNil(t *testing.T) {
	assert.NotNil(t, ErrorLogger)
}

func TestState_BooleanFlags(t *testing.T) {
	// Save originals
	origDebug := State.Debug
	origAlwaysTrust := State.AlwaysTrustFiles
	origExtraDebug := State.ExtraDebugging
	origWriteZaps := State.WriteZapsToFile
	origRetainZaps := State.RetainZapsOnCompletion
	origEnableHash := State.EnableAdditionalHashTypes
	origJobStopped := State.JobCheckingStopped
	origLegacy := State.UseLegacyDeviceIdentificationMethod
	origBenchmarks := State.BenchmarksSubmitted

	// Test toggling all boolean flags
	State.Debug = true
	State.AlwaysTrustFiles = true
	State.ExtraDebugging = true
	State.WriteZapsToFile = true
	State.RetainZapsOnCompletion = true
	State.EnableAdditionalHashTypes = true
	State.JobCheckingStopped = true
	State.UseLegacyDeviceIdentificationMethod = true
	State.BenchmarksSubmitted = true

	assert.True(t, State.Debug)
	assert.True(t, State.AlwaysTrustFiles)
	assert.True(t, State.ExtraDebugging)
	assert.True(t, State.WriteZapsToFile)
	assert.True(t, State.RetainZapsOnCompletion)
	assert.True(t, State.EnableAdditionalHashTypes)
	assert.True(t, State.JobCheckingStopped)
	assert.True(t, State.UseLegacyDeviceIdentificationMethod)
	assert.True(t, State.BenchmarksSubmitted)

	// Restore
	State.Debug = origDebug
	State.AlwaysTrustFiles = origAlwaysTrust
	State.ExtraDebugging = origExtraDebug
	State.WriteZapsToFile = origWriteZaps
	State.RetainZapsOnCompletion = origRetainZaps
	State.EnableAdditionalHashTypes = origEnableHash
	State.JobCheckingStopped = origJobStopped
	State.UseLegacyDeviceIdentificationMethod = origLegacy
	State.BenchmarksSubmitted = origBenchmarks
}
