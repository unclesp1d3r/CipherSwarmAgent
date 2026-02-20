// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

const epsilon = 1e-4

// AssertDeviceStatus compares two DeviceStatus objects field-by-field with clear error messages.
// This is useful when testing the convertDeviceStatuses function in lib/agentClient.go.
func AssertDeviceStatus(t *testing.T, expected, actual api.DeviceStatus) {
	t.Helper()
	assert.Equal(t, expected.DeviceId, actual.DeviceId, "DeviceId mismatch")
	assert.Equal(t, expected.DeviceName, actual.DeviceName, "DeviceName mismatch")
	assert.Equal(t, expected.DeviceType, actual.DeviceType, "DeviceType mismatch")
	assert.Equal(t, expected.Speed, actual.Speed, "Speed mismatch")
	assert.Equal(t, expected.Utilization, actual.Utilization, "Utilization mismatch")
	assert.Equal(t, expected.Temperature, actual.Temperature, "Temperature mismatch")
}

// AssertTaskStatus compares two TaskStatus objects, including nested HashcatGuess fields.
// This is useful when testing the convertToTaskStatus function in lib/agentClient.go.
func AssertTaskStatus(t *testing.T, expected, actual api.TaskStatus) {
	t.Helper()
	assert.Equal(t, expected.OriginalLine, actual.OriginalLine, "OriginalLine mismatch")
	assert.Equal(t, expected.Time, actual.Time, "Time mismatch")
	assert.Equal(t, expected.Session, actual.Session, "Session mismatch")
	assert.Equal(t, expected.Status, actual.Status, "Status mismatch")
	assert.Equal(t, expected.Target, actual.Target, "Target mismatch")
	assert.Equal(t, expected.Progress, actual.Progress, "Progress mismatch")
	assert.Equal(t, expected.RestorePoint, actual.RestorePoint, "RestorePoint mismatch")
	assert.Equal(t, expected.RecoveredHashes, actual.RecoveredHashes, "RecoveredHashes mismatch")
	assert.Equal(t, expected.RecoveredSalts, actual.RecoveredSalts, "RecoveredSalts mismatch")
	assert.Equal(t, expected.Rejected, actual.Rejected, "Rejected mismatch")

	// Compare HashcatGuess fields
	assert.Equal(t, expected.HashcatGuess.GuessBase, actual.HashcatGuess.GuessBase, "HashcatGuess.GuessBase mismatch")
	assert.Equal(
		t,
		expected.HashcatGuess.GuessBaseCount,
		actual.HashcatGuess.GuessBaseCount,
		"HashcatGuess.GuessBaseCount mismatch",
	)
	assert.Equal(
		t,
		expected.HashcatGuess.GuessBaseOffset,
		actual.HashcatGuess.GuessBaseOffset,
		"HashcatGuess.GuessBaseOffset mismatch",
	)
	assert.InEpsilon(
		t,
		expected.HashcatGuess.GuessBasePercentage,
		actual.HashcatGuess.GuessBasePercentage,
		epsilon,
		"HashcatGuess.GuessBasePercentage mismatch",
	)
	assert.Equal(t, expected.HashcatGuess.GuessMod, actual.HashcatGuess.GuessMod, "HashcatGuess.GuessMod mismatch")
	assert.Equal(
		t,
		expected.HashcatGuess.GuessModCount,
		actual.HashcatGuess.GuessModCount,
		"HashcatGuess.GuessModCount mismatch",
	)
	assert.Equal(
		t,
		expected.HashcatGuess.GuessModOffset,
		actual.HashcatGuess.GuessModOffset,
		"HashcatGuess.GuessModOffset mismatch",
	)
	assert.InEpsilon(
		t,
		expected.HashcatGuess.GuessModPercentage,
		actual.HashcatGuess.GuessModPercentage,
		epsilon,
		"HashcatGuess.GuessModPercentage mismatch",
	)
	assert.Equal(t, expected.HashcatGuess.GuessMode, actual.HashcatGuess.GuessMode, "HashcatGuess.GuessMode mismatch")

	// Compare DeviceStatuses
	assert.Len(t, actual.DeviceStatuses, len(expected.DeviceStatuses), "DeviceStatuses length mismatch")
	for i := range expected.DeviceStatuses {
		if i >= len(actual.DeviceStatuses) {
			continue
		}
		AssertDeviceStatus(t, expected.DeviceStatuses[i], actual.DeviceStatuses[i])
	}
}

// AssertErrorType verifies that an error is of a specific API error type
// (e.g., *api.APIError or *api.SetTaskAbandonedError).
// This is critical for testing error handling paths in lib/errorUtils.go.
func AssertErrorType(t *testing.T, err error, expectedType any) {
	t.Helper()
	if expectedType == nil {
		assert.NoError(t, err)
		return
	}

	switch expectedType.(type) {
	case *api.APIError:
		var ae *api.APIError
		require.ErrorAs(t, err, &ae, "Error should be of type *api.APIError")
	case *api.SetTaskAbandonedError:
		var sae *api.SetTaskAbandonedError
		require.ErrorAs(t, err, &sae, "Error should be of type *api.SetTaskAbandonedError")
	default:
		t.Fatalf("Unsupported error type: %T", expectedType)
	}
}

// AssertAgentConfiguration compares TestAgentConfiguration objects with detailed field-by-field comparison.
func AssertAgentConfiguration(t *testing.T, expected, actual TestAgentConfiguration) {
	t.Helper()
	assert.Equal(t, expected.APIVersion, actual.APIVersion, "APIVersion mismatch")

	expectedConfig := expected.Config
	actualConfig := actual.Config

	if expectedConfig.UseNativeHashcat != nil && actualConfig.UseNativeHashcat != nil {
		assert.Equal(t, *expectedConfig.UseNativeHashcat, *actualConfig.UseNativeHashcat, "UseNativeHashcat mismatch")
	} else {
		assert.Equal(t, expectedConfig.UseNativeHashcat, actualConfig.UseNativeHashcat, "UseNativeHashcat mismatch")
	}

	if expectedConfig.AgentUpdateInterval != nil && actualConfig.AgentUpdateInterval != nil {
		assert.Equal(
			t,
			*expectedConfig.AgentUpdateInterval,
			*actualConfig.AgentUpdateInterval,
			"AgentUpdateInterval mismatch",
		)
	} else {
		assert.Equal(
			t,
			expectedConfig.AgentUpdateInterval,
			actualConfig.AgentUpdateInterval,
			"AgentUpdateInterval mismatch",
		)
	}

	if expectedConfig.BackendDevice != nil && actualConfig.BackendDevice != nil {
		assert.Equal(t, *expectedConfig.BackendDevice, *actualConfig.BackendDevice, "BackendDevice mismatch")
	} else {
		assert.Equal(t, expectedConfig.BackendDevice, actualConfig.BackendDevice, "BackendDevice mismatch")
	}

	if expectedConfig.OpenclDevices != nil && actualConfig.OpenclDevices != nil {
		assert.Equal(t, *expectedConfig.OpenclDevices, *actualConfig.OpenclDevices, "OpenclDevices mismatch")
	} else {
		assert.Equal(t, expectedConfig.OpenclDevices, actualConfig.OpenclDevices, "OpenclDevices mismatch")
	}
}

// AssertHashcatStatus compares hashcat Status objects including nested statusGuess and device arrays.
// Note: The Guess field uses hashcat's internal statusGuess type which is not exported,
// so Guess field comparisons are skipped. For full Guess field comparison, consider
// creating a helper in the hashcat package or using reflection.
func AssertHashcatStatus(t *testing.T, expected, actual hashcat.Status) {
	t.Helper()
	assert.Equal(t, expected.OriginalLine, actual.OriginalLine, "OriginalLine mismatch")
	assert.Equal(t, expected.Time, actual.Time, "Time mismatch")
	assert.Equal(t, expected.Session, actual.Session, "Session mismatch")
	assert.Equal(t, expected.Status, actual.Status, "Status mismatch")
	assert.Equal(t, expected.Target, actual.Target, "Target mismatch")
	assert.Equal(t, expected.Progress, actual.Progress, "Progress mismatch")
	assert.Equal(t, expected.RestorePoint, actual.RestorePoint, "RestorePoint mismatch")
	assert.Equal(t, expected.RecoveredHashes, actual.RecoveredHashes, "RecoveredHashes mismatch")
	assert.Equal(t, expected.RecoveredSalts, actual.RecoveredSalts, "RecoveredSalts mismatch")
	assert.Equal(t, expected.Rejected, actual.Rejected, "Rejected mismatch")
	assert.Equal(t, expected.TimeStart, actual.TimeStart, "TimeStart mismatch")
	assert.Equal(t, expected.EstimatedStop, actual.EstimatedStop, "EstimatedStop mismatch")

	// Note: Guess field comparison skipped because statusGuess type is unexported.
	// To compare Guess fields, use a helper in the hashcat package or JSON marshaling/unmarshaling.

	// Compare Devices
	assert.Len(t, actual.Devices, len(expected.Devices), "Devices length mismatch")
	for i := range expected.Devices {
		if i >= len(actual.Devices) {
			continue
		}
		assert.Equal(t, expected.Devices[i].DeviceID, actual.Devices[i].DeviceID, "Device[%d].DeviceID mismatch", i)
		assert.Equal(
			t,
			expected.Devices[i].DeviceName,
			actual.Devices[i].DeviceName,
			"Device[%d].DeviceName mismatch",
			i,
		)
		assert.Equal(
			t,
			expected.Devices[i].DeviceType,
			actual.Devices[i].DeviceType,
			"Device[%d].DeviceType mismatch",
			i,
		)
		assert.Equal(t, expected.Devices[i].Speed, actual.Devices[i].Speed, "Device[%d].Speed mismatch", i)
		assert.Equal(t, expected.Devices[i].Util, actual.Devices[i].Util, "Device[%d].Util mismatch", i)
		assert.Equal(t, expected.Devices[i].Temp, actual.Devices[i].Temp, "Device[%d].Temp mismatch", i)
	}
}
