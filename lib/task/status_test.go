package task

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// TestConvertToTaskStatusGuessBasePercentage tests percentage field mapping.
func TestConvertToTaskStatusGuessBasePercentage(t *testing.T) {
	data := `{
        "guess": {
            "guess_base": "base",
            "guess_base_count": 10,
            "guess_base_offset": 2,
            "guess_base_percent": 25.5,
            "guess_mod": "mod",
            "guess_mod_count": 20,
            "guess_mod_offset": 5,
            "guess_mod_percent": 30.7,
            "guess_mode": 0
        },
        "status": 1,
        "target": "target",
        "progress": [1,2],
        "restore_point": 0,
        "recovered_hashes": [0,0],
        "recovered_salts": [0,0],
        "rejected": 0,
        "time_start": 0,
        "estimated_stop": 0
    }`

	var update hashcat.Status
	if err := json.Unmarshal([]byte(data), &update); err != nil {
		t.Fatalf("failed to unmarshal status: %v", err)
	}

	devices := []hashcat.StatusDevice{{
		DeviceID:   1,
		DeviceName: "GPU0",
		DeviceType: "GPU",
		Speed:      100,
		Util:       50,
		Temp:       70,
	}}

	status := convertToTaskStatus(update, convertDeviceStatuses(devices))

	if status.HashcatGuess.GuessBasePercentage != update.Guess.GuessBasePercent {
		t.Fatalf("expected %v, got %v", update.Guess.GuessBasePercent, status.HashcatGuess.GuessBasePercentage)
	}
}

// TestSendStatusUpdate tests the sendStatusUpdate method.
func TestSendStatusUpdate(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(taskID int64)
		status    hashcat.Status
	}{
		{
			name: "successful status update",
			setupMock: func(taskID int64) {
				testhelpers.MockSendStatusSuccess(taskID)
			},
			status: testhelpers.NewTestHashcatStatus("test-session"),
		},
		{
			name: "stale status update",
			setupMock: func(taskID int64) {
				testhelpers.MockSendStatusStale(taskID)
			},
			status: testhelpers.NewTestHashcatStatus("test-session"),
		},
		{
			name: "status update with zero time",
			setupMock: func(taskID int64) {
				testhelpers.MockSendStatusSuccess(taskID)
			},
			status: func() hashcat.Status {
				s := testhelpers.NewTestHashcatStatus("test-session")
				s.Time = time.Time{}
				return s
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			defer cleanupState()

			task := testhelpers.NewTestTask(456, 789)
			tt.setupMock(456)

			// Create a mock session
			sess, err := testhelpers.NewMockSession("test-session")
			if err != nil {
				t.Skipf("Skipping test: failed to create mock session: %v", err)
				return
			}
			defer sess.Cleanup()

			mgr := newTestManager()
			mgr.sendStatusUpdate(tt.status, task, sess)

			// Verify httpmock call count for send_status endpoint
			info := httpmock.GetCallCountInfo()
			var callCount int
			callCount += info["POST =~^https?://[^/]+/api/v1/tasks/456/send_status$"]
			callCount += info["POST =~^https?://[^/]+/api/v1/client/tasks/456/submit_status$"]
			callCount += info["POST https://test.api/api/v1/tasks/456/send_status"]
			callCount += info["POST https://test.api/api/v1/client/tasks/456/submit_status"]
			assert.Positive(t, callCount, "send_status endpoint should be called")
		})
	}
}

// TestSendCrackedHash tests the sendCrackedHash method.
func TestSendCrackedHash(t *testing.T) {
	tests := []struct {
		name              string
		setupMock         func(taskID int64)
		task              *api.Task
		writeZapsToFile   bool
		expectedError     bool
		expectSubmitError bool
	}{
		{
			name: "successful crack submission",
			setupMock: func(taskID int64) {
				testhelpers.MockSendCrackSuccess(taskID)
			},
			task:              testhelpers.NewTestTask(456, 789),
			writeZapsToFile:   false,
			expectedError:     false,
			expectSubmitError: false,
		},
		{
			name: "hashlist completion",
			setupMock: func(taskID int64) {
				testhelpers.MockSendCrackComplete(taskID)
			},
			task:              testhelpers.NewTestTask(456, 789),
			writeZapsToFile:   false,
			expectedError:     false,
			expectSubmitError: false,
		},
		{
			name: "with nil task",
			setupMock: func(_ int64) {
				// No mock needed, function returns early
			},
			task:              nil,
			writeZapsToFile:   false,
			expectedError:     false,
			expectSubmitError: false,
		},
		{
			name: "ErrorObject error handling",
			setupMock: func(_ int64) {
				errObj := testhelpers.NewValidationAPIError("task not found")
				apiErr := testhelpers.NewAPIError(http.StatusNotFound, errObj.Error())
				testhelpers.MockAPIError(
					`^https?://[^/]+/api/v1/client/tasks/\d+/submit_crack$`,
					http.StatusNotFound,
					*apiErr,
				)
				testhelpers.MockSubmitErrorSuccess(123)
			},
			task:              testhelpers.NewTestTask(456, 789),
			writeZapsToFile:   false,
			expectedError:     false,
			expectSubmitError: true,
		},
		{
			name: "APIError error handling",
			setupMock: func(_ int64) {
				apiErr := testhelpers.NewAPIError(http.StatusBadRequest, "bad request")
				testhelpers.MockAPIError(
					`^https?://[^/]+/api/v1/client/tasks/\d+/submit_crack$`,
					http.StatusBadRequest,
					*apiErr,
				)
				testhelpers.MockSubmitErrorSuccess(123)
			},
			task:              testhelpers.NewTestTask(456, 789),
			writeZapsToFile:   false,
			expectedError:     false,
			expectSubmitError: true,
		},
		{
			name: "with WriteZapsToFile enabled",
			setupMock: func(taskID int64) {
				testhelpers.MockSendCrackSuccess(taskID)
			},
			task:              testhelpers.NewTestTask(456, 789),
			writeZapsToFile:   true,
			expectedError:     false,
			expectSubmitError: false,
		},
		{
			name: "file open error - non-writable directory",
			setupMock: func(taskID int64) {
				testhelpers.MockSendCrackSuccess(taskID)
				testhelpers.MockSubmitErrorSuccess(123)
			},
			task:              testhelpers.NewTestTask(456, 789),
			writeZapsToFile:   true,
			expectedError:     false,
			expectSubmitError: true,
		},
		{
			name: "file write error - read-only file",
			setupMock: func(taskID int64) {
				testhelpers.MockSendCrackSuccess(taskID)
				testhelpers.MockSubmitErrorSuccess(123)
			},
			task:              testhelpers.NewTestTask(456, 789),
			writeZapsToFile:   true,
			expectedError:     false,
			expectSubmitError: false, // Platform-dependent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			defer cleanupState()

			// Set up mock for submit_error before capturing initial count
			testhelpers.MockSubmitErrorSuccess(123)
			initialCallCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")

			agentstate.State.WriteZapsToFile = tt.writeZapsToFile

			// Handle file I/O error test cases
			switch tt.name {
			case "file open error - non-writable directory":
				if runtime.GOOS == "windows" {
					t.Skip("Skipping Unix permission test on Windows")
				}

				tempDir := t.TempDir()
				t.Cleanup(func() {
					require.NoError(t, os.Chmod(tempDir, 0o755)) //nolint:gosec // adjusting temp dir perms for cleanup
				})

				require.NoError(
					t,
					os.Chmod(tempDir, 0o500), //nolint:gosec // test: set dir read-only to exercise error path
				)

				agentstate.State.ZapsPath = tempDir
			case "file write error - read-only file":
				if runtime.GOOS == "windows" {
					t.Skip("Skipping Unix permission test on Windows")
				}

				tempDir := t.TempDir()
				t.Cleanup(func() {
					require.NoError(t, os.Chmod(tempDir, 0o755)) //nolint:gosec // adjusting temp dir perms for cleanup
				})

				hashFile := path.Join(tempDir, fmt.Sprintf("%d_clientout.zap", tt.task.Id))

				file, err := os.OpenFile(hashFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
				require.NoError(t, err)
				require.NoError(t, file.Close())

				require.NoError(t, os.Chmod(tempDir, 0o500)) //nolint:gosec // Read-only directory for error path

				agentstate.State.ZapsPath = tempDir
			}

			if tt.task != nil {
				tt.setupMock(tt.task.Id)
			}

			mgr := newTestManager()
			mgr.sendCrackedHash(time.Now(), "testhash", "plaintext", tt.task)

			// Verify httpmock call counts
			if tt.task != nil && !tt.expectSubmitError {
				info := httpmock.GetCallCountInfo()
				var callCount int
				callCount += info["POST =~^https?://[^/]+/api/v1/tasks/456/send_crack$"]
				callCount += info["POST =~^https?://[^/]+/api/v1/client/tasks/456/submit_crack$"]
				callCount += info["POST https://test.api/api/v1/tasks/456/send_crack"]
				callCount += info["POST https://test.api/api/v1/client/tasks/456/submit_crack"]
				assert.Positive(t, callCount, "send_crack endpoint should be called")
			}

			// Verify file was created if WriteZapsToFile is enabled and no errors expected
			if tt.writeZapsToFile && tt.task != nil && !tt.expectSubmitError {
				hashFile := path.Join(agentstate.State.ZapsPath, fmt.Sprintf("%d_clientout.zap", tt.task.Id))
				_, err := os.Stat(hashFile)
				require.NoError(t, err, "zap file should be created")
			}

			// Verify submit_error was called for error cases
			finalCallCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")
			if tt.expectSubmitError {
				assert.Greater(t, finalCallCount, initialCallCount, "submit_error should be called on error")
			} else {
				assert.Equal(t, finalCallCount, initialCallCount, "submit_error should not be called when no error")
			}
		})
	}
}

// TestConvertDeviceStatuses tests the convertDeviceStatuses function.
func TestConvertDeviceStatuses(t *testing.T) {
	tests := []struct {
		name     string
		devices  []hashcat.StatusDevice
		expected []api.DeviceStatus
	}{
		{
			name: "single CPU device",
			devices: []hashcat.StatusDevice{
				{
					DeviceID:   0,
					DeviceName: "CPU",
					DeviceType: "CPU",
					Speed:      1000,
					Util:       50,
					Temp:       60,
				},
			},
			expected: []api.DeviceStatus{
				{
					DeviceId:    0,
					DeviceName:  "CPU",
					DeviceType:  api.CPU,
					Speed:       1000,
					Utilization: 50,
					Temperature: 60,
				},
			},
		},
		{
			name: "multiple devices with GPU",
			devices: []hashcat.StatusDevice{
				{
					DeviceID:   0,
					DeviceName: "CPU",
					DeviceType: "CPU",
					Speed:      1000,
					Util:       50,
					Temp:       60,
				},
				{
					DeviceID:   1,
					DeviceName: "GPU0",
					DeviceType: "GPU",
					Speed:      5000,
					Util:       80,
					Temp:       70,
				},
			},
			expected: []api.DeviceStatus{
				{
					DeviceId:    0,
					DeviceName:  "CPU",
					DeviceType:  api.CPU,
					Speed:       1000,
					Utilization: 50,
					Temperature: 60,
				},
				{
					DeviceId:    1,
					DeviceName:  "GPU0",
					DeviceType:  api.GPU,
					Speed:       5000,
					Utilization: 80,
					Temperature: 70,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertDeviceStatuses(tt.devices)
			require.Len(t, result, len(tt.expected))
			for i := range tt.expected {
				testhelpers.AssertDeviceStatus(t, tt.expected[i], result[i])
			}
		})
	}
}

// TestParseStringToDeviceType tests the parseStringToDeviceType function.
func TestParseStringToDeviceType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected api.DeviceStatusDeviceType
	}{
		{
			name:     "CPU device type",
			input:    "CPU",
			expected: api.CPU,
		},
		{
			name:     "GPU device type",
			input:    "GPU",
			expected: api.GPU,
		},
		{
			name:     "unknown device type defaults to CPU",
			input:    "UNKNOWN",
			expected: api.CPU,
		},
		{
			name:     "empty string defaults to CPU",
			input:    "",
			expected: api.CPU,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStringToDeviceType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConvertToTaskStatusAllFields tests convertToTaskStatus with all fields populated.
const epsilon = 1e-4

func TestConvertToTaskStatusAllFields(t *testing.T) {
	data := `{
        "guess": {
            "guess_base": "base",
            "guess_base_count": 10,
            "guess_base_offset": 2,
            "guess_base_percent": 25.5,
            "guess_mod": "mod",
            "guess_mod_count": 20,
            "guess_mod_offset": 5,
            "guess_mod_percent": 30.7,
            "guess_mode": 0
        },
        "status": 1,
        "target": "target",
        "progress": [1,2],
        "restore_point": 100,
        "recovered_hashes": [1,2],
        "recovered_salts": [3,4],
        "rejected": 5,
        "time_start": 1000,
        "estimated_stop": 2000
    }`

	var update hashcat.Status
	if err := json.Unmarshal([]byte(data), &update); err != nil {
		t.Fatalf("failed to unmarshal status: %v", err)
	}

	devices := []hashcat.StatusDevice{
		{
			DeviceID:   1,
			DeviceName: "GPU0",
			DeviceType: "GPU",
			Speed:      100,
			Util:       50,
			Temp:       70,
		},
	}

	status := convertToTaskStatus(update, convertDeviceStatuses(devices))

	assert.Equal(t, update.OriginalLine, status.OriginalLine)
	assert.Equal(t, update.Time, status.Time)
	assert.Equal(t, update.Session, status.Session)
	assert.Equal(t, int(update.Status), status.Status)
	assert.Equal(t, update.Target, status.Target)
	assert.Equal(t, update.Progress, status.Progress)
	assert.Equal(t, update.RestorePoint, status.RestorePoint)
	assert.Len(t, status.RecoveredHashes, len(update.RecoveredHashes))
	for i := range update.RecoveredHashes {
		assert.Equal(t, int(update.RecoveredHashes[i]), status.RecoveredHashes[i])
	}
	assert.Len(t, status.RecoveredSalts, len(update.RecoveredSalts))
	for i := range update.RecoveredSalts {
		assert.Equal(t, int(update.RecoveredSalts[i]), status.RecoveredSalts[i])
	}
	assert.Equal(t, update.Rejected, status.Rejected)
	assert.Equal(t, update.Guess.GuessBase, status.HashcatGuess.GuessBase)
	assert.Equal(t, update.Guess.GuessBaseCount, status.HashcatGuess.GuessBaseCount)
	assert.Equal(t, update.Guess.GuessBaseOffset, status.HashcatGuess.GuessBaseOffset)
	assert.InEpsilon(t, update.Guess.GuessBasePercent, status.HashcatGuess.GuessBasePercentage, epsilon)
	assert.Equal(t, update.Guess.GuessMod, status.HashcatGuess.GuessMod)
	assert.Equal(t, update.Guess.GuessModCount, status.HashcatGuess.GuessModCount)
	assert.Equal(t, update.Guess.GuessModOffset, status.HashcatGuess.GuessModOffset)
	assert.InEpsilon(t, update.Guess.GuessModPercent, status.HashcatGuess.GuessModPercentage, epsilon)
	assert.Equal(t, int(update.Guess.GuessMode), status.HashcatGuess.GuessMode)
}

// TestHandleSendStatusResponse tests the handleSendStatusResponse method.
func TestHandleSendStatusResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		task       *api.Task
	}{
		{
			name:       "HTTP 204 No Content",
			statusCode: http.StatusNoContent,
			task:       testhelpers.NewTestTask(456, 789),
		},
		{
			name:       "HTTP 202 Accepted",
			statusCode: http.StatusAccepted,
			task:       testhelpers.NewTestTask(456, 789),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()
			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			defer cleanupState()

			resp := &api.SendStatusResponse{
				HTTPResponse: &http.Response{StatusCode: tt.statusCode},
			}

			mgr := newTestManager()
			mgr.handleSendStatusResponse(resp, tt.task)
		})
	}
}
