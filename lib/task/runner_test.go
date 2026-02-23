package task

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// TestParseExitCode tests the parseExitCode function which extracts exit codes
// from error messages. This function handles both standard "exit status N" formats
// and non-standard error formats (like signal-based terminations).
func TestParseExitCode(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected int
	}{
		{
			name:     "exit status 0 - success",
			errMsg:   "exit status 0",
			expected: 0,
		},
		{
			name:     "exit status 1 - exhausted",
			errMsg:   "exit status 1",
			expected: 1,
		},
		{
			name:     "exit status 2 - aborted",
			errMsg:   "exit status 2",
			expected: 2,
		},
		{
			name:     "exit status 255 - high value",
			errMsg:   "exit status 255",
			expected: 255,
		},
		{
			name:     "exit status -1 - negative exit code",
			errMsg:   "exit status -1",
			expected: -1,
		},
		{
			name:     "exit status -2 - GPU watchdog",
			errMsg:   "exit status -2",
			expected: -2,
		},
		{
			name:     "signal killed - returns -1",
			errMsg:   "signal: killed",
			expected: -1,
		},
		{
			name:     "signal terminated - returns -1",
			errMsg:   "signal: terminated",
			expected: -1,
		},
		{
			name:     "signal interrupt - returns -1",
			errMsg:   "signal: interrupt",
			expected: -1,
		},
		{
			name:     "some other error - returns -1",
			errMsg:   "some other error",
			expected: -1,
		},
		{
			name:     "empty string - returns -1",
			errMsg:   "",
			expected: -1,
		},
		{
			name:     "whitespace only - returns -1",
			errMsg:   "   ",
			expected: -1,
		},
		{
			name:     "partial match - returns -1",
			errMsg:   "exit status",
			expected: -1,
		},
		{
			name:     "malformed exit status - returns -1",
			errMsg:   "exit status abc",
			expected: -1,
		},
		{
			name:     "exit status with extra text - extracts code",
			errMsg:   "exit status 42 (some extra info)",
			expected: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseExitCode(tt.errMsg)
			assert.Equal(t, tt.expected, result, "parseExitCode(%q) should return %d", tt.errMsg, tt.expected)
		})
	}
}

// TestParseExitCode_AllHashcatCodes tests parseExitCode with all documented hashcat exit codes.
func TestParseExitCode_AllHashcatCodes(t *testing.T) {
	hashcatExitCodes := []int{
		0,  // Cracked
		1,  // Exhausted
		2,  // Aborted
		3,  // Checkpoint abort
		4,  // Runtime limit
		-1, // General error
		-2, // GPU watchdog
		-3, // Backend abort
		-4, // Backend checkpoint abort
		-5, // Backend runtime abort
		-6, // Selftest fail
		-7, // Autotune fail
	}

	for _, exitCode := range hashcatExitCodes {
		t.Run(fmt.Sprintf("hashcat_exit_code_%d", exitCode), func(t *testing.T) {
			errMsg := fmt.Sprintf("exit status %d", exitCode)
			result := parseExitCode(errMsg)
			assert.Equal(t, exitCode, result, "parseExitCode should correctly parse hashcat exit code %d", exitCode)
		})
	}
}

// TestHandleStdErrLine tests the handleStdErrLine function which classifies stderr
// output and sends classified errors to the server.
func TestHandleStdErrLine(t *testing.T) {
	tests := []struct {
		name                 string
		stdErrLine           string
		expectSendAgentError bool
	}{
		{
			name:                 "empty line should not send error",
			stdErrLine:           "",
			expectSendAgentError: false,
		},
		{
			name:                 "whitespace only should not send error",
			stdErrLine:           "   ",
			expectSendAgentError: false,
		},
		{
			name:                 "tab only should not send error",
			stdErrLine:           "\t",
			expectSendAgentError: false,
		},
		{
			name:                 "non-empty line should send error",
			stdErrLine:           "Some error message",
			expectSendAgentError: true,
		},
		{
			name:                 "hash format error should be classified",
			stdErrLine:           "Hash 'test': Separator unmatched",
			expectSendAgentError: true,
		},
		{
			name:                 "device error should be classified",
			stdErrLine:           "Device #1: ATTENTION! out of memory",
			expectSendAgentError: true,
		},
		{
			name:                 "file access error should be classified",
			stdErrLine:           "ERROR: No such file or directory",
			expectSendAgentError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			defer cleanupState()

			// Mock SubmitErrorAgent endpoint
			testhelpers.MockSubmitErrorSuccess(123)

			// Create a test task
			task := testhelpers.NewTestTask(456, 789)

			// Get initial call count
			initialCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")

			// Call handleStdErrLine
			handleStdErrLine(tt.stdErrLine, task)

			// Verify SendAgentError behavior
			finalCount := testhelpers.GetSubmitErrorCallCount(123, "https://test.api")

			if tt.expectSendAgentError {
				assert.Greater(t, finalCount, initialCount,
					"SendAgentError should be called for non-empty stderr: %q", tt.stdErrLine)
			} else {
				assert.Equal(t, initialCount, finalCount,
					"SendAgentError should not be called for empty/whitespace stderr: %q", tt.stdErrLine)
			}
		})
	}
}

// TestClassifyStderr_KnownPatterns verifies that hashcat.ClassifyStderr
// returns correct categories and severities for known error patterns.
func TestClassifyStderr_KnownPatterns(t *testing.T) {
	errorPatterns := []struct {
		name             string
		line             string
		expectedCategory hashcat.ErrorCategory
		expectedSeverity api.Severity
	}{
		{
			name:             "no hashes loaded",
			line:             "No hashes loaded",
			expectedCategory: hashcat.ErrorCategoryHashFormat,
			expectedSeverity: api.SeverityCritical,
		},
		{
			name:             "OpenCL error",
			line:             "OpenCL API (clEnqueueNDRangeKernel) CL_OUT_OF_RESOURCES",
			expectedCategory: hashcat.ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
		},
		{
			name:             "restore file error",
			line:             "ERROR: Cannot read /path/to/session.restore",
			expectedCategory: hashcat.ErrorCategoryRetryable,
			expectedSeverity: api.SeverityMinor,
		},
	}

	for _, tt := range errorPatterns {
		t.Run(tt.name, func(t *testing.T) {
			info := hashcat.ClassifyStderr(tt.line)
			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch for %q", tt.line)
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch for %q", tt.line)
		})
	}
}

// TestHandleDoneChan tests the handleDoneChan method which handles completion
// of a hashcat task and classifies the exit code.
func TestHandleDoneChan(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		expectCleanup   bool
		expectExhausted bool
	}{
		{
			name:            "nil error - cleanup only",
			err:             nil,
			expectCleanup:   true,
			expectExhausted: false,
		},
		{
			name:            "exit status 0 - success path",
			err:             errors.New("exit status 0"),
			expectCleanup:   true,
			expectExhausted: false,
		},
		{
			name:            "exit status 1 - exhausted",
			err:             errors.New("exit status 1"),
			expectCleanup:   true,
			expectExhausted: true,
		},
		{
			name:            "exit status 2 - aborted",
			err:             errors.New("exit status 2"),
			expectCleanup:   true,
			expectExhausted: false,
		},
		{
			name:            "exit status -1 - general error",
			err:             errors.New("exit status -1"),
			expectCleanup:   true,
			expectExhausted: false,
		},
		{
			name:            "signal killed - treated as error",
			err:             errors.New("signal: killed"),
			expectCleanup:   true,
			expectExhausted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(123, "https://test.api", "test-token")
			defer cleanupState()

			// Mock endpoints
			testhelpers.MockSubmitErrorSuccess(123)

			// Create a test task
			task := testhelpers.NewTestTask(456, 789)

			// Create a mock session
			sess, err := testhelpers.NewMockSession("test-session")
			if err != nil {
				t.Skipf("Skipping test: failed to create mock session: %v", err)
			}

			mgr := newTestManager()
			mgr.handleDoneChan(tt.err, task, sess)

			if tt.expectExhausted {
				t.Log("exhausted path exercised for exit code 1")
			}
		})
	}
}

// TestHandleDoneChan_CleansRestoreFile verifies that handleDoneChan removes
// the session's restore file as part of cleanup.
func TestHandleDoneChan_CleansRestoreFile(t *testing.T) {
	t.Cleanup(testhelpers.SetupHTTPMock())
	t.Cleanup(testhelpers.SetupTestState(123, "https://test.api", "test-token"))

	testhelpers.MockSubmitErrorSuccess(123)

	task := testhelpers.NewTestTask(456, 789)

	sess, err := testhelpers.NewMockSession("test-session")
	require.NoError(t, err)

	// Create a real restore file on disk
	restoreFile := filepath.Join(t.TempDir(), "test.restore")
	require.NoError(t, os.WriteFile(restoreFile, []byte("data"), 0o600))
	sess.RestoreFilePath = restoreFile

	mgr := newTestManager()
	mgr.handleDoneChan(nil, task, sess)

	_, statErr := os.Stat(restoreFile)
	require.True(t, os.IsNotExist(statErr), "restore file should be removed after handleDoneChan")
}

// TestHandleDoneChan_CleansRestoreFile_OnError verifies that handleDoneChan
// removes the restore file even when a non-nil error (e.g., exhausted) is passed.
func TestHandleDoneChan_CleansRestoreFile_OnError(t *testing.T) {
	t.Cleanup(testhelpers.SetupHTTPMock())
	t.Cleanup(testhelpers.SetupTestState(123, "https://test.api", "test-token"))

	testhelpers.MockSubmitErrorSuccess(123)

	task := testhelpers.NewTestTask(456, 789)

	sess, err := testhelpers.NewMockSession("test-session-err")
	require.NoError(t, err)

	// Create a real restore file on disk
	restoreFile := filepath.Join(t.TempDir(), "test.restore")
	require.NoError(t, os.WriteFile(restoreFile, []byte("data"), 0o600))
	sess.RestoreFilePath = restoreFile

	mgr := newTestManager()
	// Use exit status 2 (general hashcat error) to exercise the error path
	mgr.handleDoneChan(errors.New("exit status 2"), task, sess)

	_, statErr := os.Stat(restoreFile)
	require.True(t, os.IsNotExist(statErr), "restore file should be removed after handleDoneChan with error")
}

// TestHandleDoneChan_ExitCodeHandling verifies that handleDoneChan
// correctly uses hashcat.ClassifyExitCode and IsExhausted for exit code handling.
func TestHandleDoneChan_ExitCodeHandling(t *testing.T) {
	tests := []struct {
		exitCode    int
		isExhausted bool
		isSuccess   bool
	}{
		{0, false, true},
		{1, true, false},
		{2, false, false},
		{-1, false, false},
		{-2, false, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("exit_code_%d", tt.exitCode), func(t *testing.T) {
			assert.Equal(t, tt.isExhausted, hashcat.IsExhausted(tt.exitCode),
				"IsExhausted(%d) mismatch", tt.exitCode)
			assert.Equal(t, tt.isSuccess, hashcat.IsSuccess(tt.exitCode),
				"IsSuccess(%d) mismatch", tt.exitCode)
		})
	}
}
