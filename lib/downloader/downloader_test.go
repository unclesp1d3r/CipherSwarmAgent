package downloader

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileExistsAndValid tests the FileExistsAndValid function.
func TestFileExistsAndValid(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name           string
		setupFile      func() string
		checksum       string
		expectedResult bool
	}{
		{
			name: "file exists with matching checksum",
			setupFile: func() string {
				filePath := filepath.Join(tempDir, "test1.txt")
				err := os.WriteFile(filePath, []byte("test content"), 0o600)
				require.NoError(t, err)
				return filePath
			},
			checksum:       "9473fdd0d880a43c21b7778d34872157", // MD5 of "test content"
			expectedResult: true,
		},
		{
			name: "file exists with no checksum provided",
			setupFile: func() string {
				filePath := filepath.Join(tempDir, "test2.txt")
				err := os.WriteFile(filePath, []byte("test content"), 0o600)
				require.NoError(t, err)
				return filePath
			},
			checksum:       "",
			expectedResult: true,
		},
		{
			name: "file exists with mismatched checksum",
			setupFile: func() string {
				filePath := filepath.Join(tempDir, "test3.txt")
				err := os.WriteFile(filePath, []byte("test content"), 0o600)
				require.NoError(t, err)
				return filePath
			},
			checksum:       "wrongchecksum123456789012345678901",
			expectedResult: false,
		},
		{
			name: "file does not exist",
			setupFile: func() string {
				return filepath.Join(tempDir, "nonexistent.txt")
			},
			checksum:       "somechecksum",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setupFile()
			result := FileExistsAndValid(filePath, tt.checksum)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// TestAppendChecksumToURL tests the appendChecksumToURL function.
func TestAppendChecksumToURL(t *testing.T) {
	tests := []struct {
		name        string
		fileURL     string
		checksum    string
		expectedURL string
		expectError bool
	}{
		{
			name:        "valid URL without query params",
			fileURL:     "https://example.com/file.txt",
			checksum:    "abc123",
			expectedURL: "https://example.com/file.txt?checksum=md5%3Aabc123", // URL-encoded :
			expectError: false,
		},
		{
			name:        "valid URL with existing query params",
			fileURL:     "https://example.com/file.txt?param=value",
			checksum:    "def456",
			expectedURL: "https://example.com/file.txt?checksum=md5%3Adef456&param=value",
			expectError: false,
		},
		{
			name:        "invalid URL",
			fileURL:     "://invalid-url",
			checksum:    "abc123",
			expectedURL: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := appendChecksumToURL(tt.fileURL, tt.checksum)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedURL, result)
			}
		})
	}
}

// TestBase64ToHex tests the Base64ToHex function.
func TestBase64ToHex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid base64 string",
			input:    "SGVsbG8gV29ybGQ=", // "Hello World" in base64
			expected: "48656c6c6f20576f726c64",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "another valid base64",
			input:    "VGVzdA==", // "Test" in base64
			expected: "54657374",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Base64ToHex(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// mockGetter is a mock implementation of the Getter interface for testing.
type mockGetter struct {
	callCount   atomic.Int32
	failCount   int
	returnError error
}

// Get implements the Getter interface. It tracks the number of calls and
// returns an error for the first failCount calls, then succeeds.
func (m *mockGetter) Get() error {
	currentCall := m.callCount.Add(1)
	if int(currentCall) <= m.failCount {
		if m.returnError != nil {
			return m.returnError
		}
		return errors.New("simulated download failure")
	}
	return nil
}

// getCallCount returns the number of times Get() was called.
func (m *mockGetter) getCallCount() int {
	return int(m.callCount.Load())
}

// TestDownloadWithRetry tests the downloadWithRetry function with various retry scenarios.
func TestDownloadWithRetry(t *testing.T) {
	tests := []struct {
		name          string
		maxRetries    int
		failCount     int
		expectSuccess bool
		expectedCalls int
	}{
		{
			name:          "success on first try",
			maxRetries:    3,
			failCount:     0,
			expectSuccess: true,
			expectedCalls: 1,
		},
		{
			name:          "success after 1 retry",
			maxRetries:    3,
			failCount:     1,
			expectSuccess: true,
			expectedCalls: 2,
		},
		{
			name:          "success on last retry",
			maxRetries:    3,
			failCount:     2,
			expectSuccess: true,
			expectedCalls: 3,
		},
		{
			name:          "all retries exhausted",
			maxRetries:    3,
			failCount:     3,
			expectSuccess: false,
			expectedCalls: 3,
		},
		{
			name:          "single retry allowed",
			maxRetries:    1,
			failCount:     1,
			expectSuccess: false,
			expectedCalls: 1,
		},
		{
			name:          "zero retries defaults to 1",
			maxRetries:    0,
			failCount:     0,
			expectSuccess: true,
			expectedCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockGetter{
				failCount:   tt.failCount,
				returnError: errors.New("download failed"),
			}

			// Use very short delay for fast tests (1ms)
			err := downloadWithRetry(mock, tt.maxRetries, 1*time.Millisecond)

			if tt.expectSuccess {
				assert.NoError(t, err, "expected successful download")
			} else {
				assert.Error(t, err, "expected download to fail")
			}

			assert.Equal(t, tt.expectedCalls, mock.getCallCount(),
				"expected %d calls but got %d", tt.expectedCalls, mock.getCallCount())
		})
	}
}

// TestDownloadWithRetryPreservesLastError verifies that the last error is returned when all retries fail.
func TestDownloadWithRetryPreservesLastError(t *testing.T) {
	expectedErr := errors.New("specific download error")
	mock := &mockGetter{
		failCount:   5,
		returnError: expectedErr,
	}

	err := downloadWithRetry(mock, 3, 1*time.Millisecond)

	require.Error(t, err)
	assert.Equal(t, expectedErr, err, "should return the last error from failed attempts")
}

// TestDownloadWithRetryNegativeRetries verifies that negative maxRetries defaults to 1 attempt.
func TestDownloadWithRetryNegativeRetries(t *testing.T) {
	mock := &mockGetter{
		failCount:   0,
		returnError: errors.New("download failed"),
	}

	err := downloadWithRetry(mock, -5, 1*time.Millisecond)

	assert.NoError(t, err, "should succeed with 1 attempt when maxRetries is negative")
	assert.Equal(t, 1, mock.getCallCount(), "should make exactly 1 call when maxRetries is negative")
}
