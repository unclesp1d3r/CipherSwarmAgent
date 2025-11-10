package downloader

import (
	"os"
	"path/filepath"
	"testing"

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
				err := os.WriteFile(filePath, []byte("test content"), 0o644)
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
				err := os.WriteFile(filePath, []byte("test content"), 0o644)
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
				err := os.WriteFile(filePath, []byte("test content"), 0o644)
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
