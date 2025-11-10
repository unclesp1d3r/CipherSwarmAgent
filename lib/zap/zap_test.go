package zap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// TestRemoveExistingZapFile tests the removeExistingZapFile function.
func TestRemoveExistingZapFile(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		setupFile     func() string
		expectedError bool
	}{
		{
			name: "remove existing file",
			setupFile: func() string {
				filePath := filepath.Join(tempDir, "test1.zap")
				err := os.WriteFile(filePath, []byte("test content"), 0o600)
				require.NoError(t, err)
				return filePath
			},
			expectedError: false,
		},
		{
			name: "remove non-existent file - should not error",
			setupFile: func() string {
				return filepath.Join(tempDir, "nonexistent.zap")
			},
			expectedError: false, // Function handles os.IsNotExist gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setupFile()
			err := removeExistingZapFile(filePath)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCreateAndWriteZapFile tests the createAndWriteZapFile function.
func TestCreateAndWriteZapFile(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		content       string
		task          *components.Task
		expectedError bool
	}{
		{
			name:          "write valid zap file",
			content:       "hash1:plain1\nhash2:plain2\n",
			task:          testhelpers.NewTestTask(123, 456),
			expectedError: false,
		},
		{
			name:          "write empty zap file",
			content:       "",
			task:          testhelpers.NewTestTask(123, 456),
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zapFilePath := filepath.Join(tempDir, tt.name+".zap")
			reader := strings.NewReader(tt.content)

			err := createAndWriteZapFile(zapFilePath, reader, tt.task)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				// Verify file was created and content matches
				content, err := os.ReadFile(zapFilePath)
				require.NoError(t, err)
				assert.Equal(t, tt.content, string(content))
			}
		})
	}
}

// TestProcessZapFile tests the processZapFile function through a file.
func TestProcessZapFile(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		content       string
		expectedCalls int
		expectedError bool
	}{
		{
			name: "valid zap file with multiple entries",
			content: `5d41402abc4b2a76b9719d911017c592:hello
098f6bcd4621d373cade4e832627b4f6:test`,
			expectedCalls: 2,
			expectedError: false,
		},
		{
			name: "zap file with invalid lines - should skip them",
			content: `5d41402abc4b2a76b9719d911017c592:hello
invalidline
098f6bcd4621d373cade4e832627b4f6:test`,
			expectedCalls: 2, // Only valid lines are processed
			expectedError: false,
		},
		{
			name:          "empty zap file",
			content:       "",
			expectedCalls: 0,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zapFilePath := filepath.Join(tempDir, tt.name+".zap")
			err := os.WriteFile(zapFilePath, []byte(tt.content), 0o600)
			require.NoError(t, err)

			callCount := 0
			mockSendFunc := func(_ time.Time, hash, plaintext string, _ *components.Task) {
				callCount++
				assert.NotEmpty(t, hash)
				assert.NotEmpty(t, plaintext)
			}

			task := testhelpers.NewTestTask(123, 456)
			err = processZapFile(zapFilePath, task, mockSendFunc)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCalls, callCount)
			}
		})
	}
}
