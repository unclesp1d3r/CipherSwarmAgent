package zap

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
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
		task          *api.Task
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

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zapFilePath := filepath.Join(tempDir, fmt.Sprintf("test_%d.zap", i))
			reader := strings.NewReader(tt.content)

			err := createAndWriteZapFile(context.Background(), zapFilePath, reader, tt.task)

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

// TestProcessZapFile_ColonSafe verifies that colon-bearing hashes round-trip
// intact (split on the last colon, not the first).
func TestProcessZapFile_ColonSafe(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		line          string
		wantHash      string
		wantPlaintext string
	}{
		{
			name:          "NTLMv2 hash with embedded colons",
			line:          "admin::CORP:1122334455667788:1f3a8b:0101000000:Spring2024!",
			wantHash:      "admin::CORP:1122334455667788:1f3a8b:0101000000",
			wantPlaintext: "Spring2024!",
		},
		{
			name:          "Kerberos krb5asrep with embedded colons",
			line:          "$krb5asrep$23$user@REALM:abcdef0123456789:hunter2",
			wantHash:      "$krb5asrep$23$user@REALM:abcdef0123456789",
			wantPlaintext: "hunter2",
		},
		{
			name:          "PBKDF2 sha256:rounds:salt:hash",
			line:          "sha256:20000:c2FsdHNhbHQ:aGFzaGhhc2g:secret",
			wantHash:      "sha256:20000:c2FsdHNhbHQ:aGFzaGhhc2g",
			wantPlaintext: "secret",
		},
		{
			name:          "plain MD5 with no embedded colon (regression)",
			line:          "5d41402abc4b2a76b9719d911017c592:hello",
			wantHash:      "5d41402abc4b2a76b9719d911017c592",
			wantPlaintext: "hello",
		},
		{
			// KTD3 documented limitation: a plaintext containing a colon is
			// misattributed because the split is on the last colon. Pinned here so
			// a future format/escaping change is greppable.
			name:          "plaintext containing a colon (documented limitation)",
			line:          "5d41402abc4b2a76b9719d911017c592:pa:ss",
			wantHash:      "5d41402abc4b2a76b9719d911017c592:pa",
			wantPlaintext: "ss",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zapFilePath := filepath.Join(tempDir, fmt.Sprintf("colon_%d.zap", i))
			require.NoError(t, os.WriteFile(zapFilePath, []byte(tt.line), 0o600))

			var gotHash, gotPlaintext string
			calls := 0
			mockSendFunc := func(_ context.Context, _ time.Time, hash, plaintext string, _ *api.Task) {
				calls++
				gotHash = hash
				gotPlaintext = plaintext
			}

			task := testhelpers.NewTestTask(123, 456)
			require.NoError(t, processZapFile(context.Background(), zapFilePath, task, mockSendFunc))

			require.Equal(t, 1, calls, "exactly one cracked hash should be submitted")
			assert.Equal(t, tt.wantHash, gotHash, "hash must not be truncated")
			assert.Equal(t, tt.wantPlaintext, gotPlaintext)
		})
	}
}

// TestProcessZapFile_OpenError verifies that a failed open returns a wrapped error.
func TestProcessZapFile_OpenError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.zap")
	task := testhelpers.NewTestTask(123, 456)
	noopSend := func(context.Context, time.Time, string, string, *api.Task) {}

	err := processZapFile(context.Background(), missing, task, noopSend)
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist, "open failure should wrap the underlying cause")
}

// TestRemoveExistingZapFile_WrapsError verifies removeExistingZapFile wraps a
// non-not-exist removal failure with context.
func TestRemoveExistingZapFile_WrapsError(t *testing.T) {
	// os.Remove on a non-empty directory fails with a non-IsNotExist error on every
	// platform (rmdir requires the directory to be empty, regardless of privileges),
	// so removeExistingZapFile must return the wrapped error including the path.
	target := filepath.Join(t.TempDir(), "nonempty.zap")
	require.NoError(t, os.MkdirAll(target, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(target, "child"), []byte("x"), 0o600))

	err := removeExistingZapFile(target)
	require.Error(t, err)
	require.ErrorContains(t, err, target)
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

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zapFilePath := filepath.Join(tempDir, fmt.Sprintf("test_%d.zap", i))
			err := os.WriteFile(zapFilePath, []byte(tt.content), 0o600)
			require.NoError(t, err)

			callCount := 0
			mockSendFunc := func(_ context.Context, _ time.Time, hash, plaintext string, _ *api.Task) {
				callCount++
				assert.NotEmpty(t, hash)
				assert.NotEmpty(t, plaintext)
			}

			task := testhelpers.NewTestTask(123, 456)
			err = processZapFile(context.Background(), zapFilePath, task, mockSendFunc)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCalls, callCount)
			}
		})
	}
}

// TestHandleResponseStream_UsesInjectedZapsPath verifies that handleResponseStream
// writes the zap file to the injected zapsPath argument rather than reading from
// agentstate.State. This is the U9 injection-point test for lib/zap.
func TestHandleResponseStream_UsesInjectedZapsPath(t *testing.T) {
	zapsDir := t.TempDir()
	task := testhelpers.NewTestTask(123, 456)

	content := "5d41402abc4b2a76b9719d911017c592:hello\n"
	reader := io.NopCloser(strings.NewReader(content))

	var gotHash, gotPlaintext string
	sendFunc := func(_ context.Context, _ time.Time, hash, plaintext string, _ *api.Task) {
		gotHash = hash
		gotPlaintext = plaintext
	}

	err := handleResponseStream(context.Background(), task, reader, sendFunc, zapsDir)
	require.NoError(t, err)

	zapFile := filepath.Join(zapsDir, "123.zap")
	_, statErr := os.Stat(zapFile)
	require.NoError(t, statErr, "zap file should be created at injected zapsPath")

	assert.Equal(t, "5d41402abc4b2a76b9719d911017c592", gotHash)
	assert.Equal(t, "hello", gotPlaintext)
}
