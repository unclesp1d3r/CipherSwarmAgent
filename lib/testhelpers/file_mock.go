// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CreateTempTestDir creates a temporary directory for test file operations
// and registers a cleanup function with t.Cleanup() to automatically remove it after the test completes.
// Returns the directory path.
func CreateTempTestDir(t *testing.T, prefix string) string {
	t.Helper()
	return t.TempDir()
}

// CreateTestFile creates a test file with the specified content in the given directory.
// Returns the full file path. Useful for testing file download verification and hashcat input files.
func CreateTestFile(t *testing.T, dir, filename string, content []byte) string {
	t.Helper()
	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, content, 0o600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	return filePath
}

// MockDownloadServer creates a test HTTP server that serves files for download testing.
// Accepts a baseDir parameter to serve files from that directory.
// Returns the server instance which should be closed via t.Cleanup().
// This will be used to test the downloader package without external dependencies.
func MockDownloadServer(t *testing.T, baseDir string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filename := filepath.Base(r.URL.Path)
		filePath := filepath.Join(baseDir, filename)

		file, err := os.Open(filePath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		defer file.Close()

		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(w, file)
	}))

	t.Cleanup(func() {
		server.Close()
	})

	return server
}

// CalculateTestChecksum calculates SHA256 checksum of provided content
// and returns it as a hex string. This mirrors the checksum verification logic
// in lib/downloader/downloader.go and allows tests to generate valid checksums for test files.
func CalculateTestChecksum(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// CreateHashListFile creates a hash list file with the provided hashes (one per line)
// in the specified directory. Returns the file path.
// This is specifically useful for testing hashcat session creation.
func CreateHashListFile(t *testing.T, dir string, hashes []string) string {
	t.Helper()
	var content string
	var contentSb79 strings.Builder
	for _, hash := range hashes {
		contentSb79.WriteString(hash + "\n")
	}
	content += contentSb79.String()
	return CreateTestFile(t, dir, "hashes.txt", []byte(content))
}
