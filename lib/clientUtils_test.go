package lib

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"

	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// errorHTTPClient is a stub HTTP client that always returns an error.
type errorHTTPClient struct{}

func (errorHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return nil, errors.New("http error")
}

// TestDownloadHashListError ensures downloadHashList does not panic when the
// API client returns an error.
func TestDownloadHashListError(t *testing.T) {
	// Prepare a temporary directory for hashlists.
	dir := t.TempDir()
	shared.State.HashlistPath = dir

	// Initialize the SDK client with the error HTTP client.
	SdkClient = sdk.New(sdk.WithClient(errorHTTPClient{}))
	Context = context.Background()

	attack := &components.Attack{ID: 1, HashListID: 1}

	if err := downloadHashList(attack); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestDummy(t *testing.T) {
	t.Log("Basic test structure for clientUtils.go")
}

// TestBase64ToHex verifies that base64ToHex correctly converts a known
// Base64 string to its hexadecimal representation.
func TestBase64ToHex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "valid base64",
			input: "aGVsbG8gd29ybGQ=",
			want:  "68656c6c6f20776f726c64",
		},
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "invalid base64",
			input: "not@base64",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := base64ToHex(tt.input)
			if got != tt.want {
				t.Fatalf("base64ToHex(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestIsExecAny checks that isExecAny correctly reports executable permissions.
func TestIsExecAny(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "exec")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if isExecAny(f) {
		t.Fatalf("expected false for non-executable file")
	}
	if err := os.Chmod(f, 0755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if !isExecAny(f) {
		t.Fatalf("expected true for executable file")
	}
}

// TestAppendChecksumToURL verifies checksum is appended and errors on bad URL.
func TestAppendChecksumToURL(t *testing.T) {
	url, err := appendChecksumToURL("http://example.com/file", "abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "http://example.com/file?checksum=abc"
	if url != expected {
		t.Fatalf("expected %s, got %s", expected, url)
	}

	if _, err := appendChecksumToURL(":", "x"); err == nil {
		t.Fatalf("expected error for invalid url")
	}
}

// TestResourceNameOrBlank verifies the helper returns the filename or blank.
func TestResourceNameOrBlank(t *testing.T) {
	if resourceNameOrBlank(nil) != "" {
		t.Fatalf("expected blank for nil resource")
	}
	r := &components.AttackResourceFile{FileName: "file.txt"}
	if resourceNameOrBlank(r) != "file.txt" {
		t.Fatalf("expected file.txt")
	}
}

// TestMoveArchiveFile ensures a temporary archive is moved to CrackersPath.
func TestMoveArchiveFile(t *testing.T) {
	dir := t.TempDir()
	shared.State.CrackersPath = dir
	temp := filepath.Join(dir, "tmp.7z")
	if err := os.WriteFile(temp, []byte("data"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	dest, err := moveArchiveFile(temp)
	if err != nil {
		t.Fatalf("moveArchiveFile returned error: %v", err)
	}
	expected := filepath.Join(dir, "hashcat.7z")
	if dest != expected {
		t.Fatalf("expected %s, got %s", expected, dest)
	}
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("dest file missing: %v", err)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("temp file should be moved")
	}
}

// TestRemoveExistingFile ensures existing files are removed without error.
func TestRemoveExistingFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "file")
	if err := os.WriteFile(fp, []byte("hi"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := removeExistingFile(fp); err != nil {
		t.Fatalf("removeExistingFile returned error: %v", err)
	}
	if _, err := os.Stat(fp); !os.IsNotExist(err) {
		t.Fatalf("file not removed")
	}
	if err := removeExistingFile(fp); err != nil {
		t.Fatalf("expected nil on missing file, got %v", err)
	}
}

// TestCreateLockFile writes the PID to the configured lock file.
func TestCreateLockFile(t *testing.T) {
	dir := t.TempDir()
	shared.State.PidFile = filepath.Join(dir, "pid")
	if err := CreateLockFile(); err != nil {
		t.Fatalf("CreateLockFile returned error: %v", err)
	}
	b, err := os.ReadFile(shared.State.PidFile)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	pid := strings.TrimSpace(string(b))
	if pid != strconv.Itoa(os.Getpid()) {
		t.Fatalf("pid mismatch: %s vs %d", pid, os.Getpid())
	}
}
