package task

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// TestDownloadResourceFile_UsesInjectedFilePath verifies that downloadResourceFile
// constructs the destination path from the injected filePath argument rather than
// from agentstate.State.FilePath.
//
// Strategy: pre-create the resource file at the injected path so that
// downloader.FileExistsAndValid returns true and the actual network download
// is skipped. This avoids the pb progress-bar pool lifecycle issues in non-TTY
// test environments while still exercising the critical filepath.Join(filePath, ...)
// injection point.
func TestDownloadResourceFile_UsesInjectedFilePath(t *testing.T) {
	t.Cleanup(testhelpers.SetupMinimalTestState(1))

	// Empty checksum so FileExistsAndValid skips checksum verification.
	agentstate.State.AlwaysTrustFiles = true

	injectedDir := t.TempDir()

	// Pre-create the file at the injected path. downloader.FileExistsAndValid will
	// find it and skip the network download entirely.
	preCreated := filepath.Join(injectedDir, "wordlist.txt")
	require.NoError(t, os.WriteFile(preCreated, []byte("word1\nword2\n"), 0o600))

	// Point agentstate.State.FilePath to a different directory so accidental reads
	// of agentstate are detectable — the file does NOT exist there.
	agentstate.State.FilePath = t.TempDir()

	resource := &api.AttackResourceFile{
		FileName:    "wordlist.txt",
		DownloadUrl: "http://127.0.0.1:1/unused", // never reached; file is already valid
		Checksum:    []byte{},
	}

	err := downloadResourceFile(context.Background(), resource, injectedDir)
	require.NoError(t, err, "should succeed: file already valid at injected path")

	// The file must exist at injectedDir — confirming the injected path was used.
	_, statErr := os.Stat(preCreated)
	require.NoError(t, statErr, "file should remain at injected filePath")

	// The file must NOT appear at agentstate.State.FilePath.
	wrongFile := filepath.Join(agentstate.State.FilePath, "wordlist.txt")
	_, wrongErr := os.Stat(wrongFile)
	require.True(t, os.IsNotExist(wrongErr), "file should NOT be at agentstate.State.FilePath")
}
