// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"os"
	"path/filepath"

	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// NewMockSession creates a minimal hashcat.Session for testing.
// It uses hashcat.NewHashcatSession with test parameters (simple mask attack, test hash).
// Sets SkipStatusUpdates to true to avoid status parsing.
// Returns the session without starting it.
// Document that this creates a real session object but doesn't execute hashcat.
// Cleanup should be called after test.
func NewMockSession(sessionName string) (*hashcat.Session, error) {
	params := CreateTestHashcatParams()
	return hashcat.NewHashcatSession(sessionName, params)
}

// MockSessionWithChannels creates a session with pre-initialized channels for testing.
// Similar to NewMockSession but ensures all channels are ready.
// Useful for tests that need to send data through channels.
func MockSessionWithChannels(sessionName string) (*hashcat.Session, error) {
	sess, err := NewMockSession(sessionName)
	if err != nil {
		return nil, err
	}
	// Channels are already initialized by NewHashcatSession
	return sess, nil
}

// CreateTestHashcatParams returns minimal valid hashcat.Params for creating test sessions.
// AttackMode: hashcat.AttackModeMask
// HashFile: path to test hash file (create in temp directory)
// Mask: "?l" (simple lowercase mask)
// Other fields set to reasonable defaults.
func CreateTestHashcatParams() hashcat.Params {
	// Create a temporary hash file for testing
	tempDir := shared.State.OutPath
	if tempDir == "" {
		tempDir = os.TempDir()
	}

	hashFile := filepath.Join(tempDir, "test_hash.txt")
	// Create an empty hash file
	file, _ := os.Create(hashFile)
	if file != nil {
		_, _ = file.WriteString("testhash\n")
		_ = file.Close()
	}

	return hashcat.Params{
		AttackMode:       hashcat.AttackModeMask,
		HashType:         0, // MD5
		HashFile:         hashFile,
		Mask:             "?l",
		OptimizedKernels: false,
		SlowCandidates:   false,
	}
}
