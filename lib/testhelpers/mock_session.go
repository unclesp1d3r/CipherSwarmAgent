// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"os"
	"path/filepath"

	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// NewMockSession creates a minimal hashcat.Session for testing without requiring the hashcat binary.
// It creates a session object with initialized channels that can be used in tests.
// The session is not started and does not execute hashcat.
// Returns a session that can be used in tests that need a Session reference but don't actually
// execute hashcat. The Cleanup method is a no-op since no process is started.
func NewMockSession(sessionName string) (*hashcat.Session, error) {
	// Create a mock session with initialized channels
	// This bypasses the need for the hashcat binary entirely
	sess := &hashcat.Session{
		CrackedHashes:     make(chan hashcat.Result, 5),
		StatusUpdates:     make(chan hashcat.Status, 5),
		StderrMessages:    make(chan string, 5),
		StdoutLines:       make(chan string, 5),
		DoneChan:          make(chan error),
		SkipStatusUpdates: true,
	}

	return sess, nil
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
	file, err := os.Create(hashFile)
	if err != nil {
		panic(err)
	}
	if file != nil {
		_, err = file.WriteString("testhash\n")
		if err != nil {
			panic(err)
		}
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
