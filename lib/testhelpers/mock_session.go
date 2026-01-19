// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"os"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

const channelBufferSize = 5 // Buffer size for mock session channels

// NewMockSession creates a minimal hashcat.Session for testing without requiring the hashcat binary.
// It creates a session object with initialized channels that can be used in tests.
// The session is not started and does not execute hashcat.
// Returns a session that can be used in tests that need a Session reference but don't actually
// execute hashcat. The Cleanup method is a no-op since no process is started.
//
// The sessionName parameter is currently unused but kept for API consistency with potential
// future use cases where session naming might be needed.
func NewMockSession(_ string) (*hashcat.Session, error) {
	// Create a mock session with initialized channels
	// This bypasses the need for the hashcat binary entirely
	sess := &hashcat.Session{
		CrackedHashes:     make(chan hashcat.Result, channelBufferSize),
		StatusUpdates:     make(chan hashcat.Status, channelBufferSize),
		StderrMessages:    make(chan string, channelBufferSize),
		StdoutLines:       make(chan string, channelBufferSize),
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
	// Channels are already initialized by NewMockSession
	return sess, nil
}

// CreateTestHashcatParams returns minimal valid hashcat.Params for creating test sessions.
// AttackMode: hashcat.AttackModeMask
// HashFile: path to test hash file (create in temp directory)
// Mask: "?l" (simple lowercase mask)
// Other fields set to reasonable defaults.
func CreateTestHashcatParams() hashcat.Params {
	// Create a temporary hash file for testing
	tempDir := agentstate.State.OutPath
	if tempDir == "" {
		tempDir = os.TempDir()
	}

	// Create a unique hash file to avoid collisions in parallel tests
	file, err := os.CreateTemp(tempDir, "test_hash_*.txt")
	if err != nil {
		panic(err)
	}
	hashFile := file.Name()
	_, err = file.WriteString("testhash\n")
	if err != nil {
		_ = file.Close()
		panic(err)
	}
	_ = file.Close()

	return hashcat.Params{
		AttackMode:       hashcat.AttackModeMask,
		HashType:         0, // MD5
		HashFile:         hashFile,
		Mask:             "?l",
		OptimizedKernels: false,
		SlowCandidates:   false,
	}
}
