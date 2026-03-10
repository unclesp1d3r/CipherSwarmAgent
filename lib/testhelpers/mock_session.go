// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"os"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// NewMockSession creates a minimal hashcat.Session for testing without requiring the hashcat binary.
// It delegates to hashcat.NewTestSession to respect constructor invariants and avoid direct
// access to unexported fields.
// Returns a session that can be used in tests that need a Session reference but don't actually
// execute hashcat. The Cleanup method is a no-op since no process is started.
//
// The sessionName parameter is currently unused but kept for API consistency with potential
// future use cases where session naming might be needed.
func NewMockSession(_ string) (*hashcat.Session, error) {
	return hashcat.NewTestSession(true), nil
}

// MockSessionWithChannels creates a session with pre-initialized channels for testing.
// Similar to NewMockSession but ensures all channels are ready.
// Useful for tests that need to send data through channels.
func MockSessionWithChannels(sessionName string) (*hashcat.Session, error) {
	return NewMockSession(sessionName)
}

// CreateTestHashcatParams returns minimal valid hashcat.Params for creating test sessions
// along with a cleanup function to delete the temporary hash file.
// AttackMode: hashcat.AttackModeMask
// HashFile: path to test hash file (created in temp directory)
// Mask: "?l" (simple lowercase mask)
// Other fields set to reasonable defaults.
//
//nolint:gocritic // Named returns conflict with nonamedreturns linter
func CreateTestHashcatParams() (hashcat.Params, func()) {
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

	cleanup := func() {
		if hashFile != "" {
			_ = os.Remove(hashFile)
		}
	}

	return hashcat.Params{
		AttackMode:       hashcat.AttackModeMask,
		HashType:         0, // MD5
		HashFile:         hashFile,
		Mask:             "?l",
		OptimizedKernels: false,
		SlowCandidates:   false,
	}, cleanup
}
