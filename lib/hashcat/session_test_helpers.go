package hashcat

// NewTestSession creates a minimal Session for testing without requiring the hashcat binary.
// It initializes only the channels needed for test communication. No process, files, or
// context are set up — the session is not startable.
// It is exported (rather than in a _test.go file) so that lib/testhelpers can call it
// across package boundaries without circular imports.
// The skipStatusUpdates parameter controls whether status update parsing is skipped.
func NewTestSession(skipStatusUpdates bool) *Session {
	const testChannelBufferSize = 5

	return &Session{
		CrackedHashes:     make(chan Result, testChannelBufferSize),
		StatusUpdates:     make(chan Status, testChannelBufferSize),
		StderrMessages:    make(chan string, testChannelBufferSize),
		StdoutLines:       make(chan string, testChannelBufferSize),
		DoneChan:          make(chan error),
		SkipStatusUpdates: skipStatusUpdates,
	}
}
