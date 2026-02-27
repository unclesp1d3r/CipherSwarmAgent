package hashcat

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nxadm/tail"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// setupSessionTestState sets up minimal agentstate paths for session tests.
// Uses t.TempDir() for automatic cleanup and t.Cleanup() to restore state.
func setupSessionTestState(t *testing.T) {
	t.Helper()
	tempDir := t.TempDir()

	savedZapsPath := agentstate.State.ZapsPath
	savedRetain := agentstate.State.RetainZapsOnCompletion

	agentstate.State.ZapsPath = filepath.Join(tempDir, "zaps")
	agentstate.State.RetainZapsOnCompletion = true // Avoid removing zaps dir during tests

	t.Cleanup(func() {
		agentstate.State.ZapsPath = savedZapsPath
		agentstate.State.RetainZapsOnCompletion = savedRetain
	})
}

// TestCleanup_RemovesRestoreFile verifies that Session.Cleanup removes the restore file.
func TestCleanup_RemovesRestoreFile(t *testing.T) {
	setupSessionTestState(t)

	restoreFile := filepath.Join(t.TempDir(), "test.restore")
	require.NoError(t, os.WriteFile(restoreFile, []byte("restore-data"), 0o600))

	sess := &Session{
		RestoreFilePath: restoreFile,
	}

	sess.Cleanup()

	_, err := os.Stat(restoreFile)
	require.True(t, os.IsNotExist(err), "restore file should be removed after Cleanup")
	require.Empty(t, sess.RestoreFilePath, "RestoreFilePath should be cleared after Cleanup")
}

// TestCleanup_SkipsMissingRestoreFile verifies that Cleanup does not error
// when the restore file does not exist.
func TestCleanup_SkipsMissingRestoreFile(t *testing.T) {
	setupSessionTestState(t)

	sess := &Session{
		RestoreFilePath: filepath.Join(t.TempDir(), "nonexistent.restore"),
	}

	// Should not panic
	sess.Cleanup()
}

// TestCleanup_SkipsEmptyRestoreFilePath verifies that Cleanup handles
// an empty RestoreFilePath gracefully.
func TestCleanup_SkipsEmptyRestoreFilePath(t *testing.T) {
	setupSessionTestState(t)

	sess := &Session{
		RestoreFilePath: "",
	}

	// Should not panic
	sess.Cleanup()
}

// testTimeout is the maximum time to wait for a goroutine to exit in cancellation tests.
const testTimeout = 5 * time.Second

// TestHandleStdout_ExitsOnContextCancellation verifies that handleStdout exits
// promptly when the session context is cancelled, even with full channel buffers.
func TestHandleStdout_ExitsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	pr, pw := io.Pipe()

	// Use CommandContext so the process is killed when context is cancelled,
	// allowing proc.Wait() inside handleStdout to return immediately.
	cmd := exec.CommandContext(ctx, "sleep", "60")
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		cancel()
		_ = pw.Close()
	})

	sess := &Session{
		ctx:               ctx,
		cancel:            cancel,
		proc:              cmd,
		pStdout:           pr,
		StdoutLines:       make(chan string, channelBufferSize),
		StatusUpdates:     make(chan Status, channelBufferSize),
		DoneChan:          make(chan error),
		SkipStatusUpdates: true,
	}

	// Fill StdoutLines to capacity so the next send blocks
	for i := range channelBufferSize {
		sess.StdoutLines <- fmt.Sprintf("prefill-%d", i)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleStdout()
	}()

	// Write a line that will cause handleStdout to block on channel send
	_, err := fmt.Fprintln(pw, "this line will block")
	require.NoError(t, err)

	// Give the goroutine time to read the line and block on the full channel
	time.Sleep(50 * time.Millisecond)

	// Cancel context — goroutine should unblock via select and exit
	cancel()

	select {
	case <-done:
		// Success: handleStdout exited
	case <-time.After(testTimeout):
		t.Fatal("handleStdout did not exit after context cancellation")
	}
}

// TestHandleStdout_DoneChanNoBlockOnCancellation verifies that handleStdout
// does not block on the unbuffered DoneChan when the context is already cancelled.
// This simulates the timeout scenario where the consumer has already exited.
func TestHandleStdout_DoneChanNoBlockOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Pre-cancel context to simulate timeout scenario
	cancel()

	pr, pw := io.Pipe()
	_ = pw.Close() // Close pipe so scanner.Scan() returns false immediately

	// Use context.Background() because the test context is already cancelled.
	// "true" exits immediately, so proc.Wait() returns right away.
	cmd := exec.CommandContext(context.Background(), "true")
	require.NoError(t, cmd.Start())

	sess := &Session{
		ctx:               ctx,
		cancel:            cancel,
		proc:              cmd,
		pStdout:           pr,
		StdoutLines:       make(chan string, channelBufferSize),
		StatusUpdates:     make(chan Status, channelBufferSize),
		DoneChan:          make(chan error), // unbuffered, no consumer
		SkipStatusUpdates: true,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleStdout()
	}()

	select {
	case <-done:
		// Success: handleStdout did not block on DoneChan
	case <-time.After(testTimeout):
		t.Fatal("handleStdout blocked on unbuffered DoneChan with cancelled context")
	}
}

// TestHandleStderr_ExitsOnContextCancellation verifies that handleStderr exits
// promptly when the session context is cancelled, even with a full channel buffer.
func TestHandleStderr_ExitsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	pr, pw := io.Pipe()

	t.Cleanup(func() {
		cancel()
		_ = pw.Close()
	})

	sess := &Session{
		ctx:            ctx,
		cancel:         cancel,
		pStderr:        pr,
		StderrMessages: make(chan string, channelBufferSize),
	}

	// Fill StderrMessages to capacity so the next send blocks
	for i := range channelBufferSize {
		sess.StderrMessages <- fmt.Sprintf("prefill-%d", i)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleStderr()
	}()

	// Write a line that will cause handleStderr to block on channel send
	_, err := fmt.Fprintln(pw, "stderr error line")
	require.NoError(t, err)

	// Give the goroutine time to read the line and block
	time.Sleep(50 * time.Millisecond)

	// Cancel context — goroutine should unblock and exit
	cancel()

	select {
	case <-done:
		// Success: handleStderr exited
	case <-time.After(testTimeout):
		t.Fatal("handleStderr did not exit after context cancellation")
	}
}

// TestHandleTailerOutput_ExitsOnContextCancellation verifies that
// handleTailerOutput exits promptly when the session context is cancelled
// and properly cleans up the tailer.
func TestHandleTailerOutput_ExitsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create a temp file for the tailer to follow
	tmpFile := filepath.Join(t.TempDir(), "test.out")
	require.NoError(t, os.WriteFile(tmpFile, []byte{}, 0o600))

	tailer, err := tail.TailFile(tmpFile, tail.Config{
		Follow: true,
		Logger: tail.DiscardingLogger,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		cancel()
		tailer.Cleanup()
	})

	sess := &Session{
		ctx:           ctx,
		cancel:        cancel,
		CrackedHashes: make(chan Result, channelBufferSize),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleTailerOutput(tailer)
	}()

	// Cancel context — handleTailerOutput should exit via the outer ctx.Done() case
	cancel()

	select {
	case <-done:
		// Success: handleTailerOutput exited and cleaned up tailer
	case <-time.After(testTimeout):
		t.Fatal("handleTailerOutput did not exit after context cancellation")
	}
}
