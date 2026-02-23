// Package hashcat provides session management and execution control for hashcat processes.
// It handles process lifecycle, I/O management, and result collection for hash cracking operations
// in a distributed agent environment.
package hashcat

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nxadm/tail"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
)

const (
	channelBufferSize = 5     // Buffer size for output channels
	filePermissions   = 0o600 // Restrictive permissions for sensitive files
	logParseMinParts  = 3     // Minimum expected parts when parsing output log lines
)

// Session represents a hashcat execution session with comprehensive process management.
// It manages the hashcat process lifecycle, handles I/O streams, and provides channels
// for real-time communication of results, status updates, and error messages.
// The session stores a context.CancelFunc to enable graceful shutdown and cancellation
// of session operations, allowing controlled termination of goroutines and resource cleanup
// during lifecycle management.
type Session struct {
	proc               *exec.Cmd  // Hashcat process command
	hashFile           string     // Path to hash input file
	outFile            *os.File   // Output file for cracked hashes
	charsetFiles       []*os.File // Custom charset files for mask attacks
	shardedCharsetFile *os.File   // Sharded charset file for distributed attacks
	cancel             context.CancelFunc
	cancelMu           sync.Mutex    // Protects cancel field from concurrent access
	CrackedHashes      chan Result   // Channel for successfully cracked hashes
	StatusUpdates      chan Status   // Channel for periodic status updates
	StderrMessages     chan string   // Channel for error messages from hashcat
	StdoutLines        chan string   // Channel for stdout lines from hashcat
	DoneChan           chan error    // Channel signaling process completion
	SkipStatusUpdates  bool          // Flag to disable status update parsing
	RestoreFilePath    string        // Path to session restore file
	pStdout            io.ReadCloser // Stdout pipe from hashcat process
	pStderr            io.ReadCloser // Stderr pipe from hashcat process
}

// NewHashcatSession creates and initializes a new hashcat session.
// It configures the hashcat command with the provided parameters, creates necessary
// temporary files, and sets up channels for communication.
// Returns an error if binary lookup, file creation, or argument validation fails.
func NewHashcatSession(id string, params Params) (*Session, error) {
	binaryPath, err := cracker.FindHashcatBinary()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	outFile, err := createOutFile(agentstate.State.OutPath, id, filePermissions)
	if err != nil {
		cancel()

		return nil, fmt.Errorf("couldn't create output file: %w", err)
	}

	charsetFiles, err := createCharsetFiles(params.MaskCustomCharsets)
	if err != nil {
		cancel()
		_ = outFile.Close()

		return nil, err
	}

	args, err := params.toCmdArgs(id, params.HashFile, outFile.Name())
	if err != nil {
		cancel()
		_ = outFile.Close()
		for _, f := range charsetFiles {
			if f != nil {
				_ = f.Close()
			}
		}

		return nil, err
	}

	// Use restore arguments if restore file exists
	if strings.TrimSpace(params.RestoreFilePath) != "" {
		if _, err := os.Stat(params.RestoreFilePath); err == nil {
			args = params.toRestoreArgs(id)
		}
	}

	return &Session{
		proc: exec.CommandContext( //nolint:gosec // G702 - binary path from internal config, not user input
			ctx,
			binaryPath,
			args...),
		cancel:             cancel,
		hashFile:           params.HashFile,
		outFile:            outFile,
		charsetFiles:       charsetFiles,
		shardedCharsetFile: nil,
		CrackedHashes:      make(chan Result, channelBufferSize),
		StatusUpdates:      make(chan Status, channelBufferSize),
		StderrMessages:     make(chan string, channelBufferSize),
		StdoutLines:        make(chan string, channelBufferSize),
		DoneChan:           make(chan error),
		SkipStatusUpdates:  params.AttackMode == AttackBenchmark,
		RestoreFilePath:    params.RestoreFilePath,
	}, nil
}

// Start initializes and starts the hashcat session.
// It attaches necessary I/O pipes, launches the hashcat process, and starts
// goroutines to handle output streams. Returns an error if process startup fails.
func (sess *Session) Start() error {
	if err := sess.attachPipes(); err != nil {
		return err
	}

	agentstate.Logger.Debug("Running hashcat command", "command", sess.proc.String())

	if err := sess.proc.Start(); err != nil {
		return fmt.Errorf("couldn't start hashcat: %w", err)
	}

	tailer, err := sess.startTailer()
	if err != nil {
		return err
	}

	go sess.handleTailerOutput(tailer)
	go sess.handleStdout()
	go sess.handleStderr()

	return nil
}

// attachPipes attaches stdout and stderr pipes to the hashcat process.
// Returns an error if pipe attachment fails.
func (sess *Session) attachPipes() error {
	pStdout, err := sess.proc.StdoutPipe()
	if err != nil {
		return fmt.Errorf("couldn't attach stdout to hashcat: %w", err)
	}

	sess.pStdout = pStdout

	pStderr, err := sess.proc.StderrPipe()
	if err != nil {
		return fmt.Errorf("couldn't attach stderr to hashcat: %w", err)
	}

	sess.pStderr = pStderr

	return nil
}

// startTailer initiates a file tailer to monitor the hashcat output file.
// The tailer follows the output file and sends new lines for processing.
// If tailer creation fails, it attempts to kill the hashcat process before returning an error.
func (sess *Session) startTailer() (*tail.Tail, error) {
	tailer, err := tail.TailFile(
		sess.outFile.Name(),
		tail.Config{Follow: true, Logger: agentstate.Logger.StandardLog()},
	)
	if err != nil {
		if killErr := sess.Kill(); killErr != nil {
			agentstate.Logger.Error("couldn't kill hashcat process", "error", killErr)
		}

		return nil, fmt.Errorf("couldn't tail outfile %q: %w", sess.outFile.Name(), err)
	}

	return tailer, nil
}

// handleTailerOutput processes lines from the hashcat output file.
// It parses each line to extract timestamp, hash, and plaintext, then sends
// the result through the CrackedHashes channel. Invalid lines are logged and skipped.
func (sess *Session) handleTailerOutput(tailer *tail.Tail) {
	for tailLine := range tailer.Lines {
		line := tailLine.Text

		values := strings.Split(line, ":")
		if len(values) < logParseMinParts {
			agentstate.Logger.Error("unexpected line contents", "line", line)

			continue
		}

		timestamp, plainHex := values[0], values[len(values)-1]

		bs, err := hex.DecodeString(plainHex)
		if err != nil {
			agentstate.Logger.Error("couldn't decode hex string", "hex", plainHex, "error", err)

			continue
		}

		plain := string(bs)
		hashParts := values[1 : len(values)-1]
		hash := strings.Join(hashParts, ":")

		timestampI, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			agentstate.Logger.Error("couldn't parse hashcat timestamp", "timestamp", timestamp, "error", err)

			continue
		}

		sess.CrackedHashes <- Result{
			Timestamp: time.Unix(timestampI, 0),
			Hash:      hash,
			Plaintext: plain,
		}
	}
}

// handleStdout processes stdout from the hashcat process.
// It sends all lines to the StdoutLines channel, parses JSON status updates
// (unless SkipStatusUpdates is true), and handles special messages like restore mode.
// This method blocks until the process completes and sends the exit status to DoneChan.
func (sess *Session) handleStdout() {
	scanner := bufio.NewScanner(sess.pStdout)
	for scanner.Scan() {
		line := scanner.Text()
		sess.StdoutLines <- line

		if line == "" {
			continue
		}

		if !sess.SkipStatusUpdates {
			lineBytes := []byte(line)
			if json.Valid(lineBytes) {
				var status Status
				if err := json.Unmarshal(lineBytes, &status); err != nil {
					agentstate.Logger.Error("couldn't unmarshal hashcat status", "error", err)

					continue
				}

				sess.StatusUpdates <- status
			} else {
				if strings.Contains(line, "starting in restore mode") {
					agentstate.Logger.Info("Hashcat is starting in restore mode")
				} else {
					agentstate.Logger.Error("unexpected stdout line", "line", line)
				}
			}
		}
	}

	done := sess.proc.Wait()

	// Allow brief time for channel consumers to drain remaining stdout/stderr
	// messages before signaling completion via DoneChan.
	time.Sleep(time.Second)

	sess.DoneChan <- done
}

// handleStderr processes stderr output from the hashcat process.
// Each line is logged and sent through the StderrMessages channel.
func (sess *Session) handleStderr() {
	scanner := bufio.NewScanner(sess.pStderr)
	for scanner.Scan() {
		agentstate.Logger.Error("read stderr", "text", scanner.Text())

		sess.StderrMessages <- scanner.Text()
	}
}

// Cancel requests cancellation of the running hashcat process via the session context.
// This method is thread-safe and may be called concurrently from multiple goroutines.
func (sess *Session) Cancel() {
	sess.cancelMu.Lock()
	defer sess.cancelMu.Unlock()

	if sess.cancel != nil {
		sess.cancel()
		sess.cancel = nil
	}
}

// Kill terminates the hashcat process.
// Returns nil if no process is running or if the process was already terminated.
// The os.ErrProcessDone error is treated as a success case.
func (sess *Session) Kill() error {
	sess.Cancel()

	if sess.proc == nil || sess.proc.Process == nil {
		return nil
	}

	err := sess.proc.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}

	return err
}

// Cleanup cancels the session context and removes all session-related temporary
// files: output file, charset files, hash file, restore file, and optionally
// the zaps directory. It is idempotent — already-removed files are silently skipped.
// Errors during cleanup are logged but don't halt the cleanup process.
func (sess *Session) Cleanup() {
	sess.Cancel()

	agentstate.Logger.Info("Cleaning up session files")

	removeFile := func(filePath string) {
		//nolint:gosec // G703 - internal session paths
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			agentstate.Logger.Error("couldn't remove file", "file", filePath, "error", err)
		}
	}

	if sess.outFile != nil {
		removeFile(sess.outFile.Name())
		sess.outFile = nil
	}

	if !agentstate.State.RetainZapsOnCompletion {
		if err := os.RemoveAll(agentstate.State.ZapsPath); err != nil {
			agentstate.Logger.Error("couldn't remove zaps directory", "error", err)
		}
	}

	for _, f := range sess.charsetFiles {
		if f != nil {
			removeFile(f.Name())
		}
	}

	removeFile(sess.hashFile)
	sess.hashFile = ""

	if strings.TrimSpace(sess.RestoreFilePath) != "" {
		removeFile(sess.RestoreFilePath)
		sess.RestoreFilePath = ""
	}
}

// CmdLine returns the command line string used to start the hashcat process.
func (sess *Session) CmdLine() string {
	return sess.proc.String()
}

// createOutFile creates the output file for cracked hashes.
// The file is created with restrictive permissions in the specified directory.
// Returns the created file handle or an error if creation or permission setting fails.
func createOutFile(dir, id string, perm os.FileMode) (*os.File, error) {
	outFilePath := filepath.Join(dir, id+".hcout")

	file, err := os.Create(
		outFilePath,
	)
	if err != nil {
		return nil, fmt.Errorf("creating output file %s: %w", outFilePath, err)
	}

	if err := file.Chmod(perm); err != nil {
		_ = file.Close()

		_ = os.Remove(outFilePath)
		return nil, fmt.Errorf("setting output file permissions: %w", err)
	}

	return file, nil
}

// createTempFile creates a temporary file with the specified pattern and permissions.
// Returns the file handle or an error if creation or permission setting fails.
func createTempFile(dir, pattern string, perm os.FileMode) (*os.File, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}

	if err := file.Chmod(perm); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name()) //nolint:gosec // G703 - cleaning up temp file we just created
		return nil, fmt.Errorf("setting temp file permissions: %w", err)
	}

	return file, nil
}

// createCharsetFiles creates temporary files for custom charsets used in mask attacks.
// Each charset string is written to a separate temporary file.
// Empty charset strings are skipped. Returns file handles or an error if creation fails.
// NOTE: Intentionally mutates charsets[i] in-place, replacing charset strings with
// the temp file paths so that toCmdArgs can reference them in --custom-charset flags.
func createCharsetFiles(charsets []string) ([]*os.File, error) {
	charsetFiles := make([]*os.File, 0, len(charsets))

	closeAll := func() {
		for _, f := range charsetFiles {
			_ = f.Close()
			_ = os.Remove(f.Name()) //nolint:gosec // G703 - cleaning up temp files we created
		}
	}

	for i, charset := range charsets {
		if strings.TrimSpace(charset) == "" {
			continue
		}

		charsetFile, err := createTempFile(agentstate.State.OutPath, "charset*", filePermissions)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("couldn't create charset file: %w", err)
		}

		if _, err := charsetFile.WriteString(charset); err != nil {
			_ = charsetFile.Close()
			_ = os.Remove(charsetFile.Name()) //nolint:gosec // G703 - cleaning up temp file we just created
			closeAll()
			return nil, fmt.Errorf("writing charset file: %w", err)
		}

		charsets[i] = charsetFile.Name()
		charsetFiles = append(charsetFiles, charsetFile)
	}

	return charsetFiles, nil
}
