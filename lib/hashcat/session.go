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
	"time"

	"github.com/nxadm/tail"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

const (
	// Channel buffer sizes.
	channelBufferSize = 5
	// File permissions.
	filePermissions = 0o600
	// Log parsing constants.
	logParseMinParts = 3
)

// Session represents a hashcat session that manages the execution, I/O, and communication
// with the hashcat process.
type Session struct {
	proc               *exec.Cmd     // The hashcat process
	hashFile           string        // The path of the file containing the hashes to crack
	outFile            *os.File      // The file to write cracked hashes to
	charsetFiles       []*os.File    // Charset files for mask attacks
	shardedCharsetFile *os.File      // Sharded charset file for mask attacks
	CrackedHashes      chan Result   // Channel to send cracked hashes to
	StatusUpdates      chan Status   // Channel to send status updates to
	StderrMessages     chan string   // Channel to send stderr messages to
	StdoutLines        chan string   // Channel to send stdout lines to
	DoneChan           chan error    // Channel to send the done signal to
	SkipStatusUpdates  bool          // Whether to skip sending status updates
	RestoreFilePath    string        // Path to the restore file
	pStdout            io.ReadCloser // Pipe for stdout
	pStderr            io.ReadCloser // Pipe for stderr
}

// NewHashcatSession creates a new Hashcat session with given id and parameters,
// initializes the necessary files, arguments, and channels, and returns the session.
func NewHashcatSession(ctx context.Context, id string, params Params) (*Session, error) {
	binaryPath, err := cracker.FindHashcatBinary()
	if err != nil {
		return nil, err
	}

	outFile, err := createOutFile(shared.State.OutPath, id, filePermissions)
	if err != nil {
		return nil, fmt.Errorf("couldn't create output file: %w", err)
	}

	charsetFiles, err := createCharsetFiles(params.MaskCustomCharsets)
	if err != nil {
		return nil, err
	}

	args, err := params.toCmdArgs(id, params.HashFile, outFile.Name())
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(params.RestoreFilePath) != "" && func() bool {
		_, err := os.Stat(params.RestoreFilePath)
		return err == nil
	}() {
		args = params.toRestoreArgs(id)
	}

	return &Session{
		proc: exec.CommandContext(ctx,
			binaryPath,
			args...),
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

// Start initializes the session by attaching the necessary pipes and starting the hashcat process.
// It also starts the tailer and handles the output from stdout and stderr concurrently.
func (sess *Session) Start() error {
	if err := sess.attachPipes(); err != nil {
		return err
	}

	shared.Logger.Debug("Running hashcat command", "command", sess.proc.String())

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

// attachPipes attaches stdout and stderr pipes to the session's process.
// It returns an error if either the stdout or stderr pipe cannot be attached.
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

// startTailer initiates a tail.Tail instance to follow the session output file.
// In case of an error, it attempts to kill the session's process.
// Returns the tail.Tail instance and an error if any occurred during the setup.
func (sess *Session) startTailer() (*tail.Tail, error) {
	tailer, err := tail.TailFile(sess.outFile.Name(), tail.Config{Follow: true, Logger: shared.Logger.StandardLog()})
	if err != nil {
		if killErr := sess.Kill(); killErr != nil {
			shared.Logger.Error("couldn't kill hashcat process", "error", killErr)
		}

		return nil, fmt.Errorf("couldn't tail outfile %q: %w", sess.outFile.Name(), err)
	}

	return tailer, nil
}

// handleTailerOutput processes the lines read from a tail.Tail instance that monitors a log file,
// extracts the relevant information, and sends it to the CrackedHashes channel for further processing.
func (sess *Session) handleTailerOutput(tailer *tail.Tail) {
	for tailLine := range tailer.Lines {
		line := tailLine.Text

		values := strings.Split(line, ":")
		if len(values) < logParseMinParts {
			shared.Logger.Error("unexpected line contents", "line", line)

			continue
		}

		timestamp, plainHex := values[0], values[len(values)-1]

		bs, err := hex.DecodeString(plainHex)
		if err != nil {
			shared.Logger.Error("couldn't decode hex string", "hex", plainHex, "error", err)

			continue
		}

		plain := string(bs)
		hashParts := values[1 : len(values)-1]
		hash := strings.Join(hashParts, ":")

		timestampI, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			shared.Logger.Error("couldn't parse hashcat timestamp.", "timestamp", timestamp, "error", err)

			continue
		}

		sess.CrackedHashes <- Result{
			Timestamp: time.Unix(timestampI, 0),
			Hash:      hash,
			Plaintext: plain,
		}
	}
}

// handleStdout processes the standard output of the hashcat process, sending lines to StdoutLines channel.
// If JSON is detected and SkipStatusUpdates is false, unmarshal it into a Status struct and sends to StatusUpdates.
// Handles specific stdout messages like "starting in restore mode" and logs errors if unexpected lines appear.
func (sess *Session) handleStdout() {
	scanner := bufio.NewScanner(sess.pStdout)
	for scanner.Scan() {
		line := scanner.Text()
		sess.StdoutLines <- line

		if line == "" {
			continue
		}

		if !sess.SkipStatusUpdates {
			if json.Valid([]byte(line)) {
				var status Status
				if err := json.Unmarshal([]byte(line), &status); err != nil {
					shared.Logger.Error("WARN: couldn't unmarshal hashcat status", "error", err)

					continue
				}

				sess.StatusUpdates <- status
			} else {
				if strings.Contains(line, "starting in restore mode") {
					shared.Logger.Info("Hashcat is starting in restore mode")
				} else {
					shared.Logger.Error("Unexpected stdout line", "line", line)
				}
			}
		}
	}

	done := sess.proc.Wait()

	time.Sleep(time.Second)

	sess.DoneChan <- done
}

// handleStderr processes the standard error output of the hashcat process and sends each line to StderrMessages channel.
func (sess *Session) handleStderr() {
	scanner := bufio.NewScanner(sess.pStderr)
	for scanner.Scan() {
		shared.Logger.Error("read stderr", "text", scanner.Text())

		sess.StderrMessages <- scanner.Text()
	}
}

// Kill terminates the hashcat process associated with the session if it is running.
// Returns nil if no process is running or if the process was already terminated successfully.
func (sess *Session) Kill() error {
	if sess.proc == nil || sess.proc.Process == nil {
		return nil
	}

	err := sess.proc.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}

	return err
}

// Cleanup removes session-related temporary files and directories. It first attempts to remove output and charset files.
// If zaps should not be retained, it deletes the zaps' directory. Finally, it clears the hashFile property.
func (sess *Session) Cleanup() {
	shared.Logger.Info("Cleaning up session files")

	removeFile := func(filePath string) {
		if _, err := os.Stat(filePath); err == nil {
			if err := os.Remove(filePath); err != nil {
				shared.Logger.Error("couldn't remove file", "file", filePath, "error", err)
			}
		}
	}

	if sess.outFile != nil {
		removeFile(sess.outFile.Name())
		sess.outFile = nil
	}

	if !shared.State.RetainZapsOnCompletion {
		if err := os.RemoveAll(shared.State.ZapsPath); err != nil {
			shared.Logger.Error("couldn't remove zaps directory", "error", err)
		}
	}

	for _, f := range sess.charsetFiles {
		if f != nil {
			removeFile(f.Name())
		}
	}

	removeFile(sess.hashFile)
	sess.hashFile = ""
}

// CmdLine returns the command line string used to start the hashcat process.
func (sess *Session) CmdLine() string {
	return sess.proc.String()
}

// createOutFile creates a new file with the specified directory, id, and permissions.
// It returns the created file or an error if the creation or permission setting fails.
func createOutFile(dir, id string, perm os.FileMode) (*os.File, error) {
	outFilePath := filepath.Join(dir, id+".hcout")

	file, err := os.Create(
		outFilePath,
	)
	if err != nil {
		return nil, err
	}

	if err := file.Chmod(perm); err != nil {
		_ = file.Close()
		return nil, err
	}

	return file, nil
}

// createTempFile creates a temporary file in the specified directory with the given pattern and permissions.
//
// Parameters:
//   - dir: The directory where the temporary file will be created.
//   - pattern: The pattern to use when naming the temporary file.
//   - perm: The file permissions to set for the temporary file.
//
// Returns:
//   - *os.File: A pointer to the created temporary file.
//   - error: An error object if file creation or permission setting fails.
func createTempFile(dir, pattern string, perm os.FileMode) (*os.File, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}

	if err := file.Chmod(perm); err != nil {
		return nil, err
	}

	return file, nil
}

// createCharsetFiles creates temporary files for provided charsets, writes each charset to a file, and returns the file pointers.
// Each charset is checked if it is non-blank before creating and writing to a temporary file.
// If an error occurs during file creation or writing, the function returns an error.
func createCharsetFiles(charsets []string) ([]*os.File, error) {
	charsetFiles := make([]*os.File, 0, len(charsets))

	for i, charset := range charsets {
		if strings.TrimSpace(charset) == "" {
			continue
		}

		charsetFile, err := createTempFile(shared.State.OutPath, "charset*", filePermissions)
		if err != nil {
			return nil, fmt.Errorf("couldn't create charset file: %w", err)
		}

		if _, err := charsetFile.WriteString(charset); err != nil {
			return nil, err
		}

		charsets[i] = charsetFile.Name()
		charsetFiles = append(charsetFiles, charsetFile)
	}

	return charsetFiles, nil
}
