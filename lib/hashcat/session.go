package hashcat

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/duke-git/lancet/v2/validator"
	"github.com/nxadm/tail"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// Session represents a running Hashcat session.
// It contains the hashcat process, the path of the file containing the hashes to crack,
// the file to write cracked hashes to, charset files for mask attacks, a channel to send cracked hashes to,.
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

// Start initializes and starts the hashcat session. It attaches necessary pipes,
// starts the hashcat process, and begins handling the output from the process.
//
// Returns an error if any step in the initialization or starting process fails.
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

// attachPipes attaches the stdout and stderr pipes to the session's process.
// It initializes the session's pStdout and pStderr fields with the respective pipes.
// If there is an error attaching either pipe, it returns an error with a descriptive message.
//
// Returns:
//
//	error: If there is an issue attaching the stdout or stderr pipes, an error is returned.
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

// startTailer starts a tailer for the session's output file.
// It follows the file for new lines and logs them using the shared logger.
// If an error occurs while starting the tailer, it attempts to kill the session's process
// and returns the error.
//
// Returns:
//
//	*tail.Tail: A pointer to the tail.Tail instance if successful.
//	error: An error if the tailer could not be started or if killing the process fails.
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

// handleTailerOutput processes the output lines from a tail.Tail instance.
// It expects each line to be in the format "timestamp:hash:plaintext".
// If the line does not conform to this format, it logs an error and continues to the next line.
// It decodes the plaintext from hex, parses the timestamp, and sends a Result struct
// containing the timestamp, hash, and plaintext to the CrackedHashes channel.
//
// Parameters:
//
//	tailer (*tail.Tail): The tail.Tail instance providing the lines to process.
func (sess *Session) handleTailerOutput(tailer *tail.Tail) {
	for tailLine := range tailer.Lines {
		line := tailLine.Text
		values := strings.Split(line, ":")
		if len(values) < 3 {
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

		timestampI, err := convertor.ToInt(timestamp)
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

// handleStdout reads from the session's standard output and processes each line.
// It sends each line to the StdoutLines channel. If the line is a valid JSON
// representing a Status object, it unmarshals it and sends the Status to the
// StatusUpdates channel. It also logs specific messages based on the content
// of the line. Once the process is done, it waits for a second and then sends
// the process state to the DoneChan channel.
func (sess *Session) handleStdout() {
	scanner := bufio.NewScanner(sess.pStdout)
	for scanner.Scan() {
		line := scanner.Text()
		sess.StdoutLines <- line

		if len(line) == 0 {
			continue
		}
		if !sess.SkipStatusUpdates {
			if validator.IsJSON(line) {
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

// handleStderr reads from the standard error output of the session's process
// and logs each line as an error. It also sends each line to the StderrMessages
// channel for further processing or handling.
//
// This function continuously scans the stderr output until the scanner encounters
// an error or EOF. Each line read from stderr is logged using the shared.Logger
// and then sent to the StderrMessages channel.
func (sess *Session) handleStderr() {
	scanner := bufio.NewScanner(sess.pStderr)
	for scanner.Scan() {
		shared.Logger.Error("read stderr", "text", scanner.Text())
		sess.StderrMessages <- scanner.Text()
	}
}

// Kill terminates the process associated with the session.
// If the process is already nil or has completed, it returns nil.
// If an error occurs during termination, it returns the error.
// If the error indicates the process is already done, it returns nil.
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

// Cleanup removes session-related files and directories.
// It performs the following actions:
// 1. Logs the cleanup process initiation.
// 2. Checks if the output file exists and removes it if present.
// 3. Sets the output file reference to nil.
// 4. Removes the zaps directory if the retain flag is not set.
// 5. Iterates through charset files, checking for existence and removing them if present.
// 6. Checks if the hash file exists and removes it if present.
// 7. Resets the hash file reference to an empty string.
func (sess *Session) Cleanup() {
	shared.Logger.Info("Cleaning up session files")

	removeFile := func(filePath string) {
		if fileutil.IsExist(filePath) {
			if err := fileutil.RemoveFile(filePath); err != nil {
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

// CmdLine returns the command line string used to start the session.
func (sess *Session) CmdLine() string {
	return sess.proc.String()
}

// NewHashcatSession creates a new Hashcat session with the given ID and parameters.
// It initializes the necessary files and command arguments for running Hashcat.
//
// Parameters:
//   - id: A unique identifier for the session.
//   - params: A Params struct containing configuration for the Hashcat session.
//
// Returns:
//   - *Session: A pointer to the newly created Session struct.
//   - error: An error if the session could not be created.
//
// The function performs the following steps:
//  1. Retrieves the Hashcat binary path from the configuration.
//  2. Creates a temporary output file for the session.
//  3. Creates charset files based on the provided custom charsets.
//  4. Constructs the command arguments for running Hashcat.
//  5. Checks if a restore file path is provided and exists, and adjusts the arguments accordingly.
//  6. Initializes and returns a new Session struct with the prepared command and channels.
func NewHashcatSession(id string, params Params) (*Session, error) {
	binaryPath := viper.GetString("hashcat_path")

	outFile, err := createOutFile(shared.State.OutPath, id, 0o600)
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

	if !strutil.IsBlank(params.RestoreFilePath) && fileutil.IsExist(params.RestoreFilePath) {
		args = params.toRestoreArgs(id)
	}

	return &Session{
		proc:               exec.Command(binaryPath, args...),
		hashFile:           params.HashFile,
		outFile:            outFile,
		charsetFiles:       charsetFiles,
		shardedCharsetFile: nil,
		CrackedHashes:      make(chan Result, 5),
		StatusUpdates:      make(chan Status, 5),
		StderrMessages:     make(chan string, 5),
		StdoutLines:        make(chan string, 5),
		DoneChan:           make(chan error),
		SkipStatusUpdates:  params.AttackMode == AttackBenchmark,
		RestoreFilePath:    params.RestoreFilePath,
	}, nil
}

// createOutFile creates a new output file with the specified name and permissions in the given directory.
//
// Parameters:
//   - dir: The directory where the output file will be created.
//   - id: The identifier string that will be used as part of the output file name.
//   - perm: The file permission settings.
//
// Returns:
//   - *os.File: A pointer to the created file.
//   - error: An error object if the file creation or permission setting fails.
//
// Actions:
//  1. Joins the directory and id to form the output file path.
//  2. Creates the file at the specified path.
//  3. Sets the file's permissions.
//  4. Returns the file pointer and any error encountered.
func createOutFile(dir string, id string, perm os.FileMode) (*os.File, error) {
	outFilePath := filepath.Join(dir, id+".hcout")
	file, err := os.Create(outFilePath)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(perm); err != nil {
		_ = file.Close() // We need to close the file if the permissions change fails
		return nil, err
	}

	return file, nil
}

// createTempFile creates a temporary file with the specified directory, name pattern, and permissions.
// Params:
//
//	dir (string): Directory where the temporary file will be created.
//	pattern (string): File name pattern, where '*' will be replaced with a random string.
//	perm (os.FileMode): File permissions to set on the created file.
//
// Returns:
//
//	*os.File: A pointer to the created temporary file.
//	error: An error value if any issues occurred during file creation or permission setting.
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

func createCharsetFiles(charsets []string) ([]*os.File, error) {
	var charsetFiles []*os.File
	for i, charset := range charsets {
		if !strutil.IsBlank(charset) {
			charsetFile, err := createTempFile(shared.State.OutPath, "charset*", 0o600)
			if err != nil {
				return nil, fmt.Errorf("couldn't create charset file: %w", err)
			}
			if _, err := charsetFile.WriteString(charset); err != nil {
				return nil, err
			}
			charsets[i] = charsetFile.Name()
			charsetFiles = append(charsetFiles, charsetFile)
		}
	}

	return charsetFiles, nil
}
