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
	"path/filepath"
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

// Session represents a cracking session for hashcat.
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

// Start initializes and runs the session process for hashcat.
// Actions performed:
// 1. Attaches necessary pipes for session communication.
// 2. Starts the hashcat process.
// 3. Initiates and starts a log tailer.
// 4. Handles the output from the tailer, standard output, and standard error in separate goroutines.
// Returns an error if any step fails.
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

// attachPipes attaches the stdout and stderr pipes of the session process to the session object.
// It returns an error if either pipe attachment fails.
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

// startTailer initializes and starts a tailer to monitor the session's output file.
// If an error occurs while starting the tailer, it attempts to kill the current session process.
// Returns the initialized tail.Tail instance or an error if the tailer couldn't be started.
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

// handleTailerOutput processes each line from the tailer.Lines channel, extracts and decodes relevant information,
// and sends the results to the CrackedHashes channel.
// Actions:
// - Reads lines from tailer.Lines.
// - Splits each line by ":" and validates the format.
// - Extracts and decodes the timestamp, hash, and plaintext from the line.
// - Converts timestamp to an integer and then to a time.Time value.
// - Sends the decoded result to the CrackedHashes channel.
//
// Parameters:
// - tailer: A pointer to a tail.Tail instance that provides the lines to be processed.
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

// handleStdout processes stdout lines from a session, sending them to StdoutLines channel and handling status updates.
// If SkipStatusUpdates is false, it checks if the line is JSON and unmarshals it into Status, then sends to StatusUpdates.
// Logs unexpected lines and specific messages such as "starting in restore mode".
// Waits for the process to finish and sends the result to DoneChan.
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

// handleStderr reads from sess.pStderr, logs the text, and sends stderr messages to sess.StderrMessages channel.
func (sess *Session) handleStderr() {
	scanner := bufio.NewScanner(sess.pStderr)
	for scanner.Scan() {
		shared.Logger.Error("read stderr", "text", scanner.Text())
		sess.StderrMessages <- scanner.Text()
	}
}

// Kill terminates the hashcat process associated with the current session.
//
// If the process is not running or has already finished, it returns nil.
// If the process is successfully terminated, it returns nil.
// Otherwise, it returns an error indicating the termination failure.
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

// Cleanup releases resources and deletes temporary files associated with the session.
//
// Actions performed:
// 1. Logs the start of the cleanup process.
// 2. Defines a helper function, removeFile, to delete a file if it exists.
// 3. Removes and nils sess.outFile if it is not nil.
// 4. Deletes the zaps directory if shared.State.RetainZapsOnCompletion is false.
// 5. Iterates through sess.charsetFiles and removes each file if it exists.
// 6. Removes sess.hashFile and sets it to an empty string.
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

// CmdLine returns the command line string representation of the hashcat process associated with the session.
func (sess *Session) CmdLine() string {
	return sess.proc.String()
}

// NewHashcatSession creates a new Hashcat session with the specified ID and parameters.
//
// Actions performed by this function:
// 1. Retrieves the Hashcat binary path from the configuration.
// 2. Creates an output file for storing the results of the cracking session.
// 3. Generates custom charset files based on the provided parameters.
// 4. Constructs the command-line arguments to run Hashcat.
// 5. Handles session restoration if a restore file path is specified.
// 6. Initializes and returns a new Session struct configured to run the Hashcat process.
//
// Parameters:
//   - id: A string representing the unique identifier for the session.
//   - params: A Params struct containing various configuration options for the session.
//
// Returns:
//   - *Session: A pointer to the newly created Session object.
//   - error: An error object if any step in setting up the session fails.
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

// createCharsetFiles creates temporary files for each non-blank charset in the input slice and writes the charset to the file.
// It returns a slice of pointers to the created files and any error encountered.
//
// Parameters:
//   - charsets: A slice of strings where each string represents a charset.
//
// Returns:
//   - []*os.File: A slice of pointers to the created temporary files.
//   - error: An error object if file creation or writing fails.
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
