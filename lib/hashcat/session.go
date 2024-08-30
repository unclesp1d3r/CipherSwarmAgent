package hashcat

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/duke-git/lancet/strutil"
	"github.com/spf13/viper"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/shared"

	"github.com/duke-git/lancet/convertor"
	"github.com/duke-git/lancet/fileutil"
	"github.com/duke-git/lancet/validator"
	"github.com/nxadm/tail"
)

// Session represents a running Hashcat session.
// It contains the hashcat process, the path of the file containing the hashes to crack,
// the file to write cracked hashes to, charset files for mask attacks, a channel to send cracked hashes to,
type Session struct {
	proc               *exec.Cmd   // The hashcat process
	hashFile           string      // The path of the file containing the hashes to crack
	outFile            *os.File    // The file to write cracked hashes to
	charsetFiles       []*os.File  // Charset files for mask attacks
	shardedCharsetFile *os.File    // Sharded charset file for mask attacks
	CrackedHashes      chan Result // Channel to send cracked hashes to
	StatusUpdates      chan Status // Channel to send status updates to
	StderrMessages     chan string // Channel to send stderr messages to
	StdoutLines        chan string // Channel to send stdout lines to
	DoneChan           chan error  // Channel to send the done signal to
	SkipStatusUpdates  bool        // Whether to skip sending status updates
	RestoreFilePath    string      // Path to the restore file
}

// Start starts the hashcat session by attaching the stdout and stderr pipes,
// starting the hashcat process, and setting up goroutines to handle the output.
// It returns an error if any of the steps fail.
func (sess *Session) Start() error {
	pStdout, err := sess.proc.StdoutPipe()
	if err != nil {
		return fmt.Errorf("couldn't attach stdout to hashcat: %w", err)
	}

	pStderr, err := sess.proc.StderrPipe()
	if err != nil {
		return fmt.Errorf("couldn't attach stderr to hashcat: %w", err)
	}

	shared.Logger.Debug("Running hashcat command", "command", sess.proc.String())
	err = sess.proc.Start()
	if err != nil {
		return fmt.Errorf("couldn't start hashcat: %w", err)
	}

	tailer, err := tail.TailFile(sess.outFile.Name(), tail.Config{Follow: true, Logger: shared.Logger.StandardLog()})
	if err != nil {
		// Kill the hashcat process if we can't tail the outfile
		err = sess.Kill()
		if err != nil {
			shared.Logger.Error("couldn't kill hashcat process", "error", err)
		}

		return fmt.Errorf("couldn't tail outfile %q: %w", sess.outFile.Name(), err)
	}

	// Read the tailer output in a separate goroutine
	go func() {
		for tailLine := range tailer.Lines {
			line := tailLine.Text
			values := strings.Split(line, ":")
			if len(values) < 3 {
				shared.Logger.Error("unexpected line contents", "line", line)
				continue
			}

			// First
			timestamp := values[0]
			// Last
			plainHex := values[len(values)-1]

			bs, err := hex.DecodeString(plainHex)
			if err != nil {
				shared.Logger.Error("couldn't decode hex string", "hex", plainHex, "error", err)
				continue
			}
			plain := string(bs)

			// Everything in the middle
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
	}()

	// Read the stdout and stderr pipes in separate goroutines
	go func() {
		scanner := bufio.NewScanner(pStdout)
		for scanner.Scan() {
			line := scanner.Text()
			sess.StdoutLines <- line

			if len(line) == 0 {
				continue
			}
			if !sess.SkipStatusUpdates {
				if validator.IsJSON(line) {
					var status Status
					err := json.Unmarshal([]byte(line), &status)
					if err != nil {
						shared.Logger.Error("WARN: couldn't unmarshal hashcat status", "error", err)
						continue
					}
					sess.StatusUpdates <- status
				} else {
					if strings.Contains(line, "starting in restore mode") {
						// This is a special case where hashcat is starting in restore mode
						shared.Logger.Info("Hashcat is starting in restore mode")
					} else {
						// This is an unexpected line in stdout
						shared.Logger.Error("Unexpected stdout line", "line", line)
					}
				}
			}
		}

		done := sess.proc.Wait()
		time.Sleep(time.Second)
		sess.DoneChan <- done

		tailer.Kill(nil)
	}()

	go func() {
		scanner := bufio.NewScanner(pStderr)
		for scanner.Scan() {
			shared.Logger.Error("read stderr", "text", scanner.Text())
			sess.StderrMessages <- scanner.Text()
		}
	}()

	return nil
}

// Kill terminates the running process associated with the session.
// If the session process is already terminated or not started, it returns nil.
// If an error occurs while terminating the process, it returns the error.
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

// Cleanup removes any temporary files associated with the session.
// It deletes the hash file, output file, charset files, and sharded charset file (if present).
// It does not remove the restore file.
func (sess *Session) Cleanup() {
	shared.Logger.Info("Cleaning up session files")

	if sess.outFile != nil {
		if fileutil.IsExist(sess.outFile.Name()) {
			err := fileutil.RemoveFile(sess.outFile.Name())
			if err != nil {
				shared.Logger.Error("couldn't remove outfile", "file", sess.outFile.Name(), "error", err)
			}
		}
		sess.outFile = nil
	}

	if !shared.State.RetainZapsOnCompletion {
		// Probably shouldn't remove the directory too, but it's fine for now
		err := os.RemoveAll(shared.State.ZapsPath)
		if err != nil {
			shared.Logger.Error("couldn't remove zaps directory", "error", err)
		}
	}

	for _, f := range sess.charsetFiles {
		if f != nil {
			if fileutil.IsExist(f.Name()) {
				err := fileutil.RemoveFile(f.Name())
				if err != nil {
					shared.Logger.Error("couldn't remove charset file", "file", f.Name(), "error", err)
				}
			}
		}
	}

	if fileutil.IsExist(sess.hashFile) {
		err := fileutil.RemoveFile(sess.hashFile)
		if err != nil {
			shared.Logger.Error("couldn't remove hash file", "file", sess.hashFile, "error", err)
		}
	}
	sess.hashFile = ""
}

// CmdLine returns the command line string used to start the session.
func (sess *Session) CmdLine() string {
	return sess.proc.String()
}

// NewHashcatSession creates a new Hashcat session with the specified ID and parameters.
// It returns a pointer to the created Session and an error, if any.
// The Session represents a running Hashcat session and provides channels for receiving cracked hashes,
// status updates, stderr messages, and stdout lines.
// The function takes an ID string and a Params struct as input.
// The ID is used to identify the session, and the Params struct contains the parameters for the Hashcat session.
// The function creates temporary files for storing the output and custom charsets, and sets the necessary permissions.
// It then constructs the command arguments based on the provided parameters and returns the initialized Session.
// If any error occurs during the creation of the session, an error is returned.
func NewHashcatSession(id string, params Params) (*Session, error) {
	var (
		outFile            *os.File
		shardedCharsetFile *os.File
		charsetFiles       []*os.File
	)

	binaryPath := viper.GetString("hashcat_path")
	outFile, err := os.CreateTemp(shared.State.OutPath, id)
	if err != nil {
		return nil, fmt.Errorf("couldn't make a temp file to store output: %w", err)
	}
	err = outFile.Chmod(0o600)
	if err != nil {
		return nil, fmt.Errorf("couldn't set permissions on output file: %w", err)
	}

	charsetFiles = []*os.File{}
	for i, charset := range params.MaskCustomCharsets {
		if !strutil.IsBlank(charset) {
			charsetFile, err := os.CreateTemp(shared.State.OutPath, "charset*")
			if err != nil {
				return nil, fmt.Errorf("couldn't make a temp file to store charset")
			}
			_, err = charsetFile.Write([]byte(charset))
			if err != nil {
				return nil, err
			}

			params.MaskCustomCharsets[i] = charsetFile.Name()
			charsetFiles = append(charsetFiles, charsetFile)
		}
	}

	args, err := params.toCmdArgs(id, params.HashFile, outFile.Name())
	if err != nil {
		return nil, err
	}

	// Check for a restore file and generate the restore arguments if it exists
	// We'll override the command arguments if a restore file is found
	if !strutil.IsBlank(params.RestoreFilePath) {
		if fileutil.IsExist(params.RestoreFilePath) {
			args, err = params.toRestoreArgs(id)
			if err != nil {
				return nil, err
			}
		}
	}

	shared.ErrorLogger.Info("Hashcat command: ", "args", args)

	return &Session{
		proc:               exec.Command(binaryPath, args...),
		hashFile:           params.HashFile,
		outFile:            outFile,
		charsetFiles:       charsetFiles,
		shardedCharsetFile: shardedCharsetFile,
		CrackedHashes:      make(chan Result, 5),
		StatusUpdates:      make(chan Status, 5),
		StderrMessages:     make(chan string, 5),
		StdoutLines:        make(chan string, 5),
		DoneChan:           make(chan error),
		SkipStatusUpdates:  params.AttackMode == AttackBenchmark,
		RestoreFilePath:    params.RestoreFilePath,
	}, nil
}
