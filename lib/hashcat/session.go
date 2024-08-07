package hashcat

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

type Session struct {
	proc               *exec.Cmd   // The hashcat process
	hashFile           *os.File    // The file containing the hashes to crack
	outFile            *os.File    // The file to write cracked hashes to
	charsetFiles       []*os.File  // Charset files for mask attacks
	shardedCharsetFile *os.File    // Sharded charset file for mask attacks
	CrackedHashes      chan Result // Channel to send cracked hashes to
	StatusUpdates      chan Status // Channel to send status updates to
	StderrMessages     chan string // Channel to send stderr messages to
	StdoutLines        chan string // Channel to send stdout lines to
	DoneChan           chan error  // Channel to send the done signal to
	SkipStatusUpdates  bool        // Whether to skip sending status updates
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
		err = sess.Kill()
		if err != nil {
			shared.Logger.Error("couldn't kill hashcat process", "error", err)
		}

		return fmt.Errorf("couldn't tail outfile %q: %w", sess.outFile.Name(), err)
	}

	// Read the tailer output in a separate goroutine
	go func() {
		for tLine := range tailer.Lines {
			line := tLine.Text
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
					shared.Logger.Error("Unexpected stdout line", "line", line)
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
func (sess *Session) Cleanup() {
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

	if sess.hashFile != nil {
		if fileutil.IsExist(sess.hashFile.Name()) {
			err := fileutil.RemoveFile(sess.hashFile.Name())
			if err != nil {
				shared.Logger.Error("couldn't remove hash file", "file", sess.hashFile.Name(), "error", err)
			}
		}
		sess.hashFile = nil
	}
}

// CmdLine returns the command line string used to start the session.
func (sess *Session) CmdLine() string {
	return sess.proc.String()
}
