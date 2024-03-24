package hashcat

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hpcloud/tail"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type HashcatSession struct {
	proc               *exec.Cmd
	hashFile           *os.File
	outFile            *os.File
	charsetFiles       []*os.File
	shardedCharsetFile *os.File
	CrackedHashes      chan HashcatResult
	StatusUpdates      chan HashcatStatus
	StderrMessages     chan string
	StdoutLines        chan string
	DoneChan           chan error
	SkipStatusUpdates  bool
}

func (sess *HashcatSession) Start() error {
	pStdout, err := sess.proc.StdoutPipe()
	if err != nil {
		return fmt.Errorf("couldn't attach stdout to hashcat: %w", err)
	}

	pStderr, err := sess.proc.StderrPipe()
	if err != nil {
		return fmt.Errorf("couldn't attach stderr to hashcat: %w", err)
	}

	fmt.Println("Running hashcat command", "command", sess.proc.String())
	err = sess.proc.Start()
	if err != nil {
		return fmt.Errorf("couldn't start hashcat: %w", err)
	}

	tailer, err := tail.TailFile(sess.outFile.Name(), tail.Config{Follow: true})
	if err != nil {
		sess.Kill()
		return fmt.Errorf("couldn't tail outfile %q: %w", sess.outFile.Name(), err)
	}

	go func() {
		for tLine := range tailer.Lines {
			line := tLine.Text
			values := strings.Split(line, ":")
			if len(values) < 3 {
				fmt.Println("unexpected line contents", "line", line)
				continue
			}

			// First
			timestamp := values[0]
			// Last
			plainHex := values[len(values)-1]

			bs, err := hex.DecodeString(plainHex)
			if err != nil {
				fmt.Println("couldn't decode hex string", "hex", plainHex, "error", err)
				continue
			}
			plain := string(bs)

			// Everything in the middle
			hashParts := values[1 : len(values)-1]
			hash := strings.Join(hashParts, ":")

			timestampI, err := strconv.ParseInt(timestamp, 10, 64)
			if err != nil {
				fmt.Println("couldn't parse hashcat timestamp.", "timestamp", timestamp, "error", err)
				continue
			}

			sess.CrackedHashes <- HashcatResult{
				Timestamp: time.Unix(timestampI, 0),
				Hash:      hash,
				Plaintext: plain,
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(pStdout)
		for scanner.Scan() {
			line := scanner.Text()
			sess.StdoutLines <- line

			if len(line) == 0 {
				continue
			}
			if !sess.SkipStatusUpdates {
				switch line[0] {
				case '{':
					var status HashcatStatus
					err := json.Unmarshal([]byte(line), &status)
					if err != nil {
						fmt.Println("WARN: couldn't unmarshal hashcat status", "error", err)
						continue
					}
					sess.StatusUpdates <- status

				default:
					fmt.Println("Unexpected stdout line", "line", line)
				}
			}
		}

		done := sess.proc.Wait()
		// Give us a hot moment to read any cracked hashes that are still being written to disk
		time.Sleep(time.Second)
		sess.DoneChan <- done

		tailer.Kill(nil)
	}()

	go func() {
		scanner := bufio.NewScanner(pStderr)
		for scanner.Scan() {
			fmt.Println("read stderr", "text", scanner.Text())
			sess.StderrMessages <- scanner.Text()
		}
	}()

	return nil
}

func (sess *HashcatSession) Kill() error {
	if sess.proc == nil || sess.proc.Process == nil {
		return nil
	}

	err := sess.proc.Process.Kill()

	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}

	return err
}

func (sess *HashcatSession) Cleanup() {
	if sess.hashFile != nil {
		os.Remove(sess.hashFile.Name())
		sess.hashFile = nil
	}

	if sess.outFile != nil {
		os.Remove(sess.outFile.Name())
		sess.outFile = nil
	}

	for _, f := range sess.charsetFiles {
		if f != nil {
			os.Remove(f.Name())
		}
	}

	if sess.shardedCharsetFile != nil {
		os.Remove(sess.shardedCharsetFile.Name())
	}
}

func (sess *HashcatSession) CmdLine() string {
	return sess.proc.String()
}
