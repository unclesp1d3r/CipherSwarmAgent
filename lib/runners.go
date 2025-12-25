package lib

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/state"
)

// runAttackTask starts the attack session and handles real-time outputs and status updates.
// It processes stdout, stderr, status updates, cracked hashes, and handles session completion.
func runAttackTask(sess *hashcat.Session, task *components.Task) {
	err := sess.Start()
	if err != nil {
		state.Logger.Error("Failed to start attack session", "error", err)
		SendAgentError(err.Error(), task, operations.SeverityFatal)

		return
	}

	waitChan := make(chan int)

	go func() {
		defer close(waitChan)

		for {
			select {
			case stdoutLine := <-sess.StdoutLines:
				handleStdOutLine(stdoutLine, task, sess)
			case stdErrLine := <-sess.StderrMessages:
				handleStdErrLine(stdErrLine, task)
			case statusUpdate := <-sess.StatusUpdates:
				handleStatusUpdate(statusUpdate, task, sess)
			case crackedHash := <-sess.CrackedHashes:
				handleCrackedHash(crackedHash, task)
			case err := <-sess.DoneChan:
				handleDoneChan(err, task, sess)

				return
			}
		}
	}()

	<-waitChan
}

// handleStdOutLine handles a line of standard output, parses it if it's JSON, and updates the task and session status.
func handleStdOutLine(stdoutLine string, task *components.Task, sess *hashcat.Session) {
	if json.Valid([]byte(stdoutLine)) {
		update := hashcat.Status{}

		err := json.Unmarshal([]byte(stdoutLine), &update)
		if err != nil {
			state.Logger.Error("Failed to parse status update", "error", err)
		} else {
			displayJobStatus(update)
			sendStatusUpdate(update, task, sess)
		}
	}
}

// handleStdErrLine handles a single line of standard error output by displaying and sending the error to the server.
func handleStdErrLine(stdErrLine string, task *components.Task) {
	displayJobError(stdErrLine)

	if strings.TrimSpace(stdErrLine) != "" {
		SendAgentError(stdErrLine, task, operations.SeverityMinor)
	}
}

// handleStatusUpdate processes a status update for a hashcat task and session.
// It does this by displaying the job status and sending the status update.
func handleStatusUpdate(statusUpdate hashcat.Status, task *components.Task, sess *hashcat.Session) {
	displayJobStatus(statusUpdate)
	sendStatusUpdate(statusUpdate, task, sess)
}

// handleCrackedHash processes a cracked hash by displaying it and then sending it to a task server.
func handleCrackedHash(crackedHash hashcat.Result, task *components.Task) {
	displayJobCrackedHash(crackedHash)
	sendCrackedHash(crackedHash.Timestamp, crackedHash.Hash, crackedHash.Plaintext, task)
}

// handleDoneChan handles the completion of a task, marking it exhausted on specific error, handling other errors, and cleaning up the session.
func handleDoneChan(err error, task *components.Task, sess *hashcat.Session) {
	if err != nil {
		if err.Error() == "exit status 1" {
			displayJobExhausted()
			markTaskExhausted(task)
		} else {
			handleNonExhaustedError(err, task, sess)
		}
	}

	sess.Cleanup()
}

// handleNonExhaustedError handles errors which are not related to exhaustion by performing specific actions based on the error message.
func handleNonExhaustedError(err error, task *components.Task, sess *hashcat.Session) {
	if strings.Contains(err.Error(), "Cannot read "+sess.RestoreFilePath) {
		if strings.TrimSpace(sess.RestoreFilePath) != "" {
			state.Logger.Info("Removing restore file", "file", sess.RestoreFilePath)

			err := os.Remove(sess.RestoreFilePath)
			if err != nil {
				state.Logger.Error("Failed to remove restore file", "error", err)
			}
		}
	} else {
		SendAgentError(err.Error(), task, operations.SeverityCritical)
		displayJobFailed(err)
	}
}
