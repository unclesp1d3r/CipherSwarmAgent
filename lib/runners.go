package lib

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// runAttackTask starts the attack session and handles real-time outputs and status updates.
// It processes stdout, stderr, status updates, cracked hashes, and handles session completion.
// A configurable timeout (task_timeout) prevents indefinite blocking if hashcat hangs.
func runAttackTask(sess *hashcat.Session, task *components.Task) {
	err := sess.Start()
	if err != nil {
		agentstate.Logger.Error("Failed to start attack session", "error", err)
		SendAgentError(err.Error(), task, operations.SeverityFatal)

		return
	}

	// Create timeout channel with configurable duration
	taskTimeout := viper.GetDuration("task_timeout")
	timeoutChan := time.After(taskTimeout)

	waitChan := make(chan int)

	go func() {
		defer close(waitChan)

		for {
			select {
			case <-timeoutChan:
				agentstate.Logger.Warn("Task timeout reached, killing session", "timeout", taskTimeout)

				if err := sess.Kill(); err != nil {
					agentstate.Logger.Error("Failed to kill session on timeout", "error", err)
				}

				SendAgentError("Task timed out", task, operations.SeverityWarning)

				return
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
			agentstate.Logger.Error("Failed to parse status update", "error", err)
		} else {
			displayJobStatus(update)
			sendStatusUpdate(update, task, sess)
		}
	}
}

// handleStdErrLine handles a single line of standard error output by classifying it
// and sending it to the server with the appropriate severity level.
func handleStdErrLine(stdErrLine string, task *components.Task) {
	displayJobError(stdErrLine)

	if strings.TrimSpace(stdErrLine) != "" {
		// Classify the stderr line to determine appropriate severity
		errorInfo := hashcat.ClassifyStderr(stdErrLine)
		SendClassifiedError(stdErrLine, task, errorInfo.Severity, errorInfo.Category.String(), errorInfo.Retryable)
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

// handleDoneChan handles the completion of a task, classifying the exit code
// and taking appropriate action based on the error category.
func handleDoneChan(err error, task *components.Task, sess *hashcat.Session) {
	if err != nil {
		exitCode := parseExitCode(err.Error())
		exitInfo := hashcat.ClassifyExitCode(exitCode)

		switch {
		case hashcat.IsExhausted(exitCode):
			displayJobExhausted()
			markTaskExhausted(task)
		case hashcat.IsSuccess(exitCode):
			// Success case - hash was cracked, nothing special to do
			agentstate.Logger.Info("Task completed successfully")
		default:
			handleNonExhaustedError(err, task, sess, exitInfo)
		}
	}

	sess.Cleanup()
}

// parseExitCode extracts the exit code from an error message like "exit status N".
func parseExitCode(errMsg string) int {
	var exitCode int

	// Try to parse "exit status N" format
	if _, err := fmt.Sscanf(errMsg, "exit status %d", &exitCode); err == nil {
		return exitCode
	}

	// Default to -1 (general error) if we can't parse
	return -1
}

// handleNonExhaustedError handles errors which are not related to exhaustion
// by performing specific actions based on the error category and message.
func handleNonExhaustedError(err error, task *components.Task, sess *hashcat.Session, exitInfo hashcat.ExitCodeInfo) {
	// Handle restore file issues specially
	if strings.Contains(err.Error(), "Cannot read "+sess.RestoreFilePath) {
		if strings.TrimSpace(sess.RestoreFilePath) != "" {
			agentstate.Logger.Info("Removing restore file", "file", sess.RestoreFilePath)

			if removeErr := os.Remove(sess.RestoreFilePath); removeErr != nil {
				agentstate.Logger.Error("Failed to remove restore file", "error", removeErr)
			}
		}

		return
	}

	// Send error with classified severity and metadata
	SendClassifiedError(
		err.Error(),
		task,
		exitInfo.Severity,
		exitInfo.Category.String(),
		exitInfo.Retryable,
	)
	displayJobFailed(err)
}
