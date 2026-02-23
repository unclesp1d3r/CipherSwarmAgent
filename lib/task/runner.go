package task

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// runAttackTask starts the attack session and handles real-time outputs and status updates.
// It processes stdout, stderr, status updates, cracked hashes, and handles session completion.
// A configurable timeout (task_timeout) prevents indefinite blocking if hashcat hangs.
func (m *Manager) runAttackTask(ctx context.Context, sess *hashcat.Session, task *api.Task) {
	err := sess.Start()
	if err != nil {
		agentstate.Logger.Error("Failed to start attack session", "error", err)
		cserrors.SendAgentError(ctx, err.Error(), task, api.SeverityFatal)
		sess.Cleanup()

		return
	}

	// Create timeout channel with configurable duration
	taskTimeout := agentstate.State.TaskTimeout
	timeoutChan := time.After(taskTimeout)

	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)

		for {
			select {
			case <-timeoutChan:
				agentstate.Logger.Warn("Task timeout reached, killing session", "timeout", taskTimeout)

				if err := sess.Kill(); err != nil {
					agentstate.Logger.Error("Failed to kill session on timeout", "error", err)
					// Report kill failure with higher severity - session may still be running
					cserrors.SendAgentError(
						ctx,
						"Task timed out; failed to kill session: "+err.Error(),
						task,
						api.SeverityFatal,
					)
					sess.Cleanup()

					return
				}

				cserrors.SendAgentError(ctx, "Task timed out", task, api.SeverityWarning)
				sess.Cleanup()

				return
			case stdoutLine := <-sess.StdoutLines:
				handleStdOutLine(ctx, stdoutLine, task)
			case stdErrLine := <-sess.StderrMessages:
				handleStdErrLine(ctx, stdErrLine, task)
			case statusUpdate := <-sess.StatusUpdates:
				m.handleStatusUpdate(ctx, statusUpdate, task, sess)
			case crackedHash := <-sess.CrackedHashes:
				m.handleCrackedHash(ctx, crackedHash, task)
			case err := <-sess.DoneChan:
				m.handleDoneChan(ctx, err, task, sess)

				return
			}
		}
	}()

	<-waitChan
}

// handleStdOutLine handles a line of standard output from hashcat.
// Valid JSON status lines are handled by the StatusUpdates channel (via handleStatusUpdate),
// so this function only reports JSON parse failures. Non-JSON lines are ignored here
// (they are already logged by session.handleStdout).
func handleStdOutLine(ctx context.Context, stdoutLine string, task *api.Task) {
	lineBytes := []byte(stdoutLine)
	if json.Valid(lineBytes) {
		var update hashcat.Status
		if err := json.Unmarshal(lineBytes, &update); err != nil {
			agentstate.Logger.Error("Failed to parse status update", "error", err)
			cserrors.SendAgentError(
				ctx,
				"Failed to parse hashcat status update: "+err.Error(),
				task,
				api.SeverityWarning,
				cserrors.WithClassification("parse_error", true), // Retryable - transient or version mismatch
			)
		}
		// Valid JSON status is processed via sess.StatusUpdates → handleStatusUpdate
	}
}

// handleStdErrLine handles a single line of standard error output by classifying it
// and sending it to the server with the appropriate severity level.
func handleStdErrLine(ctx context.Context, stdErrLine string, task *api.Task) {
	display.JobError(stdErrLine)

	if strings.TrimSpace(stdErrLine) != "" {
		// Classify the stderr line to determine appropriate severity
		errorInfo := hashcat.ClassifyStderr(stdErrLine)
		cserrors.SendAgentError(ctx, stdErrLine, task, errorInfo.Severity,
			cserrors.WithClassification(errorInfo.Category.String(), errorInfo.Retryable))
	}
}

// handleStatusUpdate validates and processes a status update for a hashcat task and session.
// It validates that Progress and RecoveredHashes have the minimum required fields before
// forwarding to display and send functions.
func (m *Manager) handleStatusUpdate(
	ctx context.Context,
	statusUpdate hashcat.Status,
	task *api.Task,
	sess *hashcat.Session,
) {
	if len(statusUpdate.Progress) < display.MinStatusFields {
		agentstate.Logger.Warn("Status update has incomplete progress data",
			"progress_len", len(statusUpdate.Progress))
		return
	}

	if len(statusUpdate.RecoveredHashes) < display.MinStatusFields {
		agentstate.Logger.Warn("Status update has incomplete recovered hashes data",
			"recovered_len", len(statusUpdate.RecoveredHashes))
		return
	}

	display.JobStatus(statusUpdate)
	m.sendStatusUpdate(ctx, statusUpdate, task, sess)
}

// handleCrackedHash processes a cracked hash by displaying it and then sending it to a task server.
func (m *Manager) handleCrackedHash(ctx context.Context, crackedHash hashcat.Result, task *api.Task) {
	display.JobCrackedHash(crackedHash)
	m.sendCrackedHash(ctx, crackedHash.Timestamp, crackedHash.Hash, crackedHash.Plaintext, task)
}

// handleDoneChan handles the completion of a task, classifying the exit code
// and taking appropriate action based on the error category.
// Note: When hashcat completes successfully with exit code 0, proc.Wait() returns nil,
// so the err != nil block only handles non-zero exit codes. Successful completion
// (nil error) proceeds directly to cleanup.
func (m *Manager) handleDoneChan(ctx context.Context, err error, task *api.Task, sess *hashcat.Session) {
	if err != nil {
		exitCode := parseExitCode(err.Error())
		exitInfo := hashcat.ClassifyExitCode(exitCode)

		switch {
		case hashcat.IsExhausted(exitCode):
			display.JobExhausted()
			m.markTaskExhausted(ctx, task)
		case hashcat.IsSuccess(exitCode):
			// Success case - hashcat process exited cleanly
			// Note: This branch is reached when exit code 0 is returned as an error,
			// which may happen in some edge cases.
			agentstate.Logger.Info("Hashcat process completed successfully")
		default:
			handleNonExhaustedError(ctx, err, task, sess, exitInfo)
		}
	}

	sess.Cleanup()
}

// parseExitCode extracts the exit code from an error message like "exit status N".
// Returns -1 (general error) for non-standard error formats, including:
// - Signal-based terminations (e.g., "signal: killed", "signal: terminated")
// - Any other error format that doesn't match "exit status N".
func parseExitCode(errMsg string) int {
	var exitCode int

	// Try to parse "exit status N" format
	if _, err := fmt.Sscanf(errMsg, "exit status %d", &exitCode); err == nil {
		return exitCode
	}

	// Default to -1 (general error) for non-standard formats
	// This includes signal-based terminations like "signal: killed"
	return -1
}

// handleNonExhaustedError handles errors which are not related to exhaustion
// by performing specific actions based on the error category and message.
func handleNonExhaustedError(
	ctx context.Context,
	err error,
	task *api.Task,
	sess *hashcat.Session,
	exitInfo hashcat.ExitCodeInfo,
) {
	// Handle restore file issues specially.
	// Check path is non-empty first to avoid matching unrelated "Cannot read " errors.
	if strings.TrimSpace(sess.RestoreFilePath) != "" &&
		strings.Contains(err.Error(), "Cannot read "+sess.RestoreFilePath) {
		agentstate.Logger.Info("Removing restore file", "file", sess.RestoreFilePath)

		if removeErr := os.Remove(sess.RestoreFilePath); removeErr != nil && !os.IsNotExist(removeErr) {
			agentstate.Logger.Error("Failed to remove restore file", "error", removeErr)
		}

		sess.RestoreFilePath = ""

		// Report the restore-file failure before returning so the server is aware
		// of the retryable failure (the task can be retried now that the corrupt
		// restore file has been removed)
		errorInfo := hashcat.ClassifyStderr(err.Error())
		cserrors.SendAgentError(ctx, err.Error(), task, errorInfo.Severity,
			cserrors.WithClassification(errorInfo.Category.String(), errorInfo.Retryable))
		display.JobFailed(err)

		return
	}

	// Send error with classified severity and metadata
	cserrors.SendAgentError(
		ctx,
		err.Error(),
		task,
		exitInfo.Severity,
		cserrors.WithClassification(exitInfo.Category.String(), exitInfo.Retryable),
	)
	display.JobFailed(err)
}
