package lib

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/duke-git/lancet/v2/validator"
	"github.com/pkg/errors"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/errorUtils"
	"github.com/unclesp1d3r/cipherswarmagent/lib/fileUtils"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/taskManager"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// runBenchmarkTask starts a hashcat benchmark session and processes its output.
// It returns a slice of benchmark results and a boolean indicating an error state.
func runBenchmarkTask(sess *hashcat.Session) ([]benchmarkResult, bool) {
	err := sess.Start()
	if err != nil {
		shared.Logger.Error("Failed to start benchmark session", "error", err)

		return nil, true
	}

	var benchmarkResults []benchmarkResult
	waitChan := make(chan int)

	go func() {
		defer close(waitChan)
		for {
			select {
			case stdOutLine := <-sess.StdoutLines:
				handleBenchmarkStdOutLine(stdOutLine, &benchmarkResults)
			case stdErrLine := <-sess.StderrMessages:
				handleBenchmarkStdErrLine(stdErrLine)
			case statusUpdate := <-sess.StatusUpdates:
				shared.Logger.Debug("Benchmark status update", "status", statusUpdate) // This should never happen
			case crackedHash := <-sess.CrackedHashes:
				shared.Logger.Debug("Benchmark cracked hash", "hash", crackedHash) // This should never happen
			case err := <-sess.DoneChan:
				if err != nil {
					shared.Logger.Error("Benchmark session failed", "error", err)
					taskManager.SendAgentError(err.Error(), nil, operations.SeverityFatal)
				}

				return
			}
		}
	}()

	<-waitChan

	return benchmarkResults, false
}

// handleBenchmarkStdOutLine processes a line of benchmark output, extracting relevant data and appending it to result.
func handleBenchmarkStdOutLine(line string, results *[]benchmarkResult) {
	fields := strings.Split(line, ":")
	if len(fields) != 6 {
		shared.Logger.Debug("Unknown benchmark line", "line", line)

		return
	}

	result := benchmarkResult{
		Device:     fields[0],
		HashType:   fields[1],
		RuntimeMs:  fields[3],
		HashTimeMs: fields[4],
		SpeedHs:    fields[5],
	}
	displayBenchmark(result)
	*results = append(*results, result)
}

// handleBenchmarkStdErrLine processes each line from the benchmark's standard error output, logs it, and reports warnings to the server.
func handleBenchmarkStdErrLine(line string) {
	displayBenchmarkError(line)
	if strutil.IsNotBlank(line) {
		taskManager.SendAgentError(line, nil, operations.SeverityWarning)
	}
}

// runAttackTask starts the attack session and handles real-time outputs and status updates.
// It processes stdout, stderr, status updates, cracked hashes, and handles session completion.
func runAttackTask(sess *hashcat.Session, task *components.Task) {
	err := sess.Start()
	if err != nil {
		shared.Logger.Error("Failed to start attack session", "error", err)
		taskManager.SendAgentError(err.Error(), task, operations.SeverityFatal)

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
	if validator.IsJSON(stdoutLine) {
		update := hashcat.Status{}
		err := json.Unmarshal([]byte(stdoutLine), &update)
		if err != nil {
			shared.Logger.Error("Failed to parse status update", "error", err)
		} else {
			displayJobStatus(update)
			taskManager.sendStatusUpdate(update, task, sess)
		}
	}
}

// handleStdErrLine handles a single line of standard error output by displaying and sending the error to the server.
func handleStdErrLine(stdErrLine string, task *components.Task) {
	displayJobError(stdErrLine)
	if strutil.IsNotBlank(stdErrLine) {
		taskManager.SendAgentError(stdErrLine, task, operations.SeverityMinor)
	}
}

// handleStatusUpdate processes a status update for a hashcat task and session.
// It does this by displaying the job status and sending the status update.
func handleStatusUpdate(statusUpdate hashcat.Status, task *components.Task, sess *hashcat.Session) {
	displayJobStatus(statusUpdate)
	taskManager.sendStatusUpdate(statusUpdate, task, sess)
}

// handleCrackedHash processes a cracked hash by displaying it and then sending it to a task server.
func handleCrackedHash(crackedHash hashcat.Result, task *components.Task) {
	displayJobCrackedHash(crackedHash)
	sendCrackedHash(crackedHash, task)
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
	if strings.Contains(err.Error(), fmt.Sprintf("Cannot read %s", sess.RestoreFilePath)) {
		if strutil.IsNotBlank(sess.RestoreFilePath) {
			shared.Logger.Info("Removing restore file", "file", sess.RestoreFilePath)
			err := fileutil.RemoveFile(sess.RestoreFilePath)
			if err != nil {
				shared.Logger.Error("Failed to remove restore file", "error", err)
			}
		}
	} else {
		taskManager.SendAgentError(err.Error(), task, operations.SeverityCritical)
		displayJobFailed(err)
	}
}

// runTestTask runs a hashcat test session, handles various output channels, and returns the session status or an error.
func runTestTask(sess *hashcat.Session) (*hashcat.Status, error) {
	err := sess.Start()
	if err != nil {
		shared.Logger.Error("Failed to start hashcat startup test session", "error", err)
		taskManager.SendAgentError(err.Error(), nil, operations.SeverityFatal)

		return nil, err
	}

	var testResults *hashcat.Status
	var errorResult error
	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)
		for {
			select {
			case stdoutLine := <-sess.StdoutLines:
				handleTestStdOutLine(stdoutLine)
			case stdErrLine := <-sess.StderrMessages:
				handleTestStdErrLine(stdErrLine, &errorResult)
			case statusUpdate := <-sess.StatusUpdates:
				testResults = &statusUpdate
			case crackedHash := <-sess.CrackedHashes:
				handleTestCrackedHash(crackedHash, &errorResult)
			case err := <-sess.DoneChan:
				handleTestDoneChan(err, &errorResult)
				sess.Cleanup()

				return
			}
		}
	}()

	<-waitChan

	return testResults, errorResult
}

// handleTestStdOutLine processes a line of standard output from a test, logging an error if the line isn't valid JSON.
func handleTestStdOutLine(stdoutLine string) {
	if !validator.IsJSON(stdoutLine) {
		shared.Logger.Error("Failed to parse status update", "output", stdoutLine)
	}
}

// handleTestStdErrLine sends the specified stderr line to the central server and sets the provided error result.
func handleTestStdErrLine(stdErrLine string, errorResult *error) {
	if strutil.IsNotBlank(stdErrLine) {
		taskManager.SendAgentError(stdErrLine, nil, operations.SeverityMinor)
		*errorResult = errors.New(stdErrLine)
	}
}

// handleTestCrackedHash processes a cracked hash result from hashcat and sets an error if the plaintext is blank.
func handleTestCrackedHash(crackedHash hashcat.Result, errorResult *error) {
	if strutil.IsBlank(crackedHash.Plaintext) {
		*errorResult = errors.New("received empty cracked hash")
	}
}

// handleTestDoneChan handles errors from the test session's done channel, sends them to central server if not exit status 1.
func handleTestDoneChan(err error, errorResult *error) {
	if err != nil && err.Error() != "exit status 1" {
		taskManager.SendAgentError(err.Error(), nil, operations.SeverityCritical)
		*errorResult = err
	}
}
