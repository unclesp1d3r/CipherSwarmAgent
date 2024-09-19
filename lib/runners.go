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
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// runBenchmarkTask runs a benchmark session and processes its output and errors.
// It starts a benchmark session and initializes a results slice.
// A goroutine is started to handle different types of messages from the session channels.
// Stdout lines are processed to extract benchmark results, while stderr lines are handled separately.
// Unexpected status updates and cracked hash messages are logged for debugging purposes.
// The function waits for the goroutine to complete before returning the benchmark results and an error flag.
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
					SendAgentError(err.Error(), nil, operations.SeverityFatal)
				}

				return
			}
		}
	}()

	<-waitChan

	return benchmarkResults, false
}

// handleBenchmarkStdOutLine processes a single line of standard output from a benchmark session.
// It splits the line into fields and creates a benchmarkResult struct if the expected number of fields is found.
// If the line format is incorrect, it logs a debug message and returns.
// The function logs the benchmark results using displayBenchmark and appends the result to the results slice.
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

// handleBenchmarkStdErrLine processes a line of benchmark standard error output.
// It logs the error message and sends a warning-level error report to the agent server if the line is not blank.
func handleBenchmarkStdErrLine(line string) {
	displayBenchmarkError(line)
	if strutil.IsNotBlank(line) {
		SendAgentError(line, nil, operations.SeverityWarning)
	}
}

// runAttackTask starts a hashcat attack session with the given session and task.
// It handles various session outputs such as stdout lines, stderr messages, status updates, cracked hashes,
// and completion status by forwarding them to their respective handlers.
// If the session fails to start, it logs the error and sends a fatal error notification.
func runAttackTask(sess *hashcat.Session, task *components.Task) {
	err := sess.Start()
	if err != nil {
		shared.Logger.Error("Failed to start attack session", "error", err)
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

// handleStdOutLine processes a single line of output. If the output is valid JSON, it parses and updates task status.
func handleStdOutLine(stdoutLine string, task *components.Task, sess *hashcat.Session) {
	if validator.IsJSON(stdoutLine) {
		update := hashcat.Status{}
		err := json.Unmarshal([]byte(stdoutLine), &update)
		if err != nil {
			shared.Logger.Error("Failed to parse status update", "error", err)
		} else {
			displayJobStatus(update)
			sendStatusUpdate(update, task, sess)
		}
	}
}

// handleStdErrLine processes a line read from stderr for a given task.
// It first logs the stderr line by calling displayJobError and, if the line is not blank,
// sends an agent error report using SendAgentError with a severity of SeverityMinor.
func handleStdErrLine(stdErrLine string, task *components.Task) {
	displayJobError(stdErrLine)
	if strutil.IsNotBlank(stdErrLine) {
		SendAgentError(stdErrLine, task, operations.SeverityMinor)
	}
}

// handleStatusUpdate processes the status update by displaying the job status and sending the status update to the relevant components.
func handleStatusUpdate(statusUpdate hashcat.Status, task *components.Task, sess *hashcat.Session) {
	displayJobStatus(statusUpdate)
	sendStatusUpdate(statusUpdate, task, sess)
}

// handleCrackedHash processes a cracked hash by displaying it and sending it to the task server.
func handleCrackedHash(crackedHash hashcat.Result, task *components.Task) {
	displayJobCrackedHash(crackedHash)
	sendCrackedHash(crackedHash, task)
}

// handleDoneChan handles the completion scenario of a task with error checking and session cleanup.
// If an error occurs, it evaluates the error message. If the error message is "exit status 1",
// it signals that the job is exhausted by calling displayJobExhausted() and marks the task
// as exhausted using markTaskExhausted(task). For other errors, it calls handleNonExhaustedError()
// to address them. After these checks, sess.Cleanup() is called to cleanup the session.
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

// handleNonExhaustedError handles errors related to non-exhausted tasks in a hashcat session.
// If the error indicates the inability to read the restore file and the restore file path is not blank,
// it attempts to remove the restore file. Upon a successful or failed removal, it logs appropriate messages.
// In case the condition is not met, it sends a critical severity agent error and displays a job failure.
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
		SendAgentError(err.Error(), task, operations.SeverityCritical)
		displayJobFailed(err)
	}
}

// runTestTask starts a hashcat test session and handles its output, status updates, error messages, and cracked hashes.
// It returns the final status of the test session and any errors encountered during execution.
func runTestTask(sess *hashcat.Session) (*hashcat.Status, error) {
	err := sess.Start()
	if err != nil {
		shared.Logger.Error("Failed to start hashcat startup test session", "error", err)
		SendAgentError(err.Error(), nil, operations.SeverityFatal)

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

// handleTestStdOutLine processes a line of standard output from a test. If the line is not valid JSON, it logs an error.
func handleTestStdOutLine(stdoutLine string) {
	if !validator.IsJSON(stdoutLine) {
		shared.Logger.Error("Failed to parse status update", "output", stdoutLine)
	}
}

// handleTestStdErrLine processes a non-blank stderr line by sending an error report and updating the error result pointer.
func handleTestStdErrLine(stdErrLine string, errorResult *error) {
	if strutil.IsNotBlank(stdErrLine) {
		SendAgentError(stdErrLine, nil, operations.SeverityMinor)
		*errorResult = errors.New(stdErrLine)
	}
}

// handleTestCrackedHash checks if the cracked hash's plaintext is blank. If so, it sets an error message in errorResult.
func handleTestCrackedHash(crackedHash hashcat.Result, errorResult *error) {
	if strutil.IsBlank(crackedHash.Plaintext) {
		*errorResult = errors.New("received empty cracked hash")
	}
}

// handleTestDoneChan handles the completion of a test by checking the error and sending a critical error message if needed.
// Parameters:
// - err: The error object received from the test execution.
// - errorResult: A pointer to an error variable to store the error for further handling.
// If the error is not "exit status 1", it sends a critical error message using SendAgentError and updates errorResult.
func handleTestDoneChan(err error, errorResult *error) {
	if err != nil && err.Error() != "exit status 1" {
		SendAgentError(err.Error(), nil, operations.SeverityCritical)
		*errorResult = err
	}
}
