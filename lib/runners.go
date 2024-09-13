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

// runBenchmarkTask runs a benchmark session using the provided hashcat session.
// It starts the session, reads the output from stdout and stderr, and handles various events.
// The benchmark results are collected and returned as a slice of benchmarkResult structs.
// If there is an error starting the session, the function returns an empty slice and a boolean value of true.
// If the benchmark session completes successfully, the function returns the benchmark results and a boolean value of false.
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

func handleBenchmarkStdErrLine(line string) {
	displayBenchmarkError(line)
	if strutil.IsNotBlank(line) {
		SendAgentError(line, nil, operations.SeverityWarning)
	}
}

// runAttackTask starts an attack session using the provided hashcat session and task.
// It continuously monitors the session for status updates, cracked hashes, and errors,
// and sends corresponding updates and notifications.
// If the session fails to start, a fatal agent error is sent and the function returns.
// If the session completes successfully, the task is marked as exhausted.
// If the session fails with a non-fatal error, a minor agent error is sent and the function returns.
//
// Parameters:
// - sess: The hashcat session to run the attack.
// - task: The task to be executed.
//
// Example usage:
//
//	sess := hashcat.NewSession()
//	task := components.NewTask()
//	RunAttackTask(sess, task)
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

func handleStdErrLine(stdErrLine string, task *components.Task) {
	displayJobError(stdErrLine)
	if strutil.IsNotBlank(stdErrLine) {
		SendAgentError(stdErrLine, task, operations.SeverityMinor)
	}
}

func handleStatusUpdate(statusUpdate hashcat.Status, task *components.Task, sess *hashcat.Session) {
	displayJobStatus(statusUpdate)
	sendStatusUpdate(statusUpdate, task, sess)
}

func handleCrackedHash(crackedHash hashcat.Result, task *components.Task) {
	displayJobCrackedHash(crackedHash)
	sendCrackedHash(crackedHash, task)
}

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

// runTestTask runs a test session using the provided hashcat session.
// It starts the session, reads the output from stdout and stderr, and handles various events.
// The test results are collected and returned as a hashcat.Status struct.
// If there is an error starting the session, the function returns nil and the error.
//
// Parameters:
// - sess: The hashcat session to run the test.
//
// Returns:
// - *hashcat.Status: The test results.
// - error: An error if the session fails to start or an error occurs during the session.
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

func handleTestStdOutLine(stdoutLine string) {
	if !validator.IsJSON(stdoutLine) {
		shared.Logger.Error("Failed to parse status update", "output", stdoutLine)
	}
}

func handleTestStdErrLine(stdErrLine string, errorResult *error) {
	if strutil.IsNotBlank(stdErrLine) {
		SendAgentError(stdErrLine, nil, operations.SeverityMinor)
		*errorResult = errors.New(stdErrLine)
	}
}

func handleTestCrackedHash(crackedHash hashcat.Result, errorResult *error) {
	if strutil.IsBlank(crackedHash.Plaintext) {
		*errorResult = errors.New("received empty cracked hash")
	}
}

func handleTestDoneChan(err error, errorResult *error) {
	if err != nil && err.Error() != "exit status 1" {
		SendAgentError(err.Error(), nil, operations.SeverityCritical)
		*errorResult = err
	}
}
