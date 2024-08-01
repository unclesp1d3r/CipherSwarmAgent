package lib

import (
	"encoding/json"
	"strings"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"

	"github.com/unclesp1d3r/cipherswarmagent/shared"

	"github.com/duke-git/lancet/v2/strutil"
	"github.com/duke-git/lancet/validator"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// RunBenchmarkTask runs a benchmark session using the provided hashcat session.
// It starts the session, reads the output from stdout and stderr, and handles various events.
// The benchmark results are collected and returned as a slice of BenchmarkResult structs.
// If there is an error starting the session, the function returns an empty slice and a boolean value of true.
// If the benchmark session completes successfully, the function returns the benchmark results and a boolean value of false.
func RunBenchmarkTask(sess *hashcat.Session) ([]BenchmarkResult, bool) {
	err := sess.Start()
	if err != nil {
		shared.Logger.Error("Failed to start benchmark session", "error", err)
		return nil, true
	}
	var benchmarkResult []BenchmarkResult
	waitChan := make(chan int)
	go func() {
	procLoop:
		for {
			select {
			case stdOutLine := <-sess.StdoutLines:
				fields := strings.Split(stdOutLine, ":")
				if len(fields) != 6 {
					shared.Logger.Debug("Unknown benchmark line", "line", stdOutLine)
				} else {
					result := BenchmarkResult{
						Device:     fields[0],
						HashType:   fields[1],
						RuntimeMs:  fields[3],
						HashTimeMs: fields[4],
						SpeedHs:    fields[5],
					}
					DisplayBenchmark(result)
					benchmarkResult = append(benchmarkResult, result)
				}

			case stdErrLine := <-sess.StderrMessages:
				DisplayBenchmarkError(stdErrLine)
				// Ignore empty lines
				if strutil.IsNotBlank(stdErrLine) {
					SendAgentError(stdErrLine, nil, components.SeverityWarning)
				}
			case statusUpdate := <-sess.StatusUpdates:
				shared.Logger.Debug("Benchmark status update", "status", statusUpdate) // This should never happen
			case crackedHash := <-sess.CrackedHashes:
				shared.Logger.Debug("Benchmark cracked hash", "hash", crackedHash) // This should never happen
			case err := <-sess.DoneChan:
				if err != nil {
					shared.Logger.Error("Benchmark session failed", "error", err)
					SendAgentError(err.Error(), nil, components.SeverityFatal)
				}
				break procLoop
			}
		}
		waitChan <- 1
	}()
	<-waitChan
	return benchmarkResult, false
}

// RunAttackTask starts an attack session using the provided hashcat session and task.
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
func RunAttackTask(sess *hashcat.Session, task *components.Task) {
	err := sess.Start()
	if err != nil {
		shared.Logger.Error("Failed to start attack session", "error", err)
		SendAgentError(err.Error(), task, components.SeverityFatal)
		return
	}
	waitChan := make(chan int)
	go func() {
	procLoop:
		for {
			select {
			case stdoutLine := <-sess.StdoutLines:
				if validator.IsJSON(stdoutLine) {
					update := hashcat.Status{}
					err := json.Unmarshal([]byte(stdoutLine), &update)
					if err != nil {
						shared.Logger.Error("Failed to parse status update", "error", err)
					} else {
						DisplayJobStatus(update)
						SendStatusUpdate(update, task, sess)
					}
				}
			case stdErrLine := <-sess.StderrMessages:
				DisplayJobError(stdErrLine)
				if strutil.IsNotBlank(stdErrLine) {
					SendAgentError(stdErrLine, task, components.SeverityMinor)
				}
			case statusUpdate := <-sess.StatusUpdates:
				DisplayJobStatus(statusUpdate)
				SendStatusUpdate(statusUpdate, task, sess)
			case crackedHash := <-sess.CrackedHashes:
				DisplayJobCrackedHash(crackedHash)
				SendCrackedHash(crackedHash, task)
			case err := <-sess.DoneChan:
				if err != nil {
					if err.Error() != "exit status 1" {
						// Something went wrong and we failed.
						SendAgentError(err.Error(), task, components.SeverityFatal)
						DisplayJobFailed(err)
					} else {
						// Exit status 1 means we exhausted the task. Mark it as such.
						DisplayJobExhausted()
						MarkTaskExhausted(task)
					}
				}
				break procLoop
			}
		}
		waitChan <- 1
	}()
	<-waitChan
}
