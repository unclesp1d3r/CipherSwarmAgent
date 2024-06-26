package lib

import (
	"encoding/json"
	"strings"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"

	"github.com/unclesp1d3r/cipherswarmagent/shared"

	"github.com/duke-git/lancet/validator"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// RunBenchmarkTask runs a benchmark session using the provided hashcat session.
// It starts the session, reads the output lines from stdout, and processes them to extract benchmark results.
// Any errors encountered during the benchmark session are logged and returned.
// The benchmark results are returned as a slice of BenchmarkResult structs.
// The second return value indicates whether the benchmark session was successful or not.
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
				SendAgentError(stdErrLine, nil, components.SeverityWarning)
				DisplayBenchmarkError(stdErrLine)
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

// RunAttackTask executes an attack task using the provided hashcat session and task.
// It starts the session, monitors the status updates, and sends the updates and results to the appropriate handlers.
// If an error occurs during the session start, it logs the error and returns.
// Once the session is done, it cleans up the session resources and waits for the completion of the goroutine.
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
				SendAgentError(stdErrLine, task, components.SeverityMinor)
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
