package lib

import (
	"encoding/json"
	"strings"

	"github.com/unclesp1d3r/cipherswarm-agent-go-api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

func RunBenchmarkTask(sess *hashcat.Session) ([]BenchmarkResult, bool) {
	err := sess.Start()
	if err != nil {
		Logger.Error("Failed to start benchmark session", "error", err)
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
					Logger.Debug("Unknown benchmark line", "line", stdOutLine)
				} else {
					result := BenchmarkResult{
						Device:    fields[0],
						HashType:  fields[1],
						RuntimeMs: fields[3],
						SpeedHs:   fields[4],
					}
					DisplayBenchmark(result)
					benchmarkResult = append(benchmarkResult, result)
				}

			case stdErrLine := <-sess.StderrMessages:
				DisplayBenchmarkError(stdErrLine)
			case statusUpdate := <-sess.StatusUpdates:
				Logger.Debug("Benchmark status update", "status", statusUpdate) // This should never happen
			case crackedHash := <-sess.CrackedHashes:
				Logger.Debug("Benchmark cracked hash", "hash", crackedHash) // This should never happen
			case err := <-sess.DoneChan:
				if err != nil {
					Logger.Error("Benchmark session failed", "error", err)
				}
				break procLoop
			}
		}
		waitChan <- 1
	}()
	<-waitChan
	sess.Cleanup()
	return benchmarkResult, false
}

func RunAttackTask(sess *hashcat.Session, task *cipherswarm.Task) {
	err := sess.Start()
	if err != nil {
		Logger.Error("Failed to start benchmark session", "error", err)
		return
	}
	waitChan := make(chan int)
	go func() {
	procLoop:
		for {
			select {
			case stdoutLine := <-sess.StdoutLines:
				if stdoutLine != "" && stdoutLine[0] == '{' {
					update := hashcat.Status{}
					err := json.Unmarshal([]byte(stdoutLine), &update)
					if err != nil {
						Logger.Error("Failed to parse status update", "error", err)
					} else {
						DisplayJobStatus(update)
						SendStatusUpdate(update, task)
					}
				}
			case stdErrLine := <-sess.StderrMessages:
				DisplayJobError(stdErrLine)
			case statusUpdate := <-sess.StatusUpdates:
				DisplayJobStatus(statusUpdate)
				SendStatusUpdate(statusUpdate, task)
			case crackedHash := <-sess.CrackedHashes:
				DisplayJobCrackedHash(crackedHash)
				SendCrackedHash(crackedHash, task)
			case err := <-sess.DoneChan:
				if err != nil {
					if err.Error() != "exit status 1" {
						// Something went wrong and we failed.
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
	sess.Cleanup()
	<-waitChan
}
