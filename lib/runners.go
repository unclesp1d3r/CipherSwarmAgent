package lib

import (
	"encoding/json"
	"strings"

	"github.com/unclesp1d3r/cipherswarm-agent-go-api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

func RunBenchmarkTask(sess *hashcat.HashcatSession) ([]BenchmarkResult, bool) {
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
					Logger.Info("Benchmark result", "device", result.Device,
						"hash_type", result.HashType, "runtime_ms", result.RuntimeMs, "speed_hs", result.SpeedHs)
					benchmarkResult = append(benchmarkResult, result)
				}

			case stdErrLine := <-sess.StderrMessages:
				Logger.Debug("Benchmark stderr", "line", CleanString(stdErrLine))
			case statusUpdate := <-sess.StatusUpdates:
				Logger.Debug("Benchmark status update", "status", statusUpdate)
			case crackedHash := <-sess.CrackedHashes:
				Logger.Debug("Benchmark cracked hash", "hash", crackedHash)
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

func RunAttackTask(sess *hashcat.HashcatSession, task *cipherswarm.Task) {
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
					update := hashcat.HashcatStatus{}
					err := json.Unmarshal([]byte(stdoutLine), &update)
					if err != nil {
						Logger.Error("Failed to parse status update", "error", err)
					} else {
						Logger.Debug("Job status update", "status", update)
						SendStatusUpdate(update, task)
					}
				}
			case stdErrLine := <-sess.StderrMessages:
				Logger.Debug("Job stderr", "line", CleanString(stdErrLine))
			case statusUpdate := <-sess.StatusUpdates:
				SendStatusUpdate(statusUpdate, task)
			case crackedHash := <-sess.CrackedHashes:
				Logger.Debug("Job cracked hash", "hash", crackedHash)
				SendCrackedHash(crackedHash, task)
			case err := <-sess.DoneChan:
				if err != nil {

					if err.Error() == "exit status 1" {
						Logger.Info("Job session exhausted", "status", "exhausted")
						MarkTaskExhausted(task)

					} else {
						Logger.Error("Job session failed", "error", err)
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
