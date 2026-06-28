// runner.go contains the hashcat session-execution functions for the benchmark
// package: RunCapabilityDetection, runSingleBenchmark, collectSingleBenchmarkOutput,
// runBenchmarks, runBenchmarkTask, processBenchmarkOutput, finalizeBenchmarkSession,
// submitBatchIfReady, and the killAndDrain helper.

package benchmark

import (
	"context"
	"fmt"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// benchmarkBatchSize is the number of benchmark results to accumulate before
// submitting an incremental batch to the server.
const benchmarkBatchSize = 10

const processFlushTimeout = 100 * time.Millisecond // processFlushTimeout is the grace period after Kill() for the process to flush remaining stdout.

// killAndDrain kills a hashcat session and waits briefly for the process to
// flush remaining stdout before returning. Kill errors are logged at Error
// level with logMsg. Cleanup must be called by the caller after any
// site-specific work that must run before cleanup.
func killAndDrain(sess *hashcat.Session, logMsg string) {
	if err := sess.Kill(); err != nil {
		agentstate.Logger.Error(logMsg, "error", err)
	}

	flushTimer := time.NewTimer(processFlushTimeout)
	select {
	case <-sess.DoneChan:
	case <-flushTimer.C:
	}
	flushTimer.Stop()
}

// newCapabilityResult builds a placeholder Result for a capability-detected hash
// type (no real timings; SpeedHs="1", Placeholder=true).
func newCapabilityResult(hashTypeID string) Result {
	return Result{
		HashType:    hashTypeID,
		Device:      "1",
		RuntimeMs:   "0",
		HashTimeMs:  "0",
		SpeedHs:     "1",
		Placeholder: true,
	}
}

// RunCapabilityDetection runs hashcat --hash-info --machine-readable to discover
// supported hash types without executing a full benchmark. It returns placeholder
// Result entries (SpeedHs="1", Placeholder=true) for each discovered type.
func (m *Manager) RunCapabilityDetection(ctx context.Context) ([]Result, error) {
	jobParams := hashcat.Params{
		AttackMode:             hashcat.AttackHashInfo,
		BackendDevices:         m.DeviceConfig.ResolvedBackendDevices(),
		OpenCLDevices:          m.DeviceConfig.ResolvedOpenCLDevices(),
		OutPath:                m.Config.OutPath,
		ZapsPath:               m.Config.ZapsPath,
		RetainZapsOnCompletion: m.Config.RetainZapsOnCompletion,
	}

	sess, err := hashcat.NewHashcatSession(ctx, "capability-detect", jobParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create capability detection session: %w", err)
	}

	agentstate.Logger.Debug("Starting capability detection session", "cmdline", sess.CmdLine())

	if startErr := sess.Start(); startErr != nil {
		return nil, fmt.Errorf("failed to start capability detection session: %w", startErr)
	}

	var results []Result
	var sessionErr error // set by goroutine if hashcat process exits with error

	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)

		for {
			select {
			case <-ctx.Done():
				agentstate.Logger.Warn("Context cancelled during capability detection, killing session")

				killAndDrain(sess, "Failed to kill capability detection session")
				sess.Cleanup()

				return
			case line := <-sess.StdoutLines:
				hashTypeID, ok := parseHashInfoLine(line)
				if ok {
					results = append(results, newCapabilityResult(hashTypeID))
				}
			case errInfo := <-sess.StderrMessages:
				handleBenchmarkStdErrLine(ctx, errInfo)
			case <-sess.StatusUpdates:
				// --hash-info does not produce status updates; drain if any.
			case <-sess.CrackedHashes:
				// --hash-info does not crack hashes; drain if any.
			case procErr := <-sess.DoneChan:
				// Drain any remaining stdout lines.
				for {
					select {
					case line := <-sess.StdoutLines:
						hashTypeID, ok := parseHashInfoLine(line)
						if ok {
							results = append(results, newCapabilityResult(hashTypeID))
						}
					default:
						goto drained
					}
				}
			drained:
				if procErr != nil {
					agentstate.Logger.Error("Capability detection session failed", "error", procErr)
					sessionErr = procErr
				}

				sess.Cleanup()

				return
			}
		}
	}()

	<-waitChan

	if ctx.Err() != nil {
		return nil, fmt.Errorf("capability detection cancelled: %w", ctx.Err())
	}

	if sessionErr != nil && len(results) == 0 {
		return nil, fmt.Errorf("capability detection process failed with no results: %w", sessionErr)
	}

	agentstate.Logger.Info("Capability detection complete", "hash_types", len(results))

	return results, nil
}

// runSingleBenchmark runs a hashcat benchmark for a single hash type and
// collects the results. Returns nil if the session failed to start or the
// context was cancelled.
func (m *Manager) runSingleBenchmark(
	ctx context.Context,
	hashType int64,
	hashTypeStr string,
) []Result {
	sessionID := "bg-benchmark-" + hashTypeStr

	jobParams := hashcat.Params{
		AttackMode:             hashcat.AttackBenchmarkSingle,
		HashType:               hashType,
		BackendDevices:         m.DeviceConfig.ResolvedBackendDevices(),
		OpenCLDevices:          m.DeviceConfig.ResolvedOpenCLDevices(),
		OutPath:                m.Config.OutPath,
		ZapsPath:               m.Config.ZapsPath,
		RetainZapsOnCompletion: m.Config.RetainZapsOnCompletion,
	}

	sess, err := hashcat.NewHashcatSession(ctx, sessionID, jobParams)
	if err != nil {
		agentstate.Logger.Warn("Failed to create background benchmark session",
			"hash_type", hashTypeStr, "error", err)
		return nil
	}

	if startErr := sess.Start(); startErr != nil {
		agentstate.Logger.Warn("Failed to start background benchmark session",
			"hash_type", hashTypeStr, "error", startErr)
		return nil
	}

	return m.collectSingleBenchmarkOutput(ctx, sess)
}

// collectSingleBenchmarkOutput processes output from a single-type benchmark
// session, collecting results and cleaning up when done.
func (m *Manager) collectSingleBenchmarkOutput(
	ctx context.Context,
	sess *hashcat.Session,
) []Result {
	var results []Result

	for {
		select {
		case <-ctx.Done():
			agentstate.Logger.Warn("Context cancelled during background benchmark, killing session")
			killAndDrain(sess, "Failed to kill background benchmark session")
			sess.Cleanup()
			return nil

		case line := <-sess.StdoutLines:
			handleBenchmarkStdOutLine(line, &results, m.deviceManager())

		case errInfo := <-sess.StderrMessages:
			handleBenchmarkStdErrLine(ctx, errInfo)

		case <-sess.StatusUpdates:
			// Benchmark mode does not produce status updates; drain.

		case <-sess.CrackedHashes:
			// Benchmark mode does not crack hashes; drain.

		case procErr := <-sess.DoneChan:
			// Drain remaining stdout lines.
			drainStdout(sess, &results, m.deviceManager())

			if procErr != nil {
				agentstate.Logger.Warn("Background benchmark session exited with error",
					"error", procErr, "results_collected", len(results))

				if len(results) == 0 {
					sess.Cleanup()

					return nil
				}
			}

			sess.Cleanup()
			return results
		}
	}
}

// runBenchmarks creates and runs a hashcat benchmark session, returning the
// parsed results. Returns an error (reported as SeverityMajor to the server)
// if the session cannot be created or fails to produce results.
func (m *Manager) runBenchmarks(ctx context.Context) ([]Result, error) {
	additionalArgs := arch.GetAdditionalHashcatArgs()

	jobParams := hashcat.Params{
		AttackMode:                hashcat.AttackBenchmark,
		AdditionalArgs:            additionalArgs,
		BackendDevices:            m.DeviceConfig.ResolvedBackendDevices(),
		OpenCLDevices:             m.DeviceConfig.ResolvedOpenCLDevices(),
		EnableAdditionalHashTypes: m.Config.EnableAdditionalHashTypes,
		OutPath:                   m.Config.OutPath,
		ZapsPath:                  m.Config.ZapsPath,
		RetainZapsOnCompletion:    m.Config.RetainZapsOnCompletion,
	}

	sess, err := hashcat.NewHashcatSession(ctx, "benchmark", jobParams)
	if err != nil {
		return nil, cserrors.LogAndSendError(
			ctx, "Failed to create benchmark session", err, api.SeverityMajor, nil,
		)
	}

	agentstate.Logger.Debug("Starting benchmark session", "cmdline", sess.CmdLine())
	display.BenchmarkStarting()

	results, startErr := m.runBenchmarkTask(ctx, sess)
	if startErr != nil {
		return nil, cserrors.LogAndSendError(
			ctx,
			"Benchmark session failed to start",
			startErr,
			api.SeverityMajor,
			nil,
		)
	}

	logBenchmarksComplete(results)

	return results, nil
}

// runBenchmarkTask starts a hashcat benchmark session and processes its output.
// It returns a slice of benchmark results and the start error if the session
// failed to launch.
func (m *Manager) runBenchmarkTask(ctx context.Context, sess *hashcat.Session) ([]Result, error) {
	err := sess.Start()
	if err != nil {
		agentstate.Logger.Error("Failed to start benchmark session", "error", err)

		return nil, fmt.Errorf("failed to start benchmark session: %w", err)
	}

	return m.processBenchmarkOutput(ctx, sess), nil
}

// submitBatchIfReady sends an incremental batch of benchmark results to the
// server when the number of unsubmitted results reaches benchmarkBatchSize.
// On success, it marks the batch as submitted and persists the cache. Returns
// the updated submittedUpTo index.
func (m *Manager) submitBatchIfReady(
	ctx context.Context,
	results []Result,
	submittedUpTo int,
) int {
	if len(results)-submittedUpTo < benchmarkBatchSize {
		return submittedUpTo
	}

	batch := results[submittedUpTo:]
	if sendErr := m.sendBenchmarkResults(ctx, batch); sendErr != nil {
		agentstate.Logger.Warn("Failed to submit incremental benchmark batch", "error", sendErr)

		return submittedUpTo
	}

	markSubmitted(results, submittedUpTo, len(results))
	newUpTo := len(results)

	if saveErr := saveBenchmarkCache(results); saveErr != nil {
		agentstate.Logger.Warn("Failed to save benchmark cache after batch", "error", saveErr)
	}

	return newUpTo
}

// finalizeBenchmarkSession handles the DoneChan signal: drains remaining
// stdout, reports errors, submits any unsubmitted results, and persists
// the final cache state. results is a pointer because drainStdout may
// append additional elements that the caller must observe.
func (m *Manager) finalizeBenchmarkSession(
	ctx context.Context,
	sess *hashcat.Session,
	results *[]Result,
	submittedUpTo int,
	procErr error,
) {
	drainStdout(sess, results, m.deviceManager())

	if procErr != nil {
		agentstate.Logger.Error("Benchmark session failed", "error", procErr)
		cserrors.SendAgentError(ctx, procErr.Error(), nil, api.SeverityFatal)
	}

	// Submit any remaining unsubmitted results
	if len(*results) > submittedUpTo {
		batch := (*results)[submittedUpTo:]
		if sendErr := m.sendBenchmarkResults(ctx, batch); sendErr != nil {
			agentstate.Logger.Warn("Failed to submit final benchmark batch", "error", sendErr)
		} else {
			markSubmitted(*results, submittedUpTo, len(*results))
		}
	}

	agentstate.State.SetBenchmarksSubmitted(allSubmitted(*results))

	// Always persist cache with Submitted flags for retry
	if saveErr := saveBenchmarkCache(*results); saveErr != nil {
		agentstate.Logger.Warn("Failed to save final benchmark cache", "error", saveErr)
	}

	sess.Cleanup()
}

// processBenchmarkOutput reads from the session's channels, collects benchmark
// results, and submits them incrementally in batches. It marks each result as
// Submitted after successful server acknowledgment and persists the cache after
// each batch. Returns the collected results (with Submitted flags set).
//
// On context cancellation, BenchmarksSubmitted remains false; partial results
// are cached to disk for retry via TrySubmitCachedBenchmarks on the next
// agent loop iteration.
func (m *Manager) processBenchmarkOutput(ctx context.Context, sess *hashcat.Session) []Result {
	// benchmarkResults is exclusively owned by the goroutine below until
	// waitChan is closed, at which point ownership transfers to the caller.
	var benchmarkResults []Result

	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)

		submittedUpTo := 0

		for {
			select {
			case <-ctx.Done():
				agentstate.Logger.Warn("Context cancelled during benchmark, killing session")

				// Wait briefly for the process to exit and flush remaining stdout.
				// In tests with mock sessions (no process), this always hits the timeout.
				killAndDrain(sess, "Failed to kill benchmark session on cancellation")

				// Best-effort drain: may miss lines still in flight between the
				// OS pipe buffer and the channel.
				drainStdout(sess, &benchmarkResults, m.deviceManager())

				if len(benchmarkResults) > 0 {
					if saveErr := saveBenchmarkCache(benchmarkResults); saveErr != nil {
						agentstate.Logger.Warn(
							"Partial benchmark results collected but could not be persisted",
							"error", saveErr, "count", len(benchmarkResults))
					} else {
						agentstate.Logger.Warn("Context cancelled during benchmark, partial results cached",
							"count", len(benchmarkResults))
					}
				} else {
					agentstate.Logger.Warn("Context cancelled during benchmark, no results to cache")
				}

				agentstate.State.SetBenchmarksSubmitted(false)
				sess.Cleanup()

				return
			case stdOutLine := <-sess.StdoutLines:
				handleBenchmarkStdOutLine(stdOutLine, &benchmarkResults, m.deviceManager())
				submittedUpTo = m.submitBatchIfReady(ctx, benchmarkResults, submittedUpTo)
			case stdErrLine := <-sess.StderrMessages:
				handleBenchmarkStdErrLine(ctx, stdErrLine)
			case statusUpdate := <-sess.StatusUpdates:
				agentstate.Logger.Debug("Benchmark status update", "status", statusUpdate)
			case crackedHash := <-sess.CrackedHashes:
				agentstate.Logger.Debug("Benchmark cracked hash", "hash", crackedHash)
			case err := <-sess.DoneChan:
				m.finalizeBenchmarkSession(ctx, sess, &benchmarkResults, submittedUpTo, err)

				return
			}
		}
	}()

	<-waitChan

	return benchmarkResults
}
