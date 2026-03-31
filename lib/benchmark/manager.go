// Package benchmark provides benchmark management for the CipherSwarm agent.
// It handles running hashcat benchmarks, submitting results to the server,
// and caching results for retry on failure.
package benchmark

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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

var errBadResponse = errors.New("bad response from server")

// Manager handles benchmark operations including running benchmarks,
// submitting results, and managing the benchmark cache.
type Manager struct {
	agentsClient   api.AgentsClient
	BackendDevices string
	OpenCLDevices  string
}

// NewManager creates a new benchmark Manager with the given API client.
func NewManager(agentsClient api.AgentsClient) *Manager {
	return &Manager{agentsClient: agentsClient}
}

// unsubmittedResults returns a new slice containing only benchmark results
// that have not yet been submitted to the server.
func unsubmittedResults(results []display.BenchmarkResult) []display.BenchmarkResult {
	var unsubmitted []display.BenchmarkResult
	for _, r := range results {
		if !r.Submitted {
			unsubmitted = append(unsubmitted, r)
		}
	}

	return unsubmitted
}

// allSubmitted reports whether every result in the slice has been submitted.
// Returns true for an empty or nil slice (nothing to submit = done).
func allSubmitted(results []display.BenchmarkResult) bool {
	for _, r := range results {
		if !r.Submitted {
			return false
		}
	}

	return true
}

// markSubmitted sets the Submitted flag to true for results in the given
// slice at indices [startIdx, endIdx). This mutates the slice elements
// in-place, which is safe within the owning goroutine.
func markSubmitted(results []display.BenchmarkResult, startIdx, endIdx int) {
	for i := startIdx; i < endIdx && i < len(results); i++ {
		results[i].Submitted = true
	}
}

// sendBenchmarkResults sends the collected benchmark results to a server endpoint.
// It converts each display.BenchmarkResult into a HashcatBenchmark and appends them to a slice.
// If the conversion fails for a result, it continues to the next result.
// Creates a SubmitBenchmarkJSONRequestBody with the HashcatBenchmarks slice and submits it via the API client interface.
// Returns an error if submission or the response received is not successful.
func (m *Manager) sendBenchmarkResults(ctx context.Context, benchmarkResults []display.BenchmarkResult) error {
	benchmarks := make([]api.HashcatBenchmark, 0, len(benchmarkResults))

	for _, result := range benchmarkResults {
		benchmark, err := createBenchmark(result)
		if err != nil {
			agentstate.Logger.Warn("Skipping unparseable benchmark result", "error", err, "hash_type", result.HashType)

			continue
		}

		benchmarks = append(benchmarks, benchmark)
	}

	if len(benchmarks) == 0 {
		return fmt.Errorf("all %d benchmark results failed to parse; nothing to submit", len(benchmarkResults))
	}

	results := api.SubmitBenchmarkJSONRequestBody{
		HashcatBenchmarks: benchmarks,
	}

	res, err := m.agentsClient.SubmitBenchmark(
		ctx,
		agentstate.State.AgentID,
		results,
	)
	if err != nil {
		return err
	}

	if res.StatusCode() == http.StatusNoContent {
		return nil
	}

	return fmt.Errorf("%w: %s", errBadResponse, res.Status())
}

// createBenchmark converts a display.BenchmarkResult to an api.HashcatBenchmark struct.
// It handles the conversion of string fields in display.BenchmarkResult to appropriate types.
// Returns a HashcatBenchmark instance and an error if any conversion fails.
func createBenchmark(result display.BenchmarkResult) (api.HashcatBenchmark, error) {
	hashType, err := strconv.Atoi(result.HashType)
	if err != nil {
		return api.HashcatBenchmark{}, fmt.Errorf("failed to convert HashType: %w", err)
	}

	runtimeMs, err := strconv.Atoi(result.RuntimeMs)
	if err != nil {
		return api.HashcatBenchmark{}, fmt.Errorf("failed to convert RuntimeMs: %w", err)
	}

	speedHs, err := strconv.ParseFloat(result.SpeedHs, 64)
	if err != nil {
		return api.HashcatBenchmark{}, fmt.Errorf("failed to convert SpeedHs: %w", err)
	}

	device, err := strconv.Atoi(result.Device)
	if err != nil {
		return api.HashcatBenchmark{}, fmt.Errorf("failed to convert Device: %w", err)
	}

	return api.HashcatBenchmark{
		HashType:  hashType,
		Runtime:   int64(runtimeMs),
		HashSpeed: speedHs,
		Device:    device,
	}, nil
}

// SubmitCapabilityResults caches and submits placeholder capability-detection results.
// It is the deferred-benchmark equivalent of the full UpdateBenchmarks path.
func (m *Manager) SubmitCapabilityResults(ctx context.Context, results []display.BenchmarkResult) error {
	return m.cacheAndSubmitBenchmarks(ctx, results)
}

// RunCapabilityDetection runs hashcat --hash-info --machine-readable to discover
// supported hash types without executing a full benchmark. It returns placeholder
// BenchmarkResult entries (SpeedHs="1", Placeholder=true) for each discovered type.
func (m *Manager) RunCapabilityDetection(ctx context.Context) ([]display.BenchmarkResult, error) {
	jobParams := hashcat.Params{
		AttackMode:     hashcat.AttackHashInfo,
		BackendDevices: m.BackendDevices,
		OpenCLDevices:  m.OpenCLDevices,
	}

	sess, err := hashcat.NewHashcatSession(ctx, "capability-detect", jobParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create capability detection session: %w", err)
	}

	agentstate.Logger.Debug("Starting capability detection session", "cmdline", sess.CmdLine())

	if startErr := sess.Start(); startErr != nil {
		return nil, fmt.Errorf("failed to start capability detection session: %w", startErr)
	}

	var results []display.BenchmarkResult
	var sessionErr error // set by goroutine if hashcat process exits with error

	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)

		for {
			select {
			case <-ctx.Done():
				agentstate.Logger.Warn("Context cancelled during capability detection, killing session")

				if killErr := sess.Kill(); killErr != nil {
					agentstate.Logger.Error("Failed to kill capability detection session", "error", killErr)
				}

				flushTimer := time.NewTimer(processFlushTimeout)
				select {
				case <-sess.DoneChan:
				case <-flushTimer.C:
				}
				flushTimer.Stop()

				sess.Cleanup()

				return
			case line := <-sess.StdoutLines:
				hashTypeID, ok := parseHashInfoLine(line)
				if ok {
					results = append(results, display.BenchmarkResult{
						HashType:    hashTypeID,
						Device:      "1",
						RuntimeMs:   "0",
						HashTimeMs:  "0",
						SpeedHs:     "1",
						Placeholder: true,
					})
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
							results = append(results, display.BenchmarkResult{
								HashType:    hashTypeID,
								Device:      "1",
								RuntimeMs:   "0",
								HashTimeMs:  "0",
								SpeedHs:     "1",
								Placeholder: true,
							})
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

// idleCheckInterval is the polling interval for checking if the agent is idle
// before starting a background benchmark for the next hash type.
const idleCheckInterval = 30 * time.Second

// RunBackgroundBenchmarks replaces placeholder cache entries with real benchmark
// results by running hashcat --benchmark -m <type> for each placeholder hash type.
// It waits for the agent to be idle before each run and submits results
// incrementally. The method is designed to run as a long-lived goroutine.
func (m *Manager) RunBackgroundBenchmarks(ctx context.Context) {
	placeholders, err := loadPlaceholderResults()
	if err != nil {
		agentstate.Logger.Error(
			"Failed to load placeholder results for background benchmarking; "+
				"real benchmarks will NOT run until agent restart",
			"error", err)

		return
	}

	if len(placeholders) == 0 {
		agentstate.Logger.Debug("No placeholder benchmarks to run in background")
		return
	}

	agentstate.Logger.Info("Starting background benchmarking",
		"placeholder_count", len(placeholders))

	for i, placeholder := range placeholders {
		// Wait for idle before each benchmark run.
		if cancelled := m.waitForIdle(ctx); cancelled {
			agentstate.Logger.Info("Background benchmarking cancelled, partial results cached")
			return
		}

		hashTypeInt, parseErr := strconv.ParseInt(placeholder.HashType, 10, 64)
		if parseErr != nil {
			agentstate.Logger.Warn("Skipping unparseable placeholder hash type",
				"hash_type", placeholder.HashType, "error", parseErr)
			continue
		}

		results := m.runSingleBenchmark(ctx, hashTypeInt, placeholder.HashType)
		if results == nil {
			// Session failed or context cancelled; runSingleBenchmark already logged.
			if ctx.Err() != nil {
				agentstate.Logger.Info("Background benchmarking cancelled, partial results cached")
				return
			}
			continue
		}

		m.updateCacheWithResults(ctx, results)

		agentstate.Logger.Info("Background benchmark progress",
			"completed", i+1, "total", len(placeholders),
			"hash_type", placeholder.HashType)
	}

	agentstate.Logger.Info("Background benchmarking complete")
}

// waitForIdle blocks until the agent's current activity is "waiting" or the
// context is cancelled. Returns true if the context was cancelled.
func (m *Manager) waitForIdle(ctx context.Context) bool {
	for {
		if agentstate.State.GetCurrentActivity() == agentstate.CurrentActivityWaiting {
			return false
		}

		timer := time.NewTimer(idleCheckInterval)
		select {
		case <-timer.C:
			timer.Stop() // idiomatic cleanup per project convention
		case <-ctx.Done():
			timer.Stop()
			return true
		}
	}
}

// runSingleBenchmark runs a hashcat benchmark for a single hash type and
// collects the results. Returns nil if the session failed to start or the
// context was cancelled.
func (m *Manager) runSingleBenchmark(
	ctx context.Context,
	hashType int64,
	hashTypeStr string,
) []display.BenchmarkResult {
	sessionID := "bg-benchmark-" + hashTypeStr

	jobParams := hashcat.Params{
		AttackMode:     hashcat.AttackBenchmarkSingle,
		HashType:       hashType,
		BackendDevices: m.BackendDevices,
		OpenCLDevices:  m.OpenCLDevices,
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
) []display.BenchmarkResult {
	var results []display.BenchmarkResult

	for {
		select {
		case <-ctx.Done():
			agentstate.Logger.Warn("Context cancelled during background benchmark, killing session")
			if killErr := sess.Kill(); killErr != nil {
				agentstate.Logger.Error("Failed to kill background benchmark session",
					"error", killErr)
			}

			flushTimer := time.NewTimer(processFlushTimeout)
			select {
			case <-sess.DoneChan:
			case <-flushTimer.C:
			}
			flushTimer.Stop()

			sess.Cleanup()
			return nil

		case line := <-sess.StdoutLines:
			handleBenchmarkStdOutLine(line, &results)

		case errInfo := <-sess.StderrMessages:
			handleBenchmarkStdErrLine(ctx, errInfo)

		case <-sess.StatusUpdates:
			// Benchmark mode does not produce status updates; drain.

		case <-sess.CrackedHashes:
			// Benchmark mode does not crack hashes; drain.

		case procErr := <-sess.DoneChan:
			// Drain remaining stdout lines.
			drainStdout(sess, &results)

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

// updateCacheWithResults reloads the full benchmark cache, replaces matching
// placeholder entries with real results, saves the cache, and submits the
// new results to the server. Holds cacheMu for the entire load-modify-save
// sequence to prevent concurrent cache corruption.
func (m *Manager) updateCacheWithResults(
	ctx context.Context,
	newResults []display.BenchmarkResult,
) {
	if len(newResults) == 0 {
		return
	}

	cacheMu.Lock()
	defer cacheMu.Unlock()

	fullCache, err := loadBenchmarkCacheLocked()
	if err != nil || fullCache == nil {
		if err != nil {
			agentstate.Logger.Error(
				"Failed to reload benchmark cache for background update; attempting direct submission",
				"error", err)
		} else {
			agentstate.Logger.Warn("Benchmark cache is empty during background update; attempting direct submission")
		}

		// Still attempt to submit results so GPU work is not wasted.
		realResults := make([]display.BenchmarkResult, 0, len(newResults))
		for _, r := range newResults {
			r.Placeholder = false
			realResults = append(realResults, r)
		}

		if sendErr := m.sendBenchmarkResults(ctx, realResults); sendErr != nil {
			agentstate.Logger.Error("Failed to submit benchmark results after cache failure",
				"error", sendErr)
		}

		return
	}

	// Build lookup from new results by hash type.
	newByHashType := make(map[string]display.BenchmarkResult, len(newResults))
	for _, r := range newResults {
		newByHashType[r.HashType] = r
	}

	// Replace placeholder entries in the full cache.
	for i, cached := range fullCache {
		if result, ok := newByHashType[cached.HashType]; ok && cached.Placeholder {
			result.Placeholder = false
			fullCache[i] = result
		}
	}

	if saveErr := saveBenchmarkCacheLocked(fullCache); saveErr != nil {
		agentstate.Logger.Warn("Failed to save benchmark cache after background update",
			"error", saveErr)
	}

	// Submit only the new real results.
	realResults := make([]display.BenchmarkResult, 0, len(newResults))
	for _, r := range newResults {
		r.Placeholder = false
		realResults = append(realResults, r)
	}

	if sendErr := m.sendBenchmarkResults(ctx, realResults); sendErr != nil {
		agentstate.Logger.Warn(
			"Failed to submit background benchmark results, cached for retry",
			"error", sendErr)
		return
	}

	// Mark submitted in cache and re-save.
	for i, cached := range fullCache {
		if _, ok := newByHashType[cached.HashType]; ok && !cached.Placeholder {
			fullCache[i].Submitted = true
		}
	}

	if saveErr := saveBenchmarkCacheLocked(fullCache); saveErr != nil {
		agentstate.Logger.Warn(
			"Failed to persist benchmark cache after background submission",
			"error", saveErr)
	}
}

// trySubmitFromCache attempts to load and submit cached benchmark results
// under cacheMu. Returns true if the caller should return nil (cache was
// found and handled — whether submission succeeded or failed).
func (m *Manager) trySubmitFromCache(ctx context.Context) bool {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	cached, loadErr := loadBenchmarkCacheLocked()
	if loadErr != nil {
		if errors.Is(loadErr, errCacheCorrupt) {
			agentstate.Logger.Warn("Benchmark cache was corrupt, will re-run benchmarks",
				"error", loadErr)
		} else {
			agentstate.Logger.Error(
				"Failed to read benchmark cache due to I/O error, will re-run benchmarks",
				"error", loadErr)
		}
	}

	if cached == nil {
		return false
	}

	if allSubmitted(cached) {
		agentstate.State.SetBenchmarksSubmitted(true)
		agentstate.Logger.Info("All cached benchmarks already submitted, skipping re-run")

		return true
	}

	pending := unsubmittedResults(cached)
	agentstate.Logger.Info("Found cached benchmark results, submitting unsubmitted to server",
		"total", len(cached), "pending", len(pending))

	if err := m.sendBenchmarkResults(ctx, pending); err != nil {
		agentstate.Logger.Warn(
			"Failed to submit cached benchmarks; task processing paused until submission succeeds",
			"error", err,
		)

		return true
	}

	// Mark all as submitted in-place — safe, single goroutine owns the slice.
	for i := range cached {
		cached[i].Submitted = true
	}

	if saveErr := saveBenchmarkCacheLocked(cached); saveErr != nil {
		agentstate.Logger.Warn(
			"Failed to persist benchmark cache after submission; benchmarks may re-submit on next restart",
			"error", saveErr,
		)
	}

	agentstate.State.SetBenchmarksSubmitted(true)
	agentstate.Logger.Info("Cached benchmarks successfully submitted to server")

	return true
}

// UpdateBenchmarks updates the benchmark metrics using Hashcat.
// It first checks for cached results from a previous run. If a valid cache
// exists (and the force-benchmark flag is not set), it attempts submission
// of only unsubmitted results. Submission failure of cached results is
// non-fatal — it returns nil and the cache is preserved for retry via
// TrySubmitCachedBenchmarks.
//
// When no cache exists (or force re-run is requested), it runs a new benchmark
// session and delegates to cacheAndSubmitBenchmarks, which may return an error
// if both the cache save and submission fail simultaneously.
func (m *Manager) UpdateBenchmarks(ctx context.Context) error {
	agentstate.State.SetBenchmarksSubmitted(false)

	// Try submitting from cache first (unless force re-run is requested)
	if !agentstate.State.GetForceBenchmarkRun() {
		if m.trySubmitFromCache(ctx) {
			return nil
		}
	}

	// No cache (or force re-run): run benchmarks from scratch
	benchmarkResults, err := m.runBenchmarks(ctx)
	if err != nil {
		return err
	}

	return m.cacheAndSubmitBenchmarks(ctx, benchmarkResults)
}

// cacheAndSubmitBenchmarks saves benchmark results to the disk cache and then
// submits any unsubmitted results to the server. If all results are already
// marked as submitted (e.g., from incremental batch submission), persists
// the cache for restart resilience and returns. On successful submission of
// all results, marks them as submitted, persists the cache, and sets
// BenchmarksSubmitted to true. If both the cache save and submission fail, it
// returns the submission error so the caller can fail fast. When the cache was
// saved but submission fails, it returns nil to allow retry via
// TrySubmitCachedBenchmarks.
func (m *Manager) cacheAndSubmitBenchmarks(ctx context.Context, benchmarkResults []display.BenchmarkResult) error {
	if allSubmitted(benchmarkResults) {
		agentstate.Logger.Info("All benchmarks already submitted incrementally, skipping bulk submission")

		if saveErr := saveBenchmarkCache(benchmarkResults); saveErr != nil {
			agentstate.Logger.Warn("Failed to persist already-submitted benchmark cache", "error", saveErr)
		}

		agentstate.State.SetBenchmarksSubmitted(true)

		return nil
	}

	// Save full results (with Submitted flags) to cache first
	cacheSaved := true

	if saveErr := saveBenchmarkCache(benchmarkResults); saveErr != nil {
		agentstate.Logger.Warn("Failed to cache benchmark results", "error", saveErr)
		cacheSaved = false
	}

	// Only send unsubmitted results
	pending := unsubmittedResults(benchmarkResults)
	if err := m.sendBenchmarkResults(ctx, pending); err != nil {
		if cacheSaved {
			agentstate.Logger.Warn(
				"Failed to submit benchmarks, cached results preserved for retry",
				"error", err,
			)

			return nil
		}

		// No cache was saved, so retry via TrySubmitCachedBenchmarks is impossible.
		// Return the error so the caller can fail fast or re-run benchmarks.
		agentstate.Logger.Error(
			"Failed to submit benchmarks and no cache was saved, cannot retry",
			"error", err,
		)

		return fmt.Errorf("benchmark submission failed with no cache for retry: %w", err)
	}

	// Mark all as submitted in-place — safe, single goroutine owns the slice.
	for i := range benchmarkResults {
		benchmarkResults[i].Submitted = true
	}

	if saveErr := saveBenchmarkCache(benchmarkResults); saveErr != nil {
		agentstate.Logger.Warn(
			"Failed to persist benchmark cache after submission; benchmarks may re-submit on next restart",
			"error", saveErr,
		)
	}

	agentstate.State.SetBenchmarksSubmitted(true)
	agentstate.Logger.Info("Benchmarks successfully submitted to server")

	return nil
}

// runBenchmarks creates and runs a hashcat benchmark session, returning the
// parsed results. Returns an error (reported as SeverityMajor to the server)
// if the session cannot be created or fails to produce results.
func (m *Manager) runBenchmarks(ctx context.Context) ([]display.BenchmarkResult, error) {
	additionalArgs := arch.GetAdditionalHashcatArgs()

	jobParams := hashcat.Params{
		AttackMode:                hashcat.AttackBenchmark,
		AdditionalArgs:            additionalArgs,
		BackendDevices:            m.BackendDevices,
		OpenCLDevices:             m.OpenCLDevices,
		EnableAdditionalHashTypes: agentstate.State.EnableAdditionalHashTypes,
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

	display.BenchmarksComplete(results)

	return results, nil
}

// runBenchmarkTask starts a hashcat benchmark session and processes its output.
// It returns a slice of benchmark results and the start error if the session
// failed to launch.
func (m *Manager) runBenchmarkTask(ctx context.Context, sess *hashcat.Session) ([]display.BenchmarkResult, error) {
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
	results []display.BenchmarkResult,
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
	results *[]display.BenchmarkResult,
	submittedUpTo int,
	procErr error,
) {
	drainStdout(sess, results)

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
func (m *Manager) processBenchmarkOutput(ctx context.Context, sess *hashcat.Session) []display.BenchmarkResult {
	// benchmarkResults is exclusively owned by the goroutine below until
	// waitChan is closed, at which point ownership transfers to the caller.
	var benchmarkResults []display.BenchmarkResult

	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)

		submittedUpTo := 0

		for {
			select {
			case <-ctx.Done():
				agentstate.Logger.Warn("Context cancelled during benchmark, killing session")

				if err := sess.Kill(); err != nil {
					agentstate.Logger.Error("Failed to kill benchmark session on cancellation", "error", err)
				}

				// Wait briefly for the process to exit and flush remaining stdout.
				// In tests with mock sessions (no process), this always hits the timeout.
				flushTimer := time.NewTimer(processFlushTimeout)
				select {
				case <-sess.DoneChan:
				case <-flushTimer.C:
				}
				flushTimer.Stop()

				// Best-effort drain: may miss lines still in flight between the
				// OS pipe buffer and the channel.
				drainStdout(sess, &benchmarkResults)

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
				handleBenchmarkStdOutLine(stdOutLine, &benchmarkResults)
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
