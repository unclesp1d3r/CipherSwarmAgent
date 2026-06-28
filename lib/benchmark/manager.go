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
	"github.com/unclesp1d3r/cipherswarmagent/lib/devices"
)

var errBadResponse = errors.New("bad response from server")

// Manager handles benchmark operations including running benchmarks,
// submitting results, and managing the benchmark cache.
type Manager struct {
	agentsClient api.AgentsClient
	DeviceConfig devices.DeviceConfig
	// Config holds injected path and benchmark-mode configuration for this Manager.
	Config Config
}

// NewManager creates a new benchmark Manager with the given API client.
func NewManager(agentsClient api.AgentsClient) *Manager {
	return &Manager{agentsClient: agentsClient}
}

// deviceManager returns the DeviceManager from the config, or nil.
// Used by benchmark output handlers for device name lookups.
func (m *Manager) deviceManager() *devices.DeviceManager {
	return m.DeviceConfig.DeviceManager()
}

// unsubmittedResults returns a new slice containing only benchmark results
// that have not yet been submitted to the server.
func unsubmittedResults(results []Result) []Result {
	var unsubmitted []Result
	for _, r := range results {
		if !r.Submitted {
			unsubmitted = append(unsubmitted, r)
		}
	}

	return unsubmitted
}

// allSubmitted reports whether every result in the slice has been submitted.
// Returns true for an empty or nil slice (nothing to submit = done).
func allSubmitted(results []Result) bool {
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
func markSubmitted(results []Result, startIdx, endIdx int) {
	for i := startIdx; i < endIdx && i < len(results); i++ {
		results[i].Submitted = true
	}
}

// sendBenchmarkResults sends the collected benchmark results to a server endpoint.
// It converts each Result into a HashcatBenchmark and appends them to a slice.
// If the conversion fails for a result, it continues to the next result.
// Creates a SubmitBenchmarkJSONRequestBody with the HashcatBenchmarks slice and submits it via the API client interface.
// Returns an error if submission or the response received is not successful.
func (m *Manager) sendBenchmarkResults(ctx context.Context, benchmarkResults []Result) error {
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

	switch res.StatusCode() {
	case http.StatusOK:
		if res.JSON200 == nil {
			return fmt.Errorf(
				"%w: server returned 200 without valid receipt body",
				errBadResponse,
			)
		}

		return validateReceipt(len(benchmarks), res.JSON200)
	case http.StatusNoContent:
		agentstate.Logger.Debug("Server returned 204 (legacy, no receipt)")

		return nil
	default:
		return fmt.Errorf("%w: %s", errBadResponse, res.Status())
	}
}

// createBenchmark converts a Result to an api.HashcatBenchmark struct.
// It handles the conversion of string fields in Result to appropriate types.
// Returns a HashcatBenchmark instance and an error if any conversion fails.
func createBenchmark(result Result) (api.HashcatBenchmark, error) {
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
func (m *Manager) SubmitCapabilityResults(ctx context.Context, results []Result) error {
	return m.cacheAndSubmitBenchmarks(ctx, results)
}

// idleCheckInterval is the polling interval for checking if the agent is idle
// before starting a background benchmark for the next hash type.
const idleCheckInterval = 30 * time.Second

// RunBackgroundBenchmarks replaces placeholder cache entries with real benchmark
// results by running hashcat --benchmark -m <type> for each placeholder hash type.
// It waits for the agent to be idle (per the injected isIdle predicate) before each
// run and submits results incrementally. The method is designed to run as a
// long-lived goroutine.
func (m *Manager) RunBackgroundBenchmarks(ctx context.Context, isIdle func() bool) {
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
		if cancelled := m.waitForIdle(ctx, isIdle); cancelled {
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

// waitForIdle blocks until the injected isIdle predicate reports the agent is
// idle, or the context is cancelled. Returns true if the context was cancelled.
func (m *Manager) waitForIdle(ctx context.Context, isIdle func() bool) bool {
	for {
		if isIdle() {
			return false
		}

		timer := time.NewTimer(idleCheckInterval)
		select {
		case <-timer.C:
			// Timer already fired; no cleanup needed.
		case <-ctx.Done():
			timer.Stop()
			return true
		}
	}
}

// updateCacheWithResults reloads the full benchmark cache, replaces matching
// placeholder entries with real results, saves the cache, and submits the
// new results to the server. Holds cacheMu for the entire load-modify-save
// sequence to prevent concurrent cache corruption.
func (m *Manager) updateCacheWithResults(
	ctx context.Context,
	newResults []Result,
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
		realResults := make([]Result, 0, len(newResults))
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

	// Build lookup from new results by hash type + device composite key.
	type resultKey struct {
		hashType string
		device   string
	}

	newByKey := make(map[resultKey]Result, len(newResults))
	for _, r := range newResults {
		newByKey[resultKey{hashType: r.HashType, device: r.Device}] = r
	}

	// Replace placeholder entries in the full cache.
	matched := make(map[resultKey]bool, len(newByKey))
	for i, cached := range fullCache {
		key := resultKey{hashType: cached.HashType, device: cached.Device}
		if result, ok := newByKey[key]; ok && cached.Placeholder {
			result.Placeholder = false
			fullCache[i] = result
			matched[key] = true
		}
	}

	// Append new results whose hash type + device had no placeholder in the cache.
	for key, result := range newByKey {
		if !matched[key] {
			result.Placeholder = false
			fullCache = append(fullCache, result)
		}
	}

	if saveErr := saveBenchmarkCacheLocked(fullCache); saveErr != nil {
		agentstate.Logger.Warn("Failed to save benchmark cache after background update",
			"error", saveErr)
	}

	// Submit only the new real results.
	realResults := make([]Result, 0, len(newResults))
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
		key := resultKey{hashType: cached.HashType, device: cached.Device}
		if _, ok := newByKey[key]; ok && !cached.Placeholder {
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
func (m *Manager) cacheAndSubmitBenchmarks(ctx context.Context, benchmarkResults []Result) error {
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
