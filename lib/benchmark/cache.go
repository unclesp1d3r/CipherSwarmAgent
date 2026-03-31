package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
)

var cacheMu sync.Mutex //nolint:gochecknoglobals // guards benchmark cache file access across goroutines

// saveBenchmarkCache acquires cacheMu and saves the benchmark cache.
// For load-modify-save sequences, use cacheMu directly to hold the lock
// across the entire operation.
func saveBenchmarkCache(results []display.BenchmarkResult) error {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	return saveBenchmarkCacheLocked(results)
}

// saveBenchmarkCacheLocked marshals the benchmark results to JSON and writes them
// atomically to the cache file via a temporary file and rename. Returns an
// error on any failure; callers decide whether to treat it as fatal since
// benchmarks can be re-run on next startup.
// Requires: cacheMu must be held by the caller.
func saveBenchmarkCacheLocked(results []display.BenchmarkResult) error {
	cachePath := agentstate.State.BenchmarkCachePath
	if cachePath == "" {
		agentstate.Logger.Warn("Benchmark cache path not configured, skipping cache save")
		return errors.New("benchmark cache path not configured")
	}

	data, err := json.Marshal(results)
	if err != nil {
		agentstate.Logger.Warn("Failed to marshal benchmark results for caching", "error", err)
		return fmt.Errorf("failed to marshal benchmark cache: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(cachePath), ".benchmark-cache-*.tmp")
	if err != nil {
		agentstate.Logger.Warn("Failed to create temp cache file", "error", err)
		return fmt.Errorf("failed to create temp cache file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		agentstate.Logger.Warn("Failed to write benchmark cache temp file",
			"error", err, "path", tmpPath)
		return fmt.Errorf("failed to write benchmark cache: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		agentstate.Logger.Warn("Failed to close temp cache file",
			"error", err, "path", tmpPath)
		return fmt.Errorf("failed to close temp cache file: %w", err)
	}

	if err := os.Rename(tmpPath, cachePath); err != nil {
		agentstate.Logger.Warn("Failed to rename benchmark cache temp file",
			"error", err, "tmp_path", tmpPath, "cache_path", cachePath)
		if removeErr := os.Remove(tmpPath); removeErr != nil && !os.IsNotExist(removeErr) {
			agentstate.Logger.Warn("Failed to clean up temp cache file",
				"error", removeErr, "path", tmpPath)
		}
		return fmt.Errorf("failed to rename benchmark cache: %w", err)
	}

	info, statErr := os.Stat(cachePath)
	if statErr == nil {
		agentstate.Logger.Info("Benchmark results cached to disk",
			"path", cachePath, "size_bytes", info.Size())
	} else {
		agentstate.Logger.Debug("Benchmark cache saved but stat failed",
			"error", statErr, "path", cachePath)
	}

	return nil
}

// errCacheCorrupt indicates the benchmark cache file contained invalid JSON.
// Removal is attempted but may fail (logged as a warning). Callers should
// treat this as "no cache" and re-run.
var errCacheCorrupt = errors.New("benchmark cache file is corrupt")

// loadBenchmarkCache acquires cacheMu and loads the benchmark cache.
// For load-modify-save sequences, use cacheMu directly to hold the lock
// across the entire operation.
func loadBenchmarkCache() ([]display.BenchmarkResult, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	return loadBenchmarkCacheLocked()
}

// loadBenchmarkCacheLocked reads and unmarshals the cached benchmark results.
// Returns (nil, nil) when no cache exists: cache path is empty, file does
// not exist, or the result slice is empty. Returns (nil, errCacheCorrupt)
// when the file exists but contains invalid JSON (the file is removed).
// Returns a non-nil error for unexpected I/O failures (e.g., permission
// denied).
// Requires: cacheMu must be held by the caller.
func loadBenchmarkCacheLocked() ([]display.BenchmarkResult, error) {
	cachePath := agentstate.State.BenchmarkCachePath
	if cachePath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			agentstate.Logger.Debug("No benchmark cache file found", "path", cachePath)

			return nil, nil
		}

		agentstate.Logger.Warn("Failed to read benchmark cache file",
			"error", err, "path", cachePath)

		return nil, fmt.Errorf("failed to read benchmark cache: %w", err)
	}

	var results []display.BenchmarkResult
	if err := json.Unmarshal(data, &results); err != nil {
		agentstate.Logger.Warn("Benchmark cache file is corrupt, removing and will re-run benchmarks",
			"error", err, "path", cachePath)

		if removeErr := os.Remove(cachePath); removeErr != nil && !os.IsNotExist(removeErr) {
			agentstate.Logger.Warn("Failed to remove corrupt benchmark cache file",
				"error", removeErr, "path", cachePath)
		}

		return nil, fmt.Errorf("%w: %w", errCacheCorrupt, err)
	}

	if len(results) == 0 {
		agentstate.Logger.Debug("Benchmark cache file is empty, will re-run benchmarks",
			"path", cachePath)

		return nil, nil
	}

	agentstate.Logger.Info("Loaded benchmark results from cache",
		"path", cachePath, "result_count", len(results))

	return results, nil
}

// TrySubmitCachedBenchmarks attempts to submit previously cached benchmark
// results to the server. Returns false immediately if the force-benchmark
// flag is set (stale results should not be submitted). If all cached results
// are already marked as submitted, returns true immediately without
// re-persisting the cache. Otherwise, filters to only unsubmitted results,
// sends them, marks as submitted, and persists the updated cache. Returns
// true if all results are now submitted, false otherwise (cache is preserved
// for the next attempt).
func (m *Manager) TrySubmitCachedBenchmarks(ctx context.Context) bool {
	if agentstate.State.GetForceBenchmarkRun() {
		agentstate.Logger.Debug("Force benchmark flag set, skipping cache submission")
		return false
	}

	cacheMu.Lock()
	defer cacheMu.Unlock()

	cached, err := loadBenchmarkCacheLocked()
	if err != nil {
		agentstate.Logger.Warn("Failed to load benchmark cache for retry", "error", err)
		return false
	}

	if cached == nil {
		return false
	}

	if allSubmitted(cached) {
		agentstate.State.SetBenchmarksSubmitted(true)
		agentstate.Logger.Info("All cached benchmarks already submitted")

		return true
	}

	pending := unsubmittedResults(cached)
	if err := m.sendBenchmarkResults(ctx, pending); err != nil {
		agentstate.Logger.Warn("Cached benchmark submission failed, will retry next interval",
			"error", err)
		return false
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

// priorityHashTypes lists hash type IDs that should be benchmarked first during
// background benchmarking. These are common/important hash types that the server
// is most likely to request tasks for.
//
//nolint:gochecknoglobals // package-level priority ordering
var priorityHashTypes = [...]string{"0", "100", "1000"}

// loadPlaceholderResults loads cached benchmark results and returns only
// placeholder entries, sorted by priority (common hash types first, then
// ascending numeric order). Returns (nil, nil) when no placeholders exist.
// This function acquires cacheMu internally via loadBenchmarkCache — do NOT
// call while holding cacheMu or it will deadlock.
func loadPlaceholderResults() ([]display.BenchmarkResult, error) {
	cached, err := loadBenchmarkCache()
	if err != nil {
		return nil, err
	}

	if cached == nil {
		return nil, nil
	}

	var placeholders []display.BenchmarkResult
	for _, r := range cached {
		if r.Placeholder {
			placeholders = append(placeholders, r)
		}
	}

	if len(placeholders) == 0 {
		return nil, nil
	}

	// Build a priority index for O(1) lookups.
	priorityIndex := make(map[string]int, len(priorityHashTypes))
	for i, ht := range priorityHashTypes {
		priorityIndex[ht] = i
	}

	sort.Slice(placeholders, func(i, j int) bool {
		pi, iPriority := priorityIndex[placeholders[i].HashType]
		pj, jPriority := priorityIndex[placeholders[j].HashType]

		if iPriority && jPriority {
			return pi < pj
		}
		if iPriority {
			return true
		}
		if jPriority {
			return false
		}

		// Both non-priority: sort by numeric hash type ascending.
		// Unparseable hash types sort after parseable ones.
		ni, niErr := strconv.Atoi(placeholders[i].HashType)
		nj, njErr := strconv.Atoi(placeholders[j].HashType)

		if niErr != nil && njErr != nil {
			return placeholders[i].HashType < placeholders[j].HashType
		}
		if niErr != nil {
			return false // unparseable sorts last
		}
		if njErr != nil {
			return true // unparseable sorts last
		}

		return ni < nj
	})

	return placeholders, nil
}
