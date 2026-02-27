package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
)

const (
	cacheFilePermissions = 0o600 // File permissions for benchmark cache
)

// saveBenchmarkCache marshals the benchmark results to JSON and writes them
// atomically to the cache file via a temporary file and rename. Returns an
// error on any failure; callers decide whether to treat it as fatal since
// benchmarks can be re-run on next startup.
func saveBenchmarkCache(results []display.BenchmarkResult) error {
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

	tmpPath := cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, cacheFilePermissions); err != nil {
		agentstate.Logger.Warn("Failed to write benchmark cache temp file",
			"error", err, "path", tmpPath)
		return fmt.Errorf("failed to write benchmark cache: %w", err)
	}

	if err := os.Rename(tmpPath, cachePath); err != nil {
		agentstate.Logger.Warn("Failed to rename benchmark cache temp file",
			"error", err, "tmp_path", tmpPath, "cache_path", cachePath)
		// Clean up the temp file on rename failure
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
		agentstate.Logger.Info("Benchmark results cached to disk", "path", cachePath)
	}

	return nil
}

// loadBenchmarkCache reads and unmarshals the cached benchmark results.
// Returns (nil, nil) when no usable cache exists: cache path is empty, file
// does not exist, file contains corrupt JSON, or the result slice is empty.
// Returns a non-nil error only for unexpected I/O failures (e.g., permission
// denied).
func loadBenchmarkCache() ([]display.BenchmarkResult, error) {
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
		return nil, nil
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

// clearBenchmarkCache removes the cache file. Silently ignores "not exist"
// errors (idempotent), and logs a warning for other removal failures without
// propagating the error.
func clearBenchmarkCache() {
	cachePath := agentstate.State.BenchmarkCachePath
	if cachePath == "" {
		return
	}

	if err := os.Remove(cachePath); err != nil {
		if !os.IsNotExist(err) {
			agentstate.Logger.Warn("Failed to remove benchmark cache file",
				"error", err, "path", cachePath)
		}
	} else {
		agentstate.Logger.Debug("Benchmark cache file cleared", "path", cachePath)
	}
}

// TrySubmitCachedBenchmarks attempts to submit previously cached benchmark
// results to the server. Returns false immediately if the force-benchmark
// flag is set (stale results should not be submitted). Filters to only
// unsubmitted results, sends them, marks as submitted, and persists the
// updated cache. Returns true if all results are now submitted, false
// otherwise (cache is preserved for the next attempt).
func (m *Manager) TrySubmitCachedBenchmarks(ctx context.Context) bool {
	if agentstate.State.ForceBenchmarkRun {
		agentstate.Logger.Debug("Force benchmark flag set, skipping cache submission")
		return false
	}

	cached, err := loadBenchmarkCache()
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

	// Mark all as submitted and persist updated cache
	for i := range cached {
		cached[i].Submitted = true
	}

	if saveErr := saveBenchmarkCache(cached); saveErr != nil {
		agentstate.Logger.Warn("Failed to update benchmark cache after submission", "error", saveErr)
	}

	agentstate.State.SetBenchmarksSubmitted(true)
	agentstate.Logger.Info("Cached benchmarks successfully submitted to server")

	return true
}
