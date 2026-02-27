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

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

const (
	benchmarkBatchSize = 10 // benchmarkBatchSize is the number of benchmark results to accumulate before submitting an incremental batch to the server.
)

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
	if !agentstate.State.ForceBenchmarkRun {
		cached, loadErr := loadBenchmarkCache()
		if loadErr != nil {
			agentstate.Logger.Warn("Failed to load benchmark cache, will re-run benchmarks",
				"error", loadErr)
		}

		if cached != nil {
			if allSubmitted(cached) {
				agentstate.State.SetBenchmarksSubmitted(true)
				agentstate.Logger.Info("All cached benchmarks already submitted, skipping re-run")

				return nil
			}

			pending := unsubmittedResults(cached)
			agentstate.Logger.Info("Found cached benchmark results, submitting unsubmitted to server",
				"total", len(cached), "pending", len(pending))

			if err := m.sendBenchmarkResults(ctx, pending); err != nil {
				agentstate.Logger.Warn(
					"Failed to submit cached benchmarks; task processing paused until submission succeeds",
					"error", err,
				)

				return nil
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
// submits any unsubmitted results to the server. On successful submission of
// all results, marks them as submitted, persists the cache, and sets
// BenchmarksSubmitted to true. If both the cache save and submission fail, it
// returns the submission error so the caller can fail fast. When the cache was
// saved but submission fails, it returns nil to allow retry via
// TrySubmitCachedBenchmarks.
func (m *Manager) cacheAndSubmitBenchmarks(ctx context.Context, benchmarkResults []display.BenchmarkResult) error {
	if allSubmitted(benchmarkResults) {
		agentstate.Logger.Info("All benchmarks already submitted incrementally, skipping bulk submission")
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

	// Mark all as submitted and persist cache so restarts skip re-running
	for i := range benchmarkResults {
		benchmarkResults[i].Submitted = true
	}

	if saveErr := saveBenchmarkCache(benchmarkResults); saveErr != nil {
		agentstate.Logger.Warn("Failed to update benchmark cache after submission", "error", saveErr)
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

	//nolint:contextcheck // NewHashcatSession does not accept context
	sess, err := hashcat.NewHashcatSession("benchmark", jobParams)
	if err != nil {
		return nil, cserrors.LogAndSendError(
			ctx, "Failed to create benchmark session", err, api.SeverityMajor, nil,
		)
	}

	agentstate.Logger.Debug("Starting benchmark session", "cmdline", sess.CmdLine())
	display.BenchmarkStarting()

	results, done := m.runBenchmarkTask(ctx, sess)
	if done {
		return nil, cserrors.LogAndSendError(
			ctx,
			"Benchmark session failed to produce results",
			errors.New("benchmark task failed"),
			api.SeverityMajor,
			nil,
		)
	}

	display.BenchmarksComplete(results)

	return results, nil
}

// runBenchmarkTask starts a hashcat benchmark session and processes its output.
// It returns a slice of benchmark results and a boolean indicating an error state.
func (m *Manager) runBenchmarkTask(ctx context.Context, sess *hashcat.Session) ([]display.BenchmarkResult, bool) {
	err := sess.Start()
	if err != nil {
		agentstate.Logger.Error("Failed to start benchmark session", "error", err)

		return nil, true
	}

	return m.processBenchmarkOutput(ctx, sess), false
}

// processBenchmarkOutput reads from the session's channels, collects benchmark
// results, and submits them incrementally in batches. It marks each result as
// Submitted after successful server acknowledgment and persists the cache after
// each batch. Returns the collected results (with Submitted flags set).
func (m *Manager) processBenchmarkOutput(ctx context.Context, sess *hashcat.Session) []display.BenchmarkResult {
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

				sess.Cleanup()

				return
			case stdOutLine := <-sess.StdoutLines:
				handleBenchmarkStdOutLine(stdOutLine, &benchmarkResults)

				if len(benchmarkResults)-submittedUpTo >= benchmarkBatchSize {
					batch := benchmarkResults[submittedUpTo:]
					if sendErr := m.sendBenchmarkResults(ctx, batch); sendErr != nil {
						agentstate.Logger.Warn("Failed to submit incremental benchmark batch", "error", sendErr)
					} else {
						markSubmitted(benchmarkResults, submittedUpTo, len(benchmarkResults))
						submittedUpTo = len(benchmarkResults)

						if saveErr := saveBenchmarkCache(benchmarkResults); saveErr != nil {
							agentstate.Logger.Warn("Failed to save benchmark cache after batch", "error", saveErr)
						}
					}
				}
			case stdErrLine := <-sess.StderrMessages:
				handleBenchmarkStdErrLine(ctx, stdErrLine)
			case statusUpdate := <-sess.StatusUpdates:
				agentstate.Logger.Debug("Benchmark status update", "status", statusUpdate) // This should never happen
			case crackedHash := <-sess.CrackedHashes:
				agentstate.Logger.Debug("Benchmark cracked hash", "hash", crackedHash) // This should never happen
			case err := <-sess.DoneChan:
				// Drain any remaining buffered stdout lines before final submission
				drainStdout(sess, &benchmarkResults)

				if err != nil {
					agentstate.Logger.Error("Benchmark session failed", "error", err)
					cserrors.SendAgentError(ctx, err.Error(), nil, api.SeverityFatal)
				}

				// Submit any remaining unsubmitted results
				if len(benchmarkResults) > submittedUpTo {
					batch := benchmarkResults[submittedUpTo:]
					if sendErr := m.sendBenchmarkResults(ctx, batch); sendErr != nil {
						agentstate.Logger.Warn("Failed to submit final benchmark batch", "error", sendErr)
					} else {
						markSubmitted(benchmarkResults, submittedUpTo, len(benchmarkResults))
					}
				}

				agentstate.State.SetBenchmarksSubmitted(allSubmitted(benchmarkResults))

				// Always persist cache with Submitted flags for retry
				if saveErr := saveBenchmarkCache(benchmarkResults); saveErr != nil {
					agentstate.Logger.Warn("Failed to save final benchmark cache", "error", saveErr)
				}

				sess.Cleanup()

				return
			}
		}
	}()

	<-waitChan

	return benchmarkResults
}
