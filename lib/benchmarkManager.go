package lib

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

const (
	benchmarkFieldCount = 6 // Expected number of fields in benchmark output line
)

// sendBenchmarkResults sends the collected benchmark results to a server endpoint.
// It converts each benchmarkResult into a HashcatBenchmark and appends them to a slice.
// If the conversion fails for a result, it continues to the next result.
// Creates a SubmitBenchmarkJSONRequestBody with the HashcatBenchmarks slice and submits it via the API client interface.
// Returns an error if submission or the response received is not successful.
func sendBenchmarkResults(benchmarkResults []benchmarkResult) error {
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

	res, err := agentstate.State.APIClient.Agents().SubmitBenchmark(
		context.Background(),
		agentstate.State.AgentID,
		results,
	)
	if err != nil {
		return err
	}

	if res.StatusCode() == http.StatusNoContent {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrBadResponse, res.Status())
}

// createBenchmark converts a benchmarkResult to an api.HashcatBenchmark struct.
// It handles the conversion of string fields in benchmarkResult to appropriate types.
// Returns a HashcatBenchmark instance and an error if any conversion fails.
func createBenchmark(result benchmarkResult) (api.HashcatBenchmark, error) {
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
// exists (and the force-benchmark flag is not set), it attempts submission.
// Submission failure of cached results is non-fatal — it returns nil and
// the cache is preserved for retry via TrySubmitCachedBenchmarks.
//
// When no cache exists (or force re-run is requested), it runs a new benchmark
// session and delegates to cacheAndSubmitBenchmarks, which may return an error
// if both the cache save and submission fail simultaneously.
func UpdateBenchmarks() error {
	agentstate.State.BenchmarksSubmitted = false

	// Try submitting from cache first (unless force re-run is requested)
	if !viper.GetBool("force_benchmark_run") {
		cached, loadErr := loadBenchmarkCache()
		if loadErr != nil {
			agentstate.Logger.Warn("Failed to load benchmark cache, will re-run benchmarks",
				"error", loadErr)
		}

		if cached != nil {
			agentstate.Logger.Info("Found cached benchmark results, submitting to server")

			if err := sendBenchmarkResults(cached); err != nil {
				agentstate.Logger.Warn(
					"Failed to submit cached benchmarks; task processing paused until submission succeeds",
					"error", err,
				)
				return nil
			}

			clearBenchmarkCache()
			agentstate.State.BenchmarksSubmitted = true
			agentstate.Logger.Info("Cached benchmarks successfully submitted to server")

			return nil
		}
	}

	// No cache (or force re-run): run benchmarks from scratch
	benchmarkResults, err := runBenchmarks()
	if err != nil {
		return err
	}

	return cacheAndSubmitBenchmarks(benchmarkResults)
}

// cacheAndSubmitBenchmarks saves benchmark results to the disk cache and then
// submits them to the server. On successful submission, clears the cache file
// and sets BenchmarksSubmitted to true. If both the cache save and submission
// fail, it returns the submission error so the caller can fail fast. When the
// cache was saved but submission fails, it returns nil to allow retry via
// TrySubmitCachedBenchmarks.
func cacheAndSubmitBenchmarks(benchmarkResults []benchmarkResult) error {
	cacheSaved := true

	if saveErr := saveBenchmarkCache(benchmarkResults); saveErr != nil {
		agentstate.Logger.Warn("Failed to cache benchmark results", "error", saveErr)
		cacheSaved = false
	}

	if err := sendBenchmarkResults(benchmarkResults); err != nil {
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

	clearBenchmarkCache()
	agentstate.State.BenchmarksSubmitted = true
	agentstate.Logger.Info("Benchmarks successfully submitted to server")

	return nil
}

// runBenchmarks creates and runs a hashcat benchmark session, returning the
// parsed results. Returns an error (reported as SeverityMajor to the server)
// if the session cannot be created or fails to produce results.
func runBenchmarks() ([]benchmarkResult, error) {
	additionalArgs := arch.GetAdditionalHashcatArgs()

	jobParams := hashcat.Params{
		AttackMode:                hashcat.AttackBenchmark,
		AdditionalArgs:            additionalArgs,
		BackendDevices:            Configuration.Config.BackendDevices,
		OpenCLDevices:             Configuration.Config.OpenCLDevices,
		EnableAdditionalHashTypes: agentstate.State.EnableAdditionalHashTypes,
	}

	sess, err := hashcat.NewHashcatSession("benchmark", jobParams)
	if err != nil {
		return nil, cserrors.LogAndSendError(
			"Failed to create benchmark session", err, api.SeverityMajor, nil,
		)
	}

	agentstate.Logger.Debug("Starting benchmark session", "cmdline", sess.CmdLine())
	displayBenchmarkStarting()

	results, done := runBenchmarkTask(sess)
	if done {
		return nil, cserrors.LogAndSendError(
			"Benchmark session failed to produce results",
			stderrors.New("benchmark task failed"),
			api.SeverityMajor,
			nil,
		)
	}

	displayBenchmarksComplete(results)

	return results, nil
}

// runBenchmarkTask starts a hashcat benchmark session and processes its output.
// It returns a slice of benchmark results and a boolean indicating an error state.
func runBenchmarkTask(sess *hashcat.Session) ([]benchmarkResult, bool) {
	err := sess.Start()
	if err != nil {
		agentstate.Logger.Error("Failed to start benchmark session", "error", err)

		return nil, true
	}

	var benchmarkResults []benchmarkResult

	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)

		for {
			select {
			case stdOutLine := <-sess.StdoutLines:
				handleBenchmarkStdOutLine(stdOutLine, &benchmarkResults)
			case stdErrLine := <-sess.StderrMessages:
				handleBenchmarkStdErrLine(stdErrLine)
			case statusUpdate := <-sess.StatusUpdates:
				agentstate.Logger.Debug("Benchmark status update", "status", statusUpdate) // This should never happen
			case crackedHash := <-sess.CrackedHashes:
				agentstate.Logger.Debug("Benchmark cracked hash", "hash", crackedHash) // This should never happen
			case err := <-sess.DoneChan:
				if err != nil {
					agentstate.Logger.Error("Benchmark session failed", "error", err)
					SendAgentError(err.Error(), nil, api.SeverityFatal)
				}

				return
			}
		}
	}()

	<-waitChan

	return benchmarkResults, false
}

// handleBenchmarkStdOutLine processes a line of benchmark output, extracting relevant data and appending it to result.
func handleBenchmarkStdOutLine(line string, results *[]benchmarkResult) {
	fields := strings.Split(line, ":")
	if len(fields) != benchmarkFieldCount {
		agentstate.Logger.Debug("Unknown benchmark line", "line", line)

		return
	}

	result := benchmarkResult{
		Device:     fields[0],
		HashType:   fields[1],
		RuntimeMs:  fields[3],
		HashTimeMs: fields[4],
		SpeedHs:    fields[5],
	}
	displayBenchmark(result)
	*results = append(*results, result)
}

// handleBenchmarkStdErrLine processes each line from the benchmark's standard error output, logs it, and reports warnings to the server.
func handleBenchmarkStdErrLine(line string) {
	displayBenchmarkError(line)

	if strings.TrimSpace(line) != "" {
		SendAgentError(line, nil, api.SeverityWarning)
	}
}
