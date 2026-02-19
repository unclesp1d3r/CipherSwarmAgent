package lib

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

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
	var benchmarks []api.HashcatBenchmark //nolint:prealloc // Size unknown until after parsing

	for _, result := range benchmarkResults {
		benchmark, err := createBenchmark(result)
		if err != nil {
			continue
		}

		benchmarks = append(benchmarks, benchmark)
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
// Creates a Hashcat session with benchmark parameters and initiates the benchmarking process.
// Logs the session start, runs the benchmark task, and updates the results.
// If any errors occur during session creation or result sending, logs the errors and returns them.
func UpdateBenchmarks() error {
	agentstate.State.BenchmarksSubmitted = false

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
		return cserrors.LogAndSendError("Failed to create benchmark session", err, api.SeverityMajor, nil)
	}

	agentstate.Logger.Debug("Starting benchmark session", "cmdline", sess.CmdLine())

	displayBenchmarkStarting()

	benchmarkResult, done := runBenchmarkTask(sess)
	if done {
		return nil
	}

	displayBenchmarksComplete(benchmarkResult)

	if err := sendBenchmarkResults(benchmarkResult); err != nil {
		return cserrors.LogAndSendError("Error updating benchmarks", err, api.SeverityCritical, nil)
	}

	agentstate.State.BenchmarksSubmitted = true
	agentstate.Logger.Info("Benchmarks successfully submitted to server")

	return nil
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

	waitChan := make(chan int)

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
