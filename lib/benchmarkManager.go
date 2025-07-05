package lib

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// sendBenchmarkResults sends the collected benchmark results to a server endpoint.
// It converts each benchmarkResult into a HashcatBenchmark and appends them to a slice.
// If the conversion fails for a result, it continues to the next result.
// Creates a SubmitBenchmarkRequestBody with the HashcatBenchmarks slice and submits it via SdkClient.
// Returns an error if submission or the response received is not successful.
func sendBenchmarkResults(benchmarkResults []benchmarkResult) error {
	var benchmarks []components.HashcatBenchmark //nolint:prealloc

	for _, result := range benchmarkResults {
		benchmark, err := createBenchmark(result)
		if err != nil {
			continue
		}
		benchmarks = append(benchmarks, benchmark)
	}

	results := operations.SubmitBenchmarkRequestBody{
		HashcatBenchmarks: benchmarks,
	}

	res, err := shared.State.SdkClient.Agents.SubmitBenchmark(shared.State.Context, shared.State.AgentID, results)
	if err != nil {
		return err
	}

	if res.StatusCode == http.StatusNoContent {
		return nil
	}

	return fmt.Errorf("bad response: %s", res.RawResponse.Status)
}

// createBenchmark converts a benchmarkResult to a components.HashcatBenchmark struct.
// It handles the conversion of string fields in benchmarkResult to appropriate types.
// Returns a HashcatBenchmark instance and an error if any conversion fails.
func createBenchmark(result benchmarkResult) (components.HashcatBenchmark, error) {
	hashType, err := strconv.Atoi(result.HashType)
	if err != nil {
		return components.HashcatBenchmark{}, fmt.Errorf("failed to convert HashType: %w", err)
	}
	runtimeMs, err := strconv.Atoi(result.RuntimeMs)
	if err != nil {
		return components.HashcatBenchmark{}, fmt.Errorf("failed to convert RuntimeMs: %w", err)
	}
	speedHs, err := strconv.ParseFloat(result.SpeedHs, 64)
	if err != nil {
		return components.HashcatBenchmark{}, fmt.Errorf("failed to convert SpeedHs: %w", err)
	}
	device, err := strconv.Atoi(result.Device)
	if err != nil {
		return components.HashcatBenchmark{}, fmt.Errorf("failed to convert Device: %w", err)
	}

	return components.HashcatBenchmark{
		HashType:  int64(hashType),
		Runtime:   int64(runtimeMs),
		HashSpeed: speedHs,
		Device:    int64(device),
	}, nil
}

// UpdateBenchmarks updates the benchmark metrics using Hashcat.
// Creates a Hashcat session with benchmark parameters and initiates the benchmarking process.
// Logs the session start, runs the benchmark task, and updates the results.
// If any errors occur during session creation or result sending, logs the errors and returns them.
func UpdateBenchmarks() error {
	jobParams := hashcat.Params{
		AttackMode:                hashcat.AttackBenchmark,
		AdditionalArgs:            arch.GetAdditionalHashcatArgs(),
		BackendDevices:            Configuration.Config.BackendDevices,
		OpenCLDevices:             Configuration.Config.OpenCLDevices,
		EnableAdditionalHashTypes: shared.State.EnableAdditionalHashTypes,
	}

	sess, err := hashcat.NewHashcatSession("benchmark", jobParams)
	if err != nil {
		return cserrors.LogAndSendError("Failed to create benchmark session", err, operations.SeverityMajor, nil)
	}
	shared.Logger.Debug("Starting benchmark session", "cmdline", sess.CmdLine())

	displayBenchmarkStarting()
	benchmarkResult, done := runBenchmarkTask(sess)
	if done {
		return nil
	}
	displayBenchmarksComplete(benchmarkResult)
	if err := sendBenchmarkResults(benchmarkResult); err != nil {
		return cserrors.LogAndSendError("Error updating benchmarks", err, operations.SeverityCritical, nil)
	}

	return nil
}

// runBenchmarkTask starts a hashcat benchmark session and processes its output.
// It returns a slice of benchmark results and a boolean indicating an error state.
func runBenchmarkTask(sess *hashcat.Session) ([]benchmarkResult, bool) {
	err := sess.Start()
	if err != nil {
		shared.Logger.Error("Failed to start benchmark session", "error", err)

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
				shared.Logger.Debug("Benchmark status update", "status", statusUpdate) // This should never happen
			case crackedHash := <-sess.CrackedHashes:
				shared.Logger.Debug("Benchmark cracked hash", "hash", crackedHash) // This should never happen
			case err := <-sess.DoneChan:
				if err != nil {
					shared.Logger.Error("Benchmark session failed", "error", err)
					SendAgentError(err.Error(), nil, operations.SeverityFatal)
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
	if len(fields) != 6 {
		shared.Logger.Debug("Unknown benchmark line", "line", line)

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
		SendAgentError(line, nil, operations.SeverityWarning)
	}
}
