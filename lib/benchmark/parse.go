package benchmark

import (
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

const (
	benchmarkFieldCount = 6 // Expected number of fields in benchmark output line
)

// handleBenchmarkStdOutLine processes a line of benchmark output, extracting relevant data and appending it to result.
func handleBenchmarkStdOutLine(line string, results *[]display.BenchmarkResult) {
	fields := strings.Split(line, ":")
	if len(fields) != benchmarkFieldCount {
		agentstate.Logger.Debug("Unknown benchmark line", "line", line)

		return
	}

	result := display.BenchmarkResult{
		Device:     fields[0],
		HashType:   fields[1],
		RuntimeMs:  fields[3],
		HashTimeMs: fields[4],
		SpeedHs:    fields[5],
	}
	display.Benchmark(result)
	*results = append(*results, result)
}

// drainStdout reads and processes any remaining buffered lines from the
// session's StdoutLines channel. This ensures no benchmark results are lost
// when DoneChan fires before all buffered output has been consumed.
func drainStdout(sess *hashcat.Session, results *[]display.BenchmarkResult) {
	for {
		select {
		case line := <-sess.StdoutLines:
			handleBenchmarkStdOutLine(line, results)
		default:
			return
		}
	}
}

// handleBenchmarkStdErrLine processes each line from the benchmark's standard error output, logs it, and reports warnings to the server.
func handleBenchmarkStdErrLine(line string) {
	display.BenchmarkError(line)

	if strings.TrimSpace(line) != "" {
		cserrors.SendAgentError(line, nil, api.SeverityWarning)
	}
}
