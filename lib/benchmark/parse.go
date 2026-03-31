package benchmark

import (
	"context"
	"regexp"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

const (
	benchmarkFieldCount = 6 // Expected number of fields in benchmark output line
	hashInfoMatchGroups = 2 // Expected number of match groups in hashInfoLineRe (full match + capture)
)

// hashInfoLineRe matches the leading numeric hash type ID in --hash-info --machine-readable output.
// Lines look like: "0 | MD5 | Raw Hash" or "100 | SHA1 | Raw Hash".
var hashInfoLineRe = regexp.MustCompile(`^\s*(\d+)\s*\|`) //nolint:gochecknoglobals // package-level compiled regex

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

// parseHashInfoLine extracts the hash type ID from a --hash-info --machine-readable
// output line. Returns the hash type ID string and true if the line matches, or
// ("", false) if the line is not a hash-info data line.
func parseHashInfoLine(line string) (string, bool) {
	matches := hashInfoLineRe.FindStringSubmatch(line)
	if len(matches) < hashInfoMatchGroups {
		return "", false
	}

	return strings.TrimSpace(matches[1]), true
}

// handleBenchmarkStdErrLine processes a classified error from the benchmark's stderr,
// logs it, and reports to the server. Info/success messages are skipped since they are
// advisory lines routed from stdout (not actual errors).
func handleBenchmarkStdErrLine(ctx context.Context, errInfo hashcat.ErrorInfo) {
	if errInfo.Category == hashcat.ErrorCategoryInfo ||
		errInfo.Category == hashcat.ErrorCategorySuccess {
		return
	}

	display.BenchmarkError(errInfo.Message)

	if strings.TrimSpace(errInfo.Message) != "" {
		cserrors.SendAgentError(ctx, errInfo.Message, nil, errInfo.Severity,
			cserrors.WithClassification(errInfo.Category.String(), errInfo.Retryable),
			cserrors.WithContext(errInfo.Context))
	}
}
