package benchmark

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/devices"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

const (
	// benchmarkMatchGroups is the expected number of match groups from benchmarkLineRe
	// (full match + 6 capture groups).
	benchmarkMatchGroups = 7
	hashInfoMatchGroups  = 2 // Expected number of match groups in hashInfoLineRe (full match + capture)
)

// Submatch indices for benchmarkLineRe capture groups.
const (
	bmGroupDevice   = 1
	bmGroupHashType = 2
	// bmGroupHashName = 3 — hash name is captured but not stored (display-only in hashcat).
	bmGroupRuntime  = 4
	bmGroupHashTime = 5
	bmGroupSpeed    = 6
)

// benchmarkLineRe parses hashcat --machine-readable --benchmark output.
// Format: device_id:hash_type:hash_name:runtime_ms:hash_time_ms:speed_hs
//
// Non-greedy (.+?) for hash_name: backtracking against trailing \d+ groups
// correctly handles hypothetical colon-containing names. In practice,
// benchmark hash names are simple labels (MD5, NTLM, etc.) and never
// contain colons (verified from hashcat source terminal.c:~3880).
//
// The speed group uses a structured float pattern that rejects nonsense
// like "e.e.e+++" while accepting integers, decimals, and scientific notation.
//
//nolint:gochecknoglobals // package-level compiled regex
var benchmarkLineRe = regexp.MustCompile(
	`^(\d+):(\d+):(.+?):(\d+):(\d+):([0-9]+(?:\.[0-9]*)?(?:[eE][+-]?\d+)?)$`,
)

// hashInfoLineRe matches the leading numeric hash type ID in --hash-info --machine-readable output.
// Lines look like: "0 | MD5 | Raw Hash" or "100 | SHA1 | Raw Hash".
var hashInfoLineRe = regexp.MustCompile(`^\s*(\d+)\s*\|`) //nolint:gochecknoglobals // package-level compiled regex

// handleBenchmarkStdOutLine processes a line of benchmark output, extracting relevant data and appending it to result.
// When dm is non-nil, it enriches the result with the human-readable device name looked up from the DeviceManager.
func handleBenchmarkStdOutLine(line string, results *[]display.BenchmarkResult, dm *devices.DeviceManager) {
	matches := benchmarkLineRe.FindStringSubmatch(line)
	if len(matches) != benchmarkMatchGroups {
		agentstate.Logger.Debug("Unknown benchmark line", "length", len(line))

		return
	}

	result := display.BenchmarkResult{
		Device:     matches[bmGroupDevice],
		HashType:   matches[bmGroupHashType],
		RuntimeMs:  matches[bmGroupRuntime],
		HashTimeMs: matches[bmGroupHashTime],
		SpeedHs:    matches[bmGroupSpeed],
	}

	if dm != nil {
		if id, err := strconv.Atoi(matches[bmGroupDevice]); err == nil {
			if dev, found := dm.GetDevice(id); found {
				result.DeviceName = dev.Name
			}
		}
	}

	display.Benchmark(result)
	*results = append(*results, result)
}

// drainStdout reads and processes any remaining buffered lines from the
// session's StdoutLines channel. This ensures no benchmark results are lost
// when DoneChan fires before all buffered output has been consumed.
func drainStdout(sess *hashcat.Session, results *[]display.BenchmarkResult, dm *devices.DeviceManager) {
	for {
		select {
		case line := <-sess.StdoutLines:
			handleBenchmarkStdOutLine(line, results, dm)
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
