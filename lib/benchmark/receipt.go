package benchmark

import (
	"fmt"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// validateReceipt checks the server's benchmark receipt against what was sent.
// Returns nil if receipt counts are non-negative and the server accepted at
// least some entries. Logs warnings for count mismatches and partial failures
// but does not return errors for these — they are advisory only, and returning
// errors would cause infinite retry loops since the same data always produces
// the same result.
//
// Returns errBadResponse for:
//   - Negative counts (malformed server response)
//   - Zero received when benchmarks were sent (protocol failure)
//   - All entries rejected (total server-side rejection)
func validateReceipt(sentCount int, receipt *api.BenchmarkReceipt) error {
	if receipt.ReceivedCount < 0 || receipt.ProcessedCount < 0 || receipt.FailedCount < 0 {
		return fmt.Errorf(
			"%w: receipt contains negative counts (received=%d, processed=%d, failed=%d)",
			errBadResponse, receipt.ReceivedCount, receipt.ProcessedCount, receipt.FailedCount,
		)
	}

	agentstate.Logger.Info("Benchmark submission receipt",
		"sent", sentCount,
		"received", receipt.ReceivedCount,
		"processed", receipt.ProcessedCount,
		"failed", receipt.FailedCount,
	)

	// Server received nothing — protocol-level failure, not deduplication.
	if receipt.ReceivedCount == 0 && sentCount > 0 {
		return fmt.Errorf(
			"%w: server acknowledged 0 of %d submitted benchmarks",
			errBadResponse, sentCount,
		)
	}

	// Server rejected every entry — re-running benchmarks may produce
	// different data, so retrying is appropriate (unlike count mismatches).
	if receipt.FailedCount > 0 && receipt.FailedCount == receipt.ReceivedCount {
		return fmt.Errorf(
			"%w: server rejected all %d benchmark entries",
			errBadResponse, receipt.FailedCount,
		)
	}

	// Count mismatch is advisory — server may legitimately deduplicate.
	if receipt.ReceivedCount != sentCount {
		agentstate.Logger.Warn("Server received count differs from submitted count",
			"sent", sentCount, "received", receipt.ReceivedCount,
		)
	}

	// Partial failures are advisory — we cannot identify which entries failed.
	if receipt.FailedCount > 0 {
		args := []any{"failed_count", receipt.FailedCount}
		if receipt.Message != nil {
			args = append(args, "message", *receipt.Message)
		}

		agentstate.Logger.Warn("Server rejected some benchmark entries", args...)
	} else if receipt.Message != nil {
		agentstate.Logger.Debug("Benchmark receipt message", "message", *receipt.Message)
	}

	return nil
}
