package benchmark

import (
	"fmt"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// validateReceipt checks the server's benchmark receipt against what was sent.
// Returns nil if the receipt is acceptable (all processed, or partial with
// logged warnings). Logs warnings for count mismatches and partial failures
// but does not return errors for these cases — they are advisory only, and
// returning errors would cause infinite retry loops since the same data
// always produces the same result.
//
// Returns errBadResponse only for clearly invalid receipts (negative counts).
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

	if receipt.ReceivedCount != sentCount {
		agentstate.Logger.Warn("Server received count differs from submitted count",
			"sent", sentCount, "received", receipt.ReceivedCount,
		)
	}

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
