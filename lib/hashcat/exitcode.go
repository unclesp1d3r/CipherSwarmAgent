// Package hashcat provides utilities for interacting with hashcat.
package hashcat

import (
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
)

// Hashcat exit codes as documented in hashcat documentation.
const (
	ExitCodeSuccess        = 0  // Success/Cracked
	ExitCodeExhausted      = 1  // Exhausted
	ExitCodeAborted        = 2  // Aborted
	ExitCodeCheckpoint     = 3  // Aborted by checkpoint
	ExitCodeRuntimeLimit   = 4  // Aborted by runtime limit
	ExitCodeGeneralError   = -1 // General error
	ExitCodeGPUWatchdog    = -2 // GPU watchdog alarm
	ExitCodeBackendAbort   = -3 // Backend abort
	ExitCodeBackendChkpt   = -4 // Backend checkpoint abort
	ExitCodeBackendRuntime = -5 // Backend runtime abort
	ExitCodeSelftestFail   = -6 // Backend selftest fail
	ExitCodeAutotuneFail   = -7 // Backend autotune fail
)

// ExitCodeInfo contains information about a hashcat exit code.
type ExitCodeInfo struct {
	Category  ErrorCategory
	Severity  operations.Severity
	Retryable bool
	Status    string
	ExitCode  int
}

// ClassifyExitCode classifies a hashcat exit code and returns detailed information.
func ClassifyExitCode(exitCode int) ExitCodeInfo {
	switch exitCode {
	case ExitCodeSuccess:
		return ExitCodeInfo{
			Category:  ErrorCategorySuccess,
			Severity:  operations.SeverityInfo,
			Retryable: false,
			Status:    "cracked",
			ExitCode:  exitCode,
		}
	case ExitCodeExhausted:
		return ExitCodeInfo{
			Category:  ErrorCategorySuccess,
			Severity:  operations.SeverityInfo,
			Retryable: false,
			Status:    "exhausted",
			ExitCode:  exitCode,
		}
	case ExitCodeAborted:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  operations.SeverityMinor,
			Retryable: true,
			Status:    "aborted",
			ExitCode:  exitCode,
		}
	case ExitCodeCheckpoint:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  operations.SeverityMinor,
			Retryable: true,
			Status:    "checkpoint",
			ExitCode:  exitCode,
		}
	case ExitCodeRuntimeLimit:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  operations.SeverityMinor,
			Retryable: true,
			Status:    "runtime_limit",
			ExitCode:  exitCode,
		}
	case ExitCodeGeneralError:
		return ExitCodeInfo{
			Category:  ErrorCategoryUnknown,
			Severity:  operations.SeverityCritical,
			Retryable: false,
			Status:    "error",
			ExitCode:  exitCode,
		}
	case ExitCodeGPUWatchdog:
		return ExitCodeInfo{
			Category:  ErrorCategoryDevice,
			Severity:  operations.SeverityFatal,
			Retryable: false,
			Status:    "gpu_watchdog",
			ExitCode:  exitCode,
		}
	case ExitCodeBackendAbort:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  operations.SeverityCritical,
			Retryable: false,
			Status:    "backend_abort",
			ExitCode:  exitCode,
		}
	case ExitCodeBackendChkpt:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  operations.SeverityCritical,
			Retryable: false,
			Status:    "backend_checkpoint",
			ExitCode:  exitCode,
		}
	case ExitCodeBackendRuntime:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  operations.SeverityCritical,
			Retryable: false,
			Status:    "backend_runtime",
			ExitCode:  exitCode,
		}
	case ExitCodeSelftestFail:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  operations.SeverityCritical,
			Retryable: false,
			Status:    "selftest_fail",
			ExitCode:  exitCode,
		}
	case ExitCodeAutotuneFail:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  operations.SeverityCritical,
			Retryable: false,
			Status:    "autotune_fail",
			ExitCode:  exitCode,
		}
	case -8, -9, -10, -11:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  operations.SeverityCritical,
			Retryable: false,
			Status:    "backend_error",
			ExitCode:  exitCode,
		}
	default:
		return ExitCodeInfo{
			Category:  ErrorCategoryUnknown,
			Severity:  operations.SeverityCritical,
			Retryable: false,
			Status:    "unknown",
			ExitCode:  exitCode,
		}
	}
}

// IsExhausted returns true if the exit code indicates hashcat exhausted the keyspace.
func IsExhausted(exitCode int) bool {
	return exitCode == ExitCodeExhausted
}

// IsSuccess returns true if the exit code indicates hashcat cracked at least one hash.
func IsSuccess(exitCode int) bool {
	return exitCode == ExitCodeSuccess
}

// IsNormalCompletion returns true if the exit code indicates normal completion
// (either cracked or exhausted).
func IsNormalCompletion(exitCode int) bool {
	return exitCode == ExitCodeSuccess || exitCode == ExitCodeExhausted
}
