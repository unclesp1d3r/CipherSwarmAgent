// Package hashcat provides utilities for interacting with hashcat.
package hashcat

import (
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// Hashcat exit codes.
// Codes 0-4 and -1 are documented in hashcat source (types.h).
// Negative codes -2 through -7 are observed from specific failure modes
// and may vary by hashcat version; they are not officially documented.
const (
	ExitCodeSuccess        = 0  // Success/Cracked (official: RC_FINAL_OK)
	ExitCodeExhausted      = 1  // Exhausted (official: RC_FINAL_EXHAUSTED)
	ExitCodeAborted        = 2  // Aborted (official: RC_FINAL_ABORT)
	ExitCodeCheckpoint     = 3  // Aborted by checkpoint (official: RC_FINAL_ABORT_CHECKPOINT)
	ExitCodeRuntimeLimit   = 4  // Aborted by runtime limit (official: RC_FINAL_ABORT_RUNTIME)
	ExitCodeGeneralError   = -1 // General error (official: RC_FINAL_ERROR)
	ExitCodeGPUWatchdog    = -2 // GPU watchdog alarm (observed, not official)
	ExitCodeBackendAbort   = -3 // Backend abort (observed, not official)
	ExitCodeBackendChkpt   = -4 // Backend checkpoint abort (observed, not official)
	ExitCodeBackendRuntime = -5 // Backend runtime abort (observed, not official)
	ExitCodeSelftestFail   = -6 // Backend selftest fail (observed, not official)
	ExitCodeAutotuneFail   = -7 // Backend autotune fail (observed, not official)
)

// ExitCodeInfo contains information about a hashcat exit code.
type ExitCodeInfo struct {
	Category  ErrorCategory
	Severity  api.Severity
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
			Severity:  api.SeverityInfo,
			Retryable: false,
			Status:    "cracked",
			ExitCode:  exitCode,
		}
	case ExitCodeExhausted:
		return ExitCodeInfo{
			Category:  ErrorCategorySuccess,
			Severity:  api.SeverityInfo,
			Retryable: false,
			Status:    "exhausted",
			ExitCode:  exitCode,
		}
	case ExitCodeAborted:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  api.SeverityMinor,
			Retryable: true,
			Status:    "aborted",
			ExitCode:  exitCode,
		}
	case ExitCodeCheckpoint:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  api.SeverityMinor,
			Retryable: true,
			Status:    "checkpoint",
			ExitCode:  exitCode,
		}
	case ExitCodeRuntimeLimit:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  api.SeverityMinor,
			Retryable: true,
			Status:    "runtime_limit",
			ExitCode:  exitCode,
		}
	case ExitCodeGeneralError:
		return ExitCodeInfo{
			Category:  ErrorCategoryUnknown,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "error",
			ExitCode:  exitCode,
		}
	case ExitCodeGPUWatchdog:
		return ExitCodeInfo{
			Category:  ErrorCategoryDevice,
			Severity:  api.SeverityFatal,
			Retryable: false,
			Status:    "gpu_watchdog",
			ExitCode:  exitCode,
		}
	case ExitCodeBackendAbort:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "backend_abort",
			ExitCode:  exitCode,
		}
	case ExitCodeBackendChkpt:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "backend_checkpoint",
			ExitCode:  exitCode,
		}
	case ExitCodeBackendRuntime:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "backend_runtime",
			ExitCode:  exitCode,
		}
	case ExitCodeSelftestFail:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "selftest_fail",
			ExitCode:  exitCode,
		}
	case ExitCodeAutotuneFail:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "autotune_fail",
			ExitCode:  exitCode,
		}
	case -8, -9, -10, -11:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "backend_error",
			ExitCode:  exitCode,
		}
	default:
		return ExitCodeInfo{
			Category:  ErrorCategoryUnknown,
			Severity:  api.SeverityCritical,
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
