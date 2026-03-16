// Package hashcat provides utilities for interacting with hashcat.
package hashcat

import (
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// Hashcat exit codes from types.h (hashcat 7.x).
// Positive codes are RC_FINAL_* (official), negative codes map to shell values
// 245-255 via unsigned conversion.
const (
	// ExitCodeSuccess indicates at least one hash was cracked.
	ExitCodeSuccess = 0 // RC_FINAL_OK
	// ExitCodeExhausted indicates the keyspace was fully exhausted.
	ExitCodeExhausted = 1 // RC_FINAL_EXHAUSTED
	// ExitCodeAborted indicates the session was aborted by the user.
	ExitCodeAborted = 2 // RC_FINAL_ABORT
	// ExitCodeCheckpoint indicates the session was aborted at a checkpoint.
	ExitCodeCheckpoint = 3 // RC_FINAL_ABORT_CHECKPOINT
	// ExitCodeRuntimeLimit indicates the session hit the runtime limit.
	ExitCodeRuntimeLimit = 4 // RC_FINAL_ABORT_RUNTIME
	// ExitCodeAbortFinish indicates the session was aborted after the finish flag was set.
	ExitCodeAbortFinish = 5 // RC_FINAL_ABORT_FINISH
	// ExitCodeGeneralError indicates a general error (STATUS_ERROR).
	ExitCodeGeneralError = -1 // shell: 255
	// ExitCodeRuntimeSkip indicates all backend devices were skipped at runtime.
	ExitCodeRuntimeSkip = -3 // shell: 253
	// ExitCodeMemoryHit indicates insufficient device memory.
	ExitCodeMemoryHit = -4 // shell: 252
	// ExitCodeKernelBuild indicates kernel compilation failed.
	ExitCodeKernelBuild = -5 // shell: 251
	// ExitCodeKernelCreate indicates kernel creation failed.
	ExitCodeKernelCreate = -6 // shell: 250
	// ExitCodeKernelAccel indicates autotune failed on all devices.
	ExitCodeKernelAccel = -7 // shell: 249
	// ExitCodeExtraSize indicates an extra_size backend issue.
	ExitCodeExtraSize = -8 // shell: 248
	// ExitCodeMixedWarnings indicates multiple backend issues.
	ExitCodeMixedWarnings = -9 // shell: 247
	// ExitCodeSelftestFail indicates the kernel self-test failed.
	ExitCodeSelftestFail = -11 // shell: 245
)

// ExitCodeInfo contains information about a hashcat exit code.
type ExitCodeInfo struct {
	Category  ErrorCategory
	Severity  api.Severity
	Retryable bool
	Status    string
	ExitCode  int
	Context   map[string]any
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
			Context:   map[string]any{"exit_code_name": "success"},
		}
	case ExitCodeExhausted:
		return ExitCodeInfo{
			Category:  ErrorCategorySuccess,
			Severity:  api.SeverityInfo,
			Retryable: false,
			Status:    "exhausted",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "exhausted"},
		}
	case ExitCodeAborted:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  api.SeverityMinor,
			Retryable: true,
			Status:    "aborted",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "aborted"},
		}
	case ExitCodeCheckpoint:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  api.SeverityMinor,
			Retryable: true,
			Status:    "checkpoint",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "checkpoint"},
		}
	case ExitCodeRuntimeLimit:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  api.SeverityMinor,
			Retryable: true,
			Status:    "runtime_limit",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "runtime_limit"},
		}
	case ExitCodeAbortFinish:
		return ExitCodeInfo{
			Category:  ErrorCategoryRetryable,
			Severity:  api.SeverityMinor,
			Retryable: true,
			Status:    "abort_finish",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "abort_finish"},
		}
	case ExitCodeGeneralError:
		return ExitCodeInfo{
			Category:  ErrorCategoryUnknown,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "error",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "general_error"},
		}
	case ExitCodeRuntimeSkip:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "runtime_skip",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "runtime_skip"},
		}
	case ExitCodeMemoryHit:
		return ExitCodeInfo{
			Category:  ErrorCategoryDevice,
			Severity:  api.SeverityFatal,
			Retryable: false,
			Status:    "memory_hit",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "memory_hit"},
		}
	case ExitCodeKernelBuild:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "kernel_build",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "kernel_build"},
		}
	case ExitCodeKernelCreate:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "kernel_create",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "kernel_create"},
		}
	case ExitCodeKernelAccel:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "kernel_accel",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "kernel_accel"},
		}
	case ExitCodeExtraSize:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "extra_size",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "extra_size"},
		}
	case ExitCodeMixedWarnings:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "mixed_warnings",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "mixed_warnings"},
		}
	case ExitCodeSelftestFail:
		return ExitCodeInfo{
			Category:  ErrorCategoryBackend,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "selftest_fail",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "selftest_fail"},
		}
	default:
		return ExitCodeInfo{
			Category:  ErrorCategoryUnknown,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Status:    "unknown",
			ExitCode:  exitCode,
			Context:   map[string]any{"exit_code_name": "unknown"},
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
