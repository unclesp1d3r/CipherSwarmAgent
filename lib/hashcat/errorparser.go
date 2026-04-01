// Package hashcat provides utilities for interacting with hashcat.
package hashcat

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// ErrorCategory represents the classification of a hashcat error.
type ErrorCategory int

const (
	// ErrorCategoryUnknown is for unrecognized error patterns.
	ErrorCategoryUnknown ErrorCategory = iota
	// ErrorCategorySuccess is for normal completion states (not actual errors).
	ErrorCategorySuccess
	// ErrorCategoryInfo is for informational messages (not actual errors).
	ErrorCategoryInfo
	// ErrorCategoryWarning is for warnings that don't stop operation.
	ErrorCategoryWarning
	// ErrorCategoryRetryable is for transient errors that may succeed on retry.
	ErrorCategoryRetryable
	// ErrorCategoryHashFormat is for hash file/format issues (permanent).
	ErrorCategoryHashFormat
	// ErrorCategoryFileAccess is for missing/corrupted files (permanent).
	ErrorCategoryFileAccess
	// ErrorCategoryDevice is for GPU/hardware errors.
	ErrorCategoryDevice
	// ErrorCategoryConfiguration is for invalid parameters.
	ErrorCategoryConfiguration
	// ErrorCategoryBackend is for OpenCL/CUDA backend errors.
	ErrorCategoryBackend
)

// String returns the string representation of an ErrorCategory.
func (c ErrorCategory) String() string {
	switch c {
	case ErrorCategoryUnknown:
		return "unknown"
	case ErrorCategorySuccess:
		return "success"
	case ErrorCategoryInfo:
		return "info"
	case ErrorCategoryWarning:
		return "warning"
	case ErrorCategoryRetryable:
		return "retryable"
	case ErrorCategoryHashFormat:
		return "hash_format"
	case ErrorCategoryFileAccess:
		return "file_access"
	case ErrorCategoryDevice:
		return "device"
	case ErrorCategoryConfiguration:
		return "configuration"
	case ErrorCategoryBackend:
		return "backend"
	default:
		return "unknown"
	}
}

// ErrorInfo contains information about a classified error line.
type ErrorInfo struct {
	Category  ErrorCategory
	Severity  api.Severity
	Retryable bool
	Message   string
	Context   map[string]any
}

// contextExtractor extracts structured context from a matched line.
// The submatch slice comes from regexp.FindStringSubmatch (index 0 is the full match).
type contextExtractor func(line string, submatch []string) map[string]any

// errorPattern represents a pattern for matching error lines.
type errorPattern struct {
	pattern   *regexp.Regexp
	category  ErrorCategory
	severity  api.Severity
	retryable bool
	extract   contextExtractor
}

// Compile all patterns at init time for performance.
//
// NOTE: Pattern order matters: more specific patterns must appear before more general ones,
// because matching is performed in slice order and the first matching pattern is used.
//
//nolint:gochecknoglobals // Patterns are intentionally global for performance
var errorPatterns = []errorPattern{
	// Stdout summary lines: hashcat emits "* <parser_error>: N/N hashes" via event_log_advice
	// to stdout. A single generic pattern covers all parser error types (Token length exception,
	// Separator unmatched, Line-length exception, Salt-length exception, Hash-value exception,
	// Signature unmatched, etc.) so new parser errors are caught automatically.
	{
		regexp.MustCompile(`^\* (.+): (\d+)/(\d+) hashes`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractSummaryContext,
	},

	// Stdout per-hash errors with file path context.
	// v7.x format: "Hash parsing error in hashfile: '<file>' on line <N> (<hash>): <error>"
	{
		regexp.MustCompile(
			`^Hash parsing error in hashfile: '([^']+)' on line (\d+) \(([^)]*)\): (.+)`,
		),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractHashfileContext,
	},
	// v7.x single-hash format: "Hash parsing error: '<hash>': <error>"
	{
		regexp.MustCompile(`^Hash parsing error: '([^']+)': (.+)`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractSingleHashContext,
	},
	// Hashfile changed during runtime (must be BEFORE generic v6.x Hashfile pattern)
	{
		regexp.MustCompile(`Hashfile '([^']+)' on line \d+.*File changed during runtime`),
		ErrorCategoryHashFormat,
		api.SeverityWarning,
		false,
		nil,
	},
	// v6.x format: "Hashfile '<file>' on line <N> (<hash>): <error>"
	{
		regexp.MustCompile(`^Hashfile '([^']+)' on line (\d+) \(([^)]*)\): (.+)`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractHashfileContext,
	},
	// v6.x file-level error: "Hashfile '<file>': <OS error>" (no line number)
	{
		regexp.MustCompile(`^Hashfile '([^']+)': (.+)`),
		ErrorCategoryFileAccess,
		api.SeverityCritical,
		false,
		extractHashfileAccessContext,
	},

	// Machine-readable per-hash errors: "<file>:<line>:<hash>:<parser_error>"
	// Emitted when --machine-readable is active. Covers all strparser() strings
	// (PA_000-PA_047) including LUKS, hccapx, TrueCrypt/VeraCrypt, and CryptoAPI errors.
	// Uses non-greedy (.+?) for the file path so hashes containing colons
	// (e.g., MD5:salt, PBKDF2 sha256:20000:salt) don't consume into the file capture.
	// The (\d+) anchor on line number prevents most false positives.
	// Fourth group ([^:]+) matches the error text after the last colon, which is safe
	// because no strparser() error string contains colons. This lets the third group
	// (.+) greedily capture hash types with colons (e.g., sha256:20000:salt).
	{
		regexp.MustCompile(`^(.+?):(\d+):(.+):([^:]+)$`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractMachineReadableContext,
	},

	// Advisory line emitted before single-hash errors on stdout.
	{
		regexp.MustCompile(`^Hash was parsed as a commandline argument`),
		ErrorCategoryInfo,
		api.SeverityInfo,
		false,
		nil,
	},

	// Stdout explanatory context lines (indented help text from hashcat's parser error block).
	// These lines follow summary/per-hash error lines and provide advisory context such as
	// "This error happens if...", "malformed...", "--username", "--dynamic-x" hints, etc.
	// A broad 2+-space-indented matcher covers current and future wording variants so they
	// classify as informational rather than falling through to unknown/retryable.
	{regexp.MustCompile(`^ {2}\S`), ErrorCategoryInfo, api.SeverityInfo, false, nil},

	// Hash format errors on stderr (non-retryable, critical).
	// v6.x stderr format: "Hash '<hash>': <parser_error>"
	// A single pattern covers all strparser() error strings.
	{
		regexp.MustCompile(`^Hash '([^']+)': (.+)`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractSingleHashContext,
	},
	{
		regexp.MustCompile(`(?i)No hashes loaded`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractTerminalContext("no_hashes_loaded"),
	},
	{
		regexp.MustCompile(`(?i)hashfile is empty or corrupt`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractTerminalContext("hashfile_empty_or_corrupt"),
	},
	{
		regexp.MustCompile(`(?i)Hash-file exception`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		staticContext("hash_file_exception"),
	},
	{
		regexp.MustCompile(`(?i)No hash-mode matches the structure`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractTerminalContext("no_hash_mode_match"),
	},
	// Hash count limits (stderr)
	{
		regexp.MustCompile(`Not enough hashes loaded - minimum is (\d+)`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractHashCountContext,
	},
	{
		regexp.MustCompile(`Too many hashes loaded - maximum is (\d+)`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
		extractHashCountContext,
	},
	// Failed to parse hashes using a specific format (stdout warning)
	{
		regexp.MustCompile(`Failed to parse hashes using the '(.+)' format`),
		ErrorCategoryHashFormat,
		api.SeverityWarning,
		false,
		staticContext("parse_format_failed"),
	},

	// Per-device self-test failures (must be BEFORE generic self-test abort)
	{
		regexp.MustCompile(`\* Device #(\d+): ATTENTION! .+ kernel self-test failed`),
		ErrorCategoryBackend,
		api.SeverityFatal,
		false,
		extractDeviceWarningContext,
	},
	// Self-test hash parsing error (stderr)
	{
		regexp.MustCompile(`Self-test hash parsing error: (.+)`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		staticContext("selftest_parse_error"),
	},
	// Self-test / autotune abort (fatal, non-retryable)
	{
		regexp.MustCompile(`Aborting session due to kernel self-test failure`),
		ErrorCategoryBackend,
		api.SeverityFatal,
		false,
		staticContext("selftest_failure"),
	},
	{
		regexp.MustCompile(`Aborting session due to kernel autotune failures?`),
		ErrorCategoryBackend,
		api.SeverityFatal,
		false,
		staticContext("autotune_failure"),
	},

	// Kernel build failures (non-retryable)
	{
		regexp.MustCompile(
			`\* Device #(\d+): Kernel (.+) build failed`,
		),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		extractKernelBuildContext,
	},
	// Kernel create failures (stdout warning, distinct from build failures)
	{
		regexp.MustCompile(`\* Device #(\d+): Kernel (.+) create failed`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		extractKernelBuildContext,
	},
	{
		regexp.MustCompile(`clBuildProgram\(\): (CL_BUILD_PROGRAM_FAILURE)`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		extractBackendContextWithType("cl_build_program_failure", "OpenCL"),
	},
	// No backend platform found (stderr, fatal)
	{
		regexp.MustCompile(`ATTENTION! No (?:OpenCL|Metal|HIP|CUDA).+platform found`),
		ErrorCategoryBackend,
		api.SeverityFatal,
		false,
		extractTerminalContext("no_backend_platform"),
	},
	// Outdated NVIDIA driver (stderr)
	{
		regexp.MustCompile(`Outdated NVIDIA .+ driver version`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		staticContext("outdated_nvidia_driver"),
	},
	// Unstable OpenCL driver (stderr)
	{
		regexp.MustCompile(`\* Device #(\d+): Unstable OpenCL driver detected`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		extractDeviceWarningContext,
	},
	// TDR kernel runtime (stderr)
	{
		regexp.MustCompile(`Kernel minimum runtime larger than default TDR`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		staticContext("tdr_exceeded"),
	},
	// Runtime library initialization failure (stdout warning)
	{
		regexp.MustCompile(`Failed to initialize .+ runtime library`),
		ErrorCategoryBackend,
		api.SeverityWarning,
		true,
		staticContext("runtime_init_failed"),
	},

	// Module / hash-mode errors (non-retryable)
	{
		regexp.MustCompile(`Cannot load module`),
		ErrorCategoryConfiguration,
		api.SeverityCritical,
		false,
		staticContext("cannot_load_module"),
	},
	{
		regexp.MustCompile(`Invalid hash-mode '?(\d+)'? selected`),
		ErrorCategoryConfiguration,
		api.SeverityCritical,
		false,
		extractHashModeContext,
	},

	// Temperature abort (retryable — transient thermal condition)
	{
		regexp.MustCompile(`Temperature limit on GPU #(\d+) reached`),
		ErrorCategoryDevice,
		api.SeverityWarning,
		true,
		extractTemperatureContext,
	},
	// Driver temperature throttle (stdout warning, distinct from temperature abort)
	{
		regexp.MustCompile(`Driver temperature threshold met on GPU #(\d+)`),
		ErrorCategoryDevice,
		api.SeverityWarning,
		true,
		extractTemperatureContext,
	},

	// Device memory errors — specific patterns first
	// "Not enough allocatable device memory" (stderr)
	{
		regexp.MustCompile(`\* Device #(\d+): Not enough allocatable device memory`),
		ErrorCategoryDevice,
		api.SeverityFatal,
		false,
		extractDeviceMemoryContext,
	},
	// "Not enough allocatable memory (RAM) for this ruleset" (stderr)
	{
		regexp.MustCompile(`Not enough allocatable memory .+ for this ruleset`),
		ErrorCategoryDevice,
		api.SeverityFatal,
		false,
		extractTerminalContext("ruleset_memory"),
	},
	// General device memory errors (non-retryable, fatal)
	// Using non-greedy .*? to prevent catastrophic backtracking on long lines
	{
		regexp.MustCompile(
			`Device #(\d+):.*?(?i)(out of memory|memory allocation|MEMORY)`,
		),
		ErrorCategoryDevice,
		api.SeverityFatal,
		false,
		extractDeviceMemoryContext,
	},

	// Device warnings (retryable)
	// Using non-greedy .*? to prevent performance issues on long lines
	{
		regexp.MustCompile(`Device #(\d+):.*?WARNING`),
		ErrorCategoryDevice,
		api.SeverityWarning,
		true,
		extractDeviceWarningContext,
	},
	{regexp.MustCompile(`(?i)hwmon.*temperature`), ErrorCategoryDevice, api.SeverityWarning, true, nil},

	// File access errors (non-retryable, critical)
	{regexp.MustCompile(`ERROR:.*can't open`), ErrorCategoryFileAccess, api.SeverityCritical, false, nil},
	{
		regexp.MustCompile(`ERROR:.*No such file or directory`),
		ErrorCategoryFileAccess,
		api.SeverityCritical,
		false,
		nil,
	},
	{
		regexp.MustCompile(`No usable dictionary file found`),
		ErrorCategoryFileAccess,
		api.SeverityCritical,
		false,
		extractTerminalContext("no_dictionary"),
	},
	{
		regexp.MustCompile(`No valid rules left`),
		ErrorCategoryFileAccess,
		api.SeverityCritical,
		false,
		extractTerminalContext("no_valid_rules"),
	},
	// Empty input file — requires path separator to avoid false positives
	{
		regexp.MustCompile(`^.+: empty file\.$`),
		ErrorCategoryFileAccess,
		api.SeverityCritical,
		false,
		staticContext("empty_input_file"),
	},

	// Backend errors - memory (fatal)
	{
		regexp.MustCompile(`OpenCL API.*?(CL_OUT_OF_HOST_MEMORY)`),
		ErrorCategoryBackend,
		api.SeverityFatal,
		false,
		extractBackendAPIContext("OpenCL"),
	},
	{
		regexp.MustCompile(`OpenCL API.*?(CL_OUT_OF_RESOURCES)`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		extractBackendAPIContext("OpenCL"),
	},

	// Backend errors - general (critical)
	{
		regexp.MustCompile(`OpenCL API.*?(CL_\w+)`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		extractBackendAPIContext("OpenCL"),
	},
	{
		regexp.MustCompile(`cuDeviceGet\(\).*?(CUDA_ERROR_\w+)`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		extractBackendAPIContext("CUDA"),
	},
	{
		regexp.MustCompile(`hipDeviceGet\(\).*?(HIP_ERROR_\w+)`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		extractBackendAPIContext("HIP"),
	},
	{
		regexp.MustCompile(`(?i)Metal API`),
		ErrorCategoryBackend,
		api.SeverityCritical,
		false,
		extractBackendContextWithType("metal_api_error", "Metal"),
	},

	// Configuration errors (non-retryable, critical)
	{regexp.MustCompile(`ERROR:.*Invalid argument`), ErrorCategoryConfiguration, api.SeverityCritical, false, nil},
	{regexp.MustCompile(`ERROR:.*Option.*requires`), ErrorCategoryConfiguration, api.SeverityCritical, false, nil},
	{regexp.MustCompile(`ERROR:.*Mixed.*not allowed`), ErrorCategoryConfiguration, api.SeverityCritical, false, nil},
	{
		regexp.MustCompile(`Integer overflow detected in keyspace`),
		ErrorCategoryConfiguration,
		api.SeverityCritical,
		false,
		staticContext("keyspace_overflow"),
	},
	{
		regexp.MustCompile(`No password candidates received in stdin mode`),
		ErrorCategoryConfiguration,
		api.SeverityCritical,
		false,
		staticContext("stdin_timeout"),
	},

	// Session / restore issues
	{regexp.MustCompile(`ERROR:.*Cannot read.*\.restore`), ErrorCategoryRetryable, api.SeverityMinor, true, nil},
	{regexp.MustCompile(`Incompatible restore-file version`), ErrorCategoryRetryable, api.SeverityMinor, true, nil},
	{
		regexp.MustCompile(`Restore value is greater than keyspace`),
		ErrorCategoryConfiguration,
		api.SeverityCritical,
		false,
		staticContext("restore_exceeds_keyspace"),
	},
	// Already running instance (stderr)
	{
		regexp.MustCompile(`Already an instance .+ running on pid (\d+)`),
		ErrorCategoryConfiguration,
		api.SeverityCritical,
		false,
		extractPidContext,
	},

	// Info/warnings (retryable)
	{regexp.MustCompile(`(?i)Skipping invalid or unsupported`), ErrorCategoryInfo, api.SeverityInfo, true, nil},
	{regexp.MustCompile(`(?i)Approaching final keyspace`), ErrorCategoryInfo, api.SeverityInfo, true, nil},
	{regexp.MustCompile(`Runtime limit reached, aborting`), ErrorCategoryInfo, api.SeverityMinor, true, nil},
	{regexp.MustCompile(`Cannot convert rule for .+ device`), ErrorCategoryInfo, api.SeverityInfo, true, nil},
	{
		regexp.MustCompile(`ATTENTION! Pure .+ backend kernels selected`),
		ErrorCategoryInfo,
		api.SeverityInfo,
		false,
		nil,
	},
	{
		regexp.MustCompile(`Hash-mode was not specified .+ auto-detect`),
		ErrorCategoryInfo,
		api.SeverityInfo,
		false,
		nil,
	},
	{regexp.MustCompile(`Byte Order Mark .+ detected`), ErrorCategoryInfo, api.SeverityInfo, false, nil},
	{regexp.MustCompile(`^Warning:`), ErrorCategoryWarning, api.SeverityMinor, true, nil},
}

// ClassifyStderr classifies a stderr/stdout error line from hashcat and returns error information.
func ClassifyStderr(line string) ErrorInfo {
	for _, p := range errorPatterns {
		submatch := p.pattern.FindStringSubmatch(line)
		if submatch == nil {
			continue
		}

		info := ErrorInfo{
			Category:  p.category,
			Severity:  p.severity,
			Retryable: p.retryable,
			Message:   line,
		}

		if p.extract != nil {
			info.Context = p.extract(line, submatch)
		}

		return info
	}

	// Handle generic ERROR: prefix without specific pattern
	if strings.HasPrefix(line, "ERROR:") {
		return ErrorInfo{
			Category:  ErrorCategoryUnknown,
			Severity:  api.SeverityCritical,
			Retryable: false,
			Message:   line,
		}
	}

	// Default: unknown message, minor severity, retryable.
	// Design decision: We use Minor severity for unrecognized stderr because hashcat
	// often emits informational or progress messages to stderr that aren't actual errors.
	// The ERROR: prefix check above catches explicit errors with Critical severity.
	// If a serious unrecognized error occurs, it will likely be accompanied by a
	// non-zero exit code which is classified separately with appropriate severity.
	return ErrorInfo{
		Category:  ErrorCategoryUnknown,
		Severity:  api.SeverityMinor,
		Retryable: true,
		Message:   line,
	}
}

// --- Context extractor functions ---

// extractSummaryContext extracts from "* <error_type>: N/N hashes" lines.
func extractSummaryContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type": normalizeErrorType(submatch[1]),
	}

	if affected, err := strconv.Atoi(submatch[2]); err == nil {
		ctx["affected_count"] = affected
	}

	if total, err := strconv.Atoi(submatch[3]); err == nil {
		ctx["total_count"] = total
	}

	return ctx
}

// extractHashfileContext extracts from per-hash file error lines.
// submatch: [full, file, lineNum, hashPreview, errorType]
func extractHashfileContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type": normalizeErrorType(submatch[4]),
		"hashfile":   submatch[1],
	}

	if lineNum, err := strconv.Atoi(submatch[2]); err == nil {
		ctx["line_number"] = lineNum
	}

	if submatch[3] != "" {
		ctx["hash_preview"] = truncateHash(submatch[3])
	}

	return ctx
}

// extractSingleHashContext extracts from "Hash '<hash>': <error>" lines.
// submatch: [full, hash, errorType]
func extractSingleHashContext(_ string, submatch []string) map[string]any {
	return map[string]any{
		"error_type":   normalizeErrorType(submatch[2]),
		"hash_preview": truncateHash(submatch[1]),
	}
}

// extractMachineReadableContext extracts from machine-readable per-hash error lines.
// submatch: [full, file, lineNum, hash, errorType]
func extractMachineReadableContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type":   normalizeErrorType(submatch[4]),
		"hashfile":     submatch[1],
		"hash_preview": truncateHash(submatch[3]),
	}

	if lineNum, err := strconv.Atoi(submatch[2]); err == nil {
		ctx["line_number"] = lineNum
	}

	return ctx
}

// extractTerminalContext returns an extractor for terminal errors (e.g., "No hashes loaded").
func extractTerminalContext(errorType string) contextExtractor {
	return func(_ string, _ []string) map[string]any {
		return map[string]any{
			"error_type": errorType,
			"terminal":   true,
		}
	}
}

// staticContext returns an extractor that provides a fixed error_type.
func staticContext(errorType string) contextExtractor {
	return func(_ string, _ []string) map[string]any {
		return map[string]any{
			"error_type": errorType,
		}
	}
}

// extractHashfileAccessContext extracts from "Hashfile '<file>': <OS error>" lines.
// submatch: [full, file, osError]
func extractHashfileAccessContext(_ string, submatch []string) map[string]any {
	return map[string]any{
		"error_type": "hashfile_access_error",
		"hashfile":   submatch[1],
		"os_error":   submatch[2],
	}
}

// extractKernelBuildContext extracts device ID and kernel path from kernel build failures.
// submatch: [full, deviceID, kernelPath]
func extractKernelBuildContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type": "kernel_build_failed",
	}

	if deviceID, err := strconv.Atoi(submatch[1]); err == nil {
		ctx["device_id"] = deviceID
	}

	ctx["kernel_path"] = submatch[2]

	return ctx
}

// extractHashModeContext extracts hash mode from "Invalid hash-mode" errors.
// submatch: [full, hashMode]
func extractHashModeContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type": "invalid_hash_mode",
	}

	if hashMode, err := strconv.Atoi(submatch[1]); err == nil {
		ctx["hash_mode"] = hashMode
	}

	return ctx
}

// extractHashCountContext extracts the hash count limit from "Not enough/Too many hashes" errors.
// submatch: [full, limit]
func extractHashCountContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type": "hash_count_limit",
	}

	if limit, err := strconv.Atoi(submatch[1]); err == nil {
		ctx["hash_count_limit"] = limit
	}

	return ctx
}

// extractPidContext extracts a process ID from "Already an instance running" errors.
// submatch: [full, pid]
func extractPidContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type": "already_running",
	}

	if pid, err := strconv.Atoi(submatch[1]); err == nil {
		ctx["pid"] = pid
	}

	return ctx
}

// extractTemperatureContext extracts GPU device ID from temperature abort.
// submatch: [full, deviceID]
func extractTemperatureContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type": "temperature_limit",
	}

	if deviceID, err := strconv.Atoi(submatch[1]); err == nil {
		ctx["device_id"] = deviceID
	}

	return ctx
}

// extractDeviceMemoryContext extracts device ID from memory errors.
// submatch: [full, deviceID, memoryErrorType]
func extractDeviceMemoryContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type": "device_memory",
	}

	if deviceID, err := strconv.Atoi(submatch[1]); err == nil {
		ctx["device_id"] = deviceID
	}

	return ctx
}

// extractDeviceWarningContext extracts device ID from device warnings.
// submatch: [full, deviceID]
func extractDeviceWarningContext(_ string, submatch []string) map[string]any {
	ctx := map[string]any{
		"error_type": "device_warning",
	}

	if deviceID, err := strconv.Atoi(submatch[1]); err == nil {
		ctx["device_id"] = deviceID
	}

	return ctx
}

// extractBackendContextWithType returns an extractor for backend errors with a known error type.
// Used for patterns where the error type is fixed (e.g., CL_BUILD_PROGRAM_FAILURE, Metal API)
// but we still want consistent backend_api metadata.
func extractBackendContextWithType(errorType, backendAPI string) contextExtractor {
	return func(_ string, submatch []string) map[string]any {
		ctx := map[string]any{
			"error_type":  errorType,
			"backend_api": backendAPI,
		}

		if len(submatch) > 1 {
			ctx["api_error"] = submatch[1]
		}

		return ctx
	}
}

// extractBackendAPIContext returns an extractor for backend API errors.
func extractBackendAPIContext(backendAPI string) contextExtractor {
	return func(_ string, submatch []string) map[string]any {
		ctx := map[string]any{
			"error_type":  "backend_api_error",
			"backend_api": backendAPI,
		}

		if len(submatch) > 1 {
			ctx["api_error"] = submatch[1]
		}

		return ctx
	}
}

// --- Helper functions ---

const maxHashPreviewLen = 64

// truncateHash truncates a hash string for inclusion in context metadata.
func truncateHash(hash string) string {
	if len(hash) > maxHashPreviewLen {
		return hash[:maxHashPreviewLen] + "..."
	}

	return hash
}

// normalizeErrorType converts a human-readable error type to snake_case.
// e.g., "Token length exception" -> "token_length_exception".
func normalizeErrorType(errorType string) string {
	s := strings.ToLower(strings.TrimSpace(errorType))
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")

	return s
}
