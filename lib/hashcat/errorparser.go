// Package hashcat provides utilities for interacting with hashcat.
package hashcat

import (
	"regexp"
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

// ErrorInfo contains information about a classified stderr line.
type ErrorInfo struct {
	Category  ErrorCategory
	Severity  api.Severity
	Retryable bool
	Message   string
}

// errorPattern represents a pattern for matching stderr lines.
type errorPattern struct {
	pattern   *regexp.Regexp
	category  ErrorCategory
	severity  api.Severity
	retryable bool
}

// Compile all patterns at init time for performance.
//
// NOTE: Pattern order matters: more specific patterns must appear before more general ones,
// because matching is performed in slice order and the first matching pattern is used.
//
//nolint:gochecknoglobals // Patterns are intentionally global for performance
var errorPatterns = []errorPattern{
	// Hash format errors (non-retryable, critical)
	{regexp.MustCompile(`Hash '.+': Separator unmatched`), ErrorCategoryHashFormat, api.SeverityCritical, false},
	{
		regexp.MustCompile(`Hash '.+': Token length exception`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
	},
	{
		regexp.MustCompile(`Hash '.+': Line-length exception`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
	},
	{
		regexp.MustCompile(`Hash '.+': Salt-length exception`),
		ErrorCategoryHashFormat,
		api.SeverityCritical,
		false,
	},
	{regexp.MustCompile(`(?i)No hashes loaded`), ErrorCategoryHashFormat, api.SeverityCritical, false},
	{regexp.MustCompile(`(?i)Hash-file exception`), ErrorCategoryHashFormat, api.SeverityCritical, false},

	// Device memory errors (non-retryable, fatal)
	// Using non-greedy .*? to prevent catastrophic backtracking on long lines
	{
		regexp.MustCompile(`Device #\d+:.*?(?i)(out of memory|memory allocation|MEMORY)`),
		ErrorCategoryDevice,
		api.SeverityFatal,
		false,
	},

	// Device warnings (retryable)
	// Using non-greedy .*? to prevent performance issues on long lines
	{regexp.MustCompile(`Device #\d+:.*?WARNING`), ErrorCategoryDevice, api.SeverityWarning, true},
	{regexp.MustCompile(`(?i)hwmon.*temperature`), ErrorCategoryDevice, api.SeverityWarning, true},

	// File access errors (non-retryable, critical)
	{regexp.MustCompile(`ERROR:.*can't open`), ErrorCategoryFileAccess, api.SeverityCritical, false},
	{
		regexp.MustCompile(`ERROR:.*No such file or directory`),
		ErrorCategoryFileAccess,
		api.SeverityCritical,
		false,
	},

	// Backend errors - memory (fatal)
	{regexp.MustCompile(`OpenCL API.*CL_OUT_OF_HOST_MEMORY`), ErrorCategoryBackend, api.SeverityFatal, false},

	// Backend errors - general (critical)
	{regexp.MustCompile(`OpenCL API.*CL_`), ErrorCategoryBackend, api.SeverityCritical, false},
	{regexp.MustCompile(`cuDeviceGet\(\).*CUDA_ERROR`), ErrorCategoryBackend, api.SeverityCritical, false},
	{regexp.MustCompile(`hipDeviceGet\(\).*HIP_ERROR`), ErrorCategoryBackend, api.SeverityCritical, false},
	{regexp.MustCompile(`(?i)Metal API`), ErrorCategoryBackend, api.SeverityCritical, false},

	// Configuration errors (non-retryable, critical)
	{regexp.MustCompile(`ERROR:.*Invalid argument`), ErrorCategoryConfiguration, api.SeverityCritical, false},
	{regexp.MustCompile(`ERROR:.*Option.*requires`), ErrorCategoryConfiguration, api.SeverityCritical, false},
	{regexp.MustCompile(`ERROR:.*Mixed.*not allowed`), ErrorCategoryConfiguration, api.SeverityCritical, false},

	// Restore file issues (retryable)
	{regexp.MustCompile(`ERROR:.*Cannot read.*\.restore`), ErrorCategoryRetryable, api.SeverityMinor, true},

	// Info/warnings (retryable)
	{regexp.MustCompile(`(?i)Skipping invalid or unsupported`), ErrorCategoryInfo, api.SeverityInfo, true},
	{regexp.MustCompile(`(?i)Approaching final keyspace`), ErrorCategoryInfo, api.SeverityInfo, true},
	{regexp.MustCompile(`^Warning:`), ErrorCategoryWarning, api.SeverityMinor, true},
}

// ClassifyStderr classifies a stderr line from hashcat and returns error information.
func ClassifyStderr(line string) ErrorInfo {
	// Check each pattern in order
	for _, p := range errorPatterns {
		if p.pattern.MatchString(line) {
			return ErrorInfo{
				Category:  p.category,
				Severity:  p.severity,
				Retryable: p.retryable,
				Message:   line,
			}
		}
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
