// Package hashcat provides utilities for interacting with hashcat.
package hashcat

import (
	"regexp"
	"strings"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
)

// ErrorCategory represents the classification of a hashcat error.
type ErrorCategory int

const (
	// ErrorCategoryUnknown is for unrecognized error patterns.
	ErrorCategoryUnknown ErrorCategory = iota
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
	Severity  operations.Severity
	Retryable bool
	Message   string
}

// errorPattern represents a pattern for matching stderr lines.
type errorPattern struct {
	pattern   *regexp.Regexp
	category  ErrorCategory
	severity  operations.Severity
	retryable bool
}

// Compile all patterns at init time for performance.
//
//nolint:gochecknoglobals // Patterns are intentionally global for performance
var errorPatterns = []errorPattern{
	// Hash format errors (non-retryable, critical)
	{regexp.MustCompile(`Hash '.+': Separator unmatched`), ErrorCategoryHashFormat, operations.SeverityCritical, false},
	{
		regexp.MustCompile(`Hash '.+': Token length exception`),
		ErrorCategoryHashFormat,
		operations.SeverityCritical,
		false,
	},
	{
		regexp.MustCompile(`Hash '.+': Line-length exception`),
		ErrorCategoryHashFormat,
		operations.SeverityCritical,
		false,
	},
	{
		regexp.MustCompile(`Hash '.+': Salt-length exception`),
		ErrorCategoryHashFormat,
		operations.SeverityCritical,
		false,
	},
	{regexp.MustCompile(`(?i)No hashes loaded`), ErrorCategoryHashFormat, operations.SeverityCritical, false},
	{regexp.MustCompile(`(?i)Hash-file exception`), ErrorCategoryHashFormat, operations.SeverityCritical, false},

	// Device memory errors (non-retryable, fatal)
	{
		regexp.MustCompile(`Device #\d+:.*(?i)(out of memory|memory allocation|MEMORY)`),
		ErrorCategoryDevice,
		operations.SeverityFatal,
		false,
	},

	// Device warnings (retryable)
	{regexp.MustCompile(`Device #\d+:.*WARNING`), ErrorCategoryDevice, operations.SeverityWarning, true},
	{regexp.MustCompile(`(?i)hwmon.*temperature`), ErrorCategoryDevice, operations.SeverityWarning, true},

	// File access errors (non-retryable, critical)
	{regexp.MustCompile(`ERROR:.*can't open`), ErrorCategoryFileAccess, operations.SeverityCritical, false},
	{
		regexp.MustCompile(`ERROR:.*No such file or directory`),
		ErrorCategoryFileAccess,
		operations.SeverityCritical,
		false,
	},

	// Backend errors - memory (fatal)
	{regexp.MustCompile(`OpenCL API.*CL_OUT_OF_HOST_MEMORY`), ErrorCategoryBackend, operations.SeverityFatal, false},

	// Backend errors - general (critical)
	{regexp.MustCompile(`OpenCL API.*CL_`), ErrorCategoryBackend, operations.SeverityCritical, false},
	{regexp.MustCompile(`cuDeviceGet\(\).*CUDA_ERROR`), ErrorCategoryBackend, operations.SeverityCritical, false},
	{regexp.MustCompile(`hipDeviceGet\(\).*HIP_ERROR`), ErrorCategoryBackend, operations.SeverityCritical, false},
	{regexp.MustCompile(`(?i)Metal API`), ErrorCategoryBackend, operations.SeverityCritical, false},

	// Configuration errors (non-retryable, critical)
	{regexp.MustCompile(`ERROR:.*Invalid argument`), ErrorCategoryConfiguration, operations.SeverityCritical, false},
	{regexp.MustCompile(`ERROR:.*Option.*requires`), ErrorCategoryConfiguration, operations.SeverityCritical, false},
	{regexp.MustCompile(`ERROR:.*Mixed.*not allowed`), ErrorCategoryConfiguration, operations.SeverityCritical, false},

	// Restore file issues (retryable)
	{regexp.MustCompile(`ERROR:.*Cannot read.*\.restore`), ErrorCategoryRetryable, operations.SeverityMinor, true},

	// Info/warnings (retryable)
	{regexp.MustCompile(`(?i)Skipping invalid or unsupported`), ErrorCategoryInfo, operations.SeverityInfo, true},
	{regexp.MustCompile(`(?i)Approaching final keyspace`), ErrorCategoryInfo, operations.SeverityInfo, true},
	{regexp.MustCompile(`^Warning:`), ErrorCategoryWarning, operations.SeverityMinor, true},
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
			Severity:  operations.SeverityCritical,
			Retryable: false,
			Message:   line,
		}
	}

	// Default: unknown error, minor severity, retryable
	return ErrorInfo{
		Category:  ErrorCategoryUnknown,
		Severity:  operations.SeverityMinor,
		Retryable: true,
		Message:   line,
	}
}
