package hashcat

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
)

// stderrTestCase represents a test case for ClassifyStderr.
type stderrTestCase struct {
	name             string
	line             string
	expectedCategory ErrorCategory
	expectedSeverity operations.Severity
	expectedRetry    bool
}

// runStderrTests is a helper function to run stderr classification tests.
func runStderrTests(t *testing.T, tests []stderrTestCase) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyStderr(tt.line)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
		})
	}
}

func TestClassifyStderr_HashFormatErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"separator unmatched error",
			"Hash 'abc123def': Separator unmatched",
			ErrorCategoryHashFormat,
			operations.SeverityCritical,
			false,
		},
		{
			"token length exception",
			"Hash '$2a$10$abc123': Token length exception",
			ErrorCategoryHashFormat,
			operations.SeverityCritical,
			false,
		},
		{"no hashes loaded", "No hashes loaded", ErrorCategoryHashFormat, operations.SeverityCritical, false},
		{"hash-file exception", "Hash-file exception", ErrorCategoryHashFormat, operations.SeverityCritical, false},
		{
			"line length exception",
			"Hash 'test': Line-length exception",
			ErrorCategoryHashFormat,
			operations.SeverityCritical,
			false,
		},
		{
			"salt length exception",
			"Hash 'test': Salt-length exception",
			ErrorCategoryHashFormat,
			operations.SeverityCritical,
			false,
		},
	})
}

func TestClassifyStderr_DeviceErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"device out of memory",
			"Device #1: ATTENTION! out of memory",
			ErrorCategoryDevice,
			operations.SeverityFatal,
			false,
		},
		{
			"device memory error lowercase",
			"Device #2: memory allocation failed",
			ErrorCategoryDevice,
			operations.SeverityFatal,
			false,
		},
		{
			"device warning temperature",
			"Device #1: WARNING! Temperature limit reached",
			ErrorCategoryDevice,
			operations.SeverityWarning,
			true,
		},
		{
			"hardware monitor warning",
			"hwmon: GPU temperature above threshold",
			ErrorCategoryDevice,
			operations.SeverityWarning,
			true,
		},
	})
}

func TestClassifyStderr_FileAccessErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"cannot open file",
			"ERROR: wordlist.txt: can't open",
			ErrorCategoryFileAccess,
			operations.SeverityCritical,
			false,
		},
		{
			"no such file or directory",
			"ERROR: No such file or directory",
			ErrorCategoryFileAccess,
			operations.SeverityCritical,
			false,
		},
		{
			"file not found",
			"ERROR: /path/to/rules.rule: No such file or directory",
			ErrorCategoryFileAccess,
			operations.SeverityCritical,
			false,
		},
	})
}

func TestClassifyStderr_BackendErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"OpenCL out of resources",
			"OpenCL API (clEnqueueNDRangeKernel) CL_OUT_OF_RESOURCES",
			ErrorCategoryBackend,
			operations.SeverityCritical,
			false,
		},
		{
			"OpenCL out of host memory",
			"OpenCL API (clCreateBuffer) CL_OUT_OF_HOST_MEMORY",
			ErrorCategoryBackend,
			operations.SeverityFatal,
			false,
		},
		{"CUDA error", "cuDeviceGet() CUDA_ERROR_NO_DEVICE", ErrorCategoryBackend, operations.SeverityCritical, false},
		{"HIP error", "hipDeviceGet() HIP_ERROR_NO_DEVICE", ErrorCategoryBackend, operations.SeverityCritical, false},
		{"Metal error", "Metal API error", ErrorCategoryBackend, operations.SeverityCritical, false},
	})
}

func TestClassifyStderr_ConfigurationErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"invalid argument",
			"ERROR: Invalid argument specified",
			ErrorCategoryConfiguration,
			operations.SeverityCritical,
			false,
		},
		{
			"option requires argument",
			"ERROR: Option --session requires an argument",
			ErrorCategoryConfiguration,
			operations.SeverityCritical,
			false,
		},
		{
			"mixed options error",
			"ERROR: Mixed options not allowed",
			ErrorCategoryConfiguration,
			operations.SeverityCritical,
			false,
		},
	})
}

func TestClassifyStderr_InfoAndWarnings(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"skipping invalid hash",
			"Skipping invalid or unsupported hash on line 5",
			ErrorCategoryInfo,
			operations.SeverityInfo,
			true,
		},
		{"generic warning", "Warning: Hash found in potfile", ErrorCategoryWarning, operations.SeverityMinor, true},
		{"approaching limit warning", "Approaching final keyspace", ErrorCategoryInfo, operations.SeverityInfo, true},
	})
}

func TestClassifyStderr_UnknownErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"unrecognized error message",
			"Some random stderr output that doesn't match any pattern",
			ErrorCategoryUnknown,
			operations.SeverityMinor,
			true,
		},
		{"empty line", "", ErrorCategoryUnknown, operations.SeverityMinor, true},
		{"whitespace only", "   ", ErrorCategoryUnknown, operations.SeverityMinor, true},
	})
}

func TestClassifyStderr_GeneralErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"generic ERROR prefix without specific pattern",
			"ERROR: Something unexpected happened",
			ErrorCategoryUnknown,
			operations.SeverityCritical,
			false,
		},
		{
			"restore file issue",
			"ERROR: Cannot read /path/to/session.restore",
			ErrorCategoryRetryable,
			operations.SeverityMinor,
			true,
		},
	})
}

func TestErrorInfo_Fields(t *testing.T) {
	info := ErrorInfo{
		Category:  ErrorCategoryHashFormat,
		Severity:  operations.SeverityCritical,
		Retryable: false,
		Message:   "Hash 'test': Separator unmatched",
	}

	assert.Equal(t, ErrorCategoryHashFormat, info.Category)
	assert.Equal(t, operations.SeverityCritical, info.Severity)
	assert.False(t, info.Retryable)
	assert.Equal(t, "Hash 'test': Separator unmatched", info.Message)
}

func TestErrorCategory_String(t *testing.T) {
	tests := []struct {
		category ErrorCategory
		expected string
	}{
		{ErrorCategoryUnknown, "unknown"},
		{ErrorCategorySuccess, "success"},
		{ErrorCategoryInfo, "info"},
		{ErrorCategoryWarning, "warning"},
		{ErrorCategoryRetryable, "retryable"},
		{ErrorCategoryHashFormat, "hash_format"},
		{ErrorCategoryFileAccess, "file_access"},
		{ErrorCategoryDevice, "device"},
		{ErrorCategoryConfiguration, "configuration"},
		{ErrorCategoryBackend, "backend"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.category.String())
		})
	}
}
