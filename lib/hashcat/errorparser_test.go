package hashcat

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// stderrTestCase represents a test case for ClassifyStderr.
type stderrTestCase struct {
	name             string
	line             string
	expectedCategory ErrorCategory
	expectedSeverity api.Severity
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
			api.SeverityCritical,
			false,
		},
		{
			"token length exception",
			"Hash '$2a$10$abc123': Token length exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{"no hashes loaded", "No hashes loaded", ErrorCategoryHashFormat, api.SeverityCritical, false},
		{"hash-file exception", "Hash-file exception", ErrorCategoryHashFormat, api.SeverityCritical, false},
		{
			"line length exception",
			"Hash 'test': Line-length exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"salt length exception",
			"Hash 'test': Salt-length exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
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
			api.SeverityFatal,
			false,
		},
		{
			"device memory error lowercase",
			"Device #2: memory allocation failed",
			ErrorCategoryDevice,
			api.SeverityFatal,
			false,
		},
		{
			"device warning temperature",
			"Device #1: WARNING! Temperature limit reached",
			ErrorCategoryDevice,
			api.SeverityWarning,
			true,
		},
		{
			"hardware monitor warning",
			"hwmon: GPU temperature above threshold",
			ErrorCategoryDevice,
			api.SeverityWarning,
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
			api.SeverityCritical,
			false,
		},
		{
			"no such file or directory",
			"ERROR: No such file or directory",
			ErrorCategoryFileAccess,
			api.SeverityCritical,
			false,
		},
		{
			"file not found",
			"ERROR: /path/to/rules.rule: No such file or directory",
			ErrorCategoryFileAccess,
			api.SeverityCritical,
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
			api.SeverityCritical,
			false,
		},
		{
			"OpenCL out of host memory",
			"OpenCL API (clCreateBuffer) CL_OUT_OF_HOST_MEMORY",
			ErrorCategoryBackend,
			api.SeverityFatal,
			false,
		},
		{"CUDA error", "cuDeviceGet() CUDA_ERROR_NO_DEVICE", ErrorCategoryBackend, api.SeverityCritical, false},
		{"HIP error", "hipDeviceGet() HIP_ERROR_NO_DEVICE", ErrorCategoryBackend, api.SeverityCritical, false},
		{"Metal error", "Metal API error", ErrorCategoryBackend, api.SeverityCritical, false},
	})
}

func TestClassifyStderr_ConfigurationErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"invalid argument",
			"ERROR: Invalid argument specified",
			ErrorCategoryConfiguration,
			api.SeverityCritical,
			false,
		},
		{
			"option requires argument",
			"ERROR: Option --session requires an argument",
			ErrorCategoryConfiguration,
			api.SeverityCritical,
			false,
		},
		{
			"mixed options error",
			"ERROR: Mixed options not allowed",
			ErrorCategoryConfiguration,
			api.SeverityCritical,
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
			api.SeverityInfo,
			true,
		},
		{"generic warning", "Warning: Hash found in potfile", ErrorCategoryWarning, api.SeverityMinor, true},
		{"approaching limit warning", "Approaching final keyspace", ErrorCategoryInfo, api.SeverityInfo, true},
	})
}

func TestClassifyStderr_UnknownErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"unrecognized error message",
			"Some random stderr output that doesn't match any pattern",
			ErrorCategoryUnknown,
			api.SeverityMinor,
			true,
		},
		{"empty line", "", ErrorCategoryUnknown, api.SeverityMinor, true},
		{"whitespace only", "   ", ErrorCategoryUnknown, api.SeverityMinor, true},
	})
}

func TestClassifyStderr_GeneralErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"generic ERROR prefix without specific pattern",
			"ERROR: Something unexpected happened",
			ErrorCategoryUnknown,
			api.SeverityCritical,
			false,
		},
		{
			"restore file issue",
			"ERROR: Cannot read /path/to/session.restore",
			ErrorCategoryRetryable,
			api.SeverityMinor,
			true,
		},
	})
}

func TestClassifyStderr_StdoutErrorPatterns(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		// Summary lines (generic "* <error>: N/N hashes" pattern)
		{
			"summary token length exception",
			"* Token length exception: 1024/1024 hashes",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"summary separator unmatched",
			"* Separator unmatched: 5/100 hashes",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"summary line-length exception",
			"* Line-length exception: 2/50 hashes",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"summary salt-length exception",
			"* Salt-length exception: 10/10 hashes",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"summary hash-value exception",
			"* Hash-value exception: 3/200 hashes",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"summary signature unmatched",
			"* Signature unmatched: 50/50 hashes",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"summary hash-encoding exception",
			"* Hash-encoding exception: 1/10 hashes",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"summary insufficient entropy",
			"* Insufficient entropy exception: 2/2 hashes",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"summary zero hashes",
			"* Token length exception: 0/0 hashes",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},

		// v6.x per-hash with file path: "Hashfile '<file>' on line N (<hash>): <error>"
		{
			"v6 hashfile per-line error",
			"Hashfile '/path/to/2.hsh' on line 1023 ($abc...): Token length exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"v6 hashfile with long path",
			"Hashfile '/very/long/nested/dir/hashes.txt' on line 1 (abc): Separator unmatched",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"v6 hashfile file-level error",
			"Hashfile '/tmp/hashes.txt': No such file or directory",
			ErrorCategoryFileAccess,
			api.SeverityCritical,
			false,
		},

		// v7.x per-hash format: "Hash parsing error in hashfile: '<file>' on line N (<hash>): <error>"
		{
			"v7 hashfile per-line error",
			"Hash parsing error in hashfile: '/tmp/hashes.txt' on line 5 ($2a$10$abc): Token length exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		// v7.x single-hash format: "Hash parsing error: '<hash>': <error>"
		{
			"v7 single hash parsing error",
			"Hash parsing error: '$2a$10$abc123def456': Token length exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},

		// Machine-readable per-hash errors: "<file>:<line>:<hash>:<parser_error>"
		{
			"machine-readable token length",
			"/tmp/hashes.txt:5:$2a$10$abc:Token length exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable separator unmatched",
			"/tmp/hashes.txt:1:abc123:Separator unmatched",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable signature unmatched",
			"/tmp/hashes.txt:10:badhash:Signature unmatched",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable hash-encoding exception",
			"/tmp/hashes.txt:3:xyz:Hash-encoding exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable insufficient entropy",
			"/tmp/hashes.txt:1:short:Insufficient entropy exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},

		// Advisory line before single-hash errors
		{
			"commandline argument advisory",
			"Hash was parsed as a commandline argument (not as a file, maybe the file doesn't exist?)",
			ErrorCategoryInfo,
			api.SeverityInfo,
			false,
		},

		// Indented advisory context lines
		{
			"explanatory context line",
			"  This error happens if the wrong hash type is specified, if the hashes are",
			ErrorCategoryInfo,
			api.SeverityInfo,
			false,
		},
		{
			"malformed continuation line",
			"  malformed or if the hash type is not supported by the installed version",
			ErrorCategoryInfo,
			api.SeverityInfo,
			false,
		},
		{
			"username hint line",
			"  --username to enable it.",
			ErrorCategoryInfo,
			api.SeverityInfo,
			false,
		},
		{
			"dynamic-x hint line (v7)",
			"  --dynamic-x to enable it.",
			ErrorCategoryInfo,
			api.SeverityInfo,
			false,
		},
		{
			"generic indented advisory line",
			"  Consider using --force to bypass this check.",
			ErrorCategoryInfo,
			api.SeverityInfo,
			false,
		},
	})
}

func TestErrorInfo_Fields(t *testing.T) {
	info := ErrorInfo{
		Category:  ErrorCategoryHashFormat,
		Severity:  api.SeverityCritical,
		Retryable: false,
		Message:   "Hash 'test': Separator unmatched",
	}

	assert.Equal(t, ErrorCategoryHashFormat, info.Category)
	assert.Equal(t, api.SeverityCritical, info.Severity)
	assert.False(t, info.Retryable)
	assert.Equal(t, "Hash 'test': Separator unmatched", info.Message)
}

func TestClassifyStderr_SummaryContext(t *testing.T) {
	info := ClassifyStderr("* Token length exception: 1024/1024 hashes")

	require.NotNil(t, info.Context)
	assert.Equal(t, "token_length_exception", info.Context["error_type"])
	assert.Equal(t, 1024, info.Context["affected_count"])
	assert.Equal(t, 1024, info.Context["total_count"])
}

func TestClassifyStderr_SummaryContextPartialHashes(t *testing.T) {
	info := ClassifyStderr("* Separator unmatched: 5/100 hashes")

	require.NotNil(t, info.Context)
	assert.Equal(t, "separator_unmatched", info.Context["error_type"])
	assert.Equal(t, 5, info.Context["affected_count"])
	assert.Equal(t, 100, info.Context["total_count"])
}

func TestClassifyStderr_V6HashfileContext(t *testing.T) {
	info := ClassifyStderr(
		"Hashfile '/path/to/2.hsh' on line 1023 ($abc...): Token length exception",
	)

	require.NotNil(t, info.Context)
	assert.Equal(t, "token_length_exception", info.Context["error_type"])
	assert.Equal(t, "/path/to/2.hsh", info.Context["hashfile"])
	assert.Equal(t, 1023, info.Context["line_number"])
	assert.Equal(t, "$abc...", info.Context["hash_preview"])
}

func TestClassifyStderr_V7HashfileContext(t *testing.T) {
	info := ClassifyStderr(
		"Hash parsing error in hashfile: '/tmp/hashes.txt' on line 5 ($2a$10$abc): Token length exception",
	)

	require.NotNil(t, info.Context)
	assert.Equal(t, "token_length_exception", info.Context["error_type"])
	assert.Equal(t, "/tmp/hashes.txt", info.Context["hashfile"])
	assert.Equal(t, 5, info.Context["line_number"])
	assert.Equal(t, "$2a$10$abc", info.Context["hash_preview"])
}

func TestClassifyStderr_V7SingleHashContext(t *testing.T) {
	info := ClassifyStderr("Hash parsing error: '$2a$10$abc123': Token length exception")

	require.NotNil(t, info.Context)
	assert.Equal(t, "token_length_exception", info.Context["error_type"])
	assert.Equal(t, "$2a$10$abc123", info.Context["hash_preview"])
}

func TestClassifyStderr_MachineReadableContext(t *testing.T) {
	info := ClassifyStderr("/tmp/hashes.txt:5:$2a$10$abc:Token length exception")

	require.NotNil(t, info.Context)
	assert.Equal(t, "token_length_exception", info.Context["error_type"])
	assert.Equal(t, "/tmp/hashes.txt", info.Context["hashfile"])
	assert.Equal(t, 5, info.Context["line_number"])
	assert.Equal(t, "$2a$10$abc", info.Context["hash_preview"])
}

func TestClassifyStderr_MachineReadableColonsInHash(t *testing.T) {
	// Hash formats like MD5:salt or PBKDF2 (sha256:20000:salt) contain colons.
	// The non-greedy file path capture must stop at the first :<digits>: boundary.
	info := ClassifyStderr(
		"/tmp/hashes.txt:3:sha256:20000:saltvalue:Hash-encoding exception",
	)

	require.NotNil(t, info.Context)
	assert.Equal(t, "hash_encoding_exception", info.Context["error_type"])
	assert.Equal(t, "/tmp/hashes.txt", info.Context["hashfile"])
	assert.Equal(t, 3, info.Context["line_number"])
	assert.Equal(t, "sha256:20000:saltvalue", info.Context["hash_preview"])
}

func TestClassifyStderr_NoHashesLoadedContext(t *testing.T) {
	info := ClassifyStderr("No hashes loaded.")

	require.NotNil(t, info.Context)
	assert.Equal(t, "no_hashes_loaded", info.Context["error_type"])
	assert.Equal(t, true, info.Context["terminal"])
}

func TestClassifyStderr_HashfileEmptyContext(t *testing.T) {
	info := ClassifyStderr("hashfile is empty or corrupt.")

	require.NotNil(t, info.Context)
	assert.Equal(t, "hashfile_empty_or_corrupt", info.Context["error_type"])
	assert.Equal(t, true, info.Context["terminal"])
}

func TestClassifyStderr_NoHashModeMatchContext(t *testing.T) {
	info := ClassifyStderr("No hash-mode matches the structure of the input hash.")

	require.NotNil(t, info.Context)
	assert.Equal(t, "no_hash_mode_match", info.Context["error_type"])
	assert.Equal(t, true, info.Context["terminal"])
}

func TestClassifyStderr_SelftestAbortContext(t *testing.T) {
	info := ClassifyStderr("Aborting session due to kernel self-test failure.")

	require.NotNil(t, info.Context)
	assert.Equal(t, "selftest_failure", info.Context["error_type"])
	assert.Equal(t, ErrorCategoryBackend, info.Category)
	assert.Equal(t, api.SeverityFatal, info.Severity)
}

func TestClassifyStderr_AutotuneAbortContext(t *testing.T) {
	info := ClassifyStderr(
		"Aborting session due to kernel autotune failures, for all active devices.",
	)

	require.NotNil(t, info.Context)
	assert.Equal(t, "autotune_failure", info.Context["error_type"])
	assert.Equal(t, ErrorCategoryBackend, info.Category)
	assert.Equal(t, api.SeverityFatal, info.Severity)
}

func TestClassifyStderr_KernelBuildContext(t *testing.T) {
	info := ClassifyStderr(
		"* Device #1: Kernel /usr/share/hashcat/OpenCL/m00010_a0-pure.cl build failed.",
	)

	require.NotNil(t, info.Context)
	assert.Equal(t, "kernel_build_failed", info.Context["error_type"])
	assert.Equal(t, 1, info.Context["device_id"])
	assert.Equal(t,
		"/usr/share/hashcat/OpenCL/m00010_a0-pure.cl",
		info.Context["kernel_path"],
	)
}

func TestClassifyStderr_InvalidHashModeContext(t *testing.T) {
	info := ClassifyStderr("Invalid hash-mode '99999' selected.")

	require.NotNil(t, info.Context)
	assert.Equal(t, "invalid_hash_mode", info.Context["error_type"])
	assert.Equal(t, 99999, info.Context["hash_mode"])
	assert.Equal(t, ErrorCategoryConfiguration, info.Category)
}

func TestClassifyStderr_TemperatureContext(t *testing.T) {
	info := ClassifyStderr("Temperature limit on GPU #2 reached, aborting")

	require.NotNil(t, info.Context)
	assert.Equal(t, "temperature_limit", info.Context["error_type"])
	assert.Equal(t, 2, info.Context["device_id"])
	assert.Equal(t, ErrorCategoryDevice, info.Category)
	assert.True(t, info.Retryable)
}

func TestClassifyStderr_DeviceMemoryContext(t *testing.T) {
	info := ClassifyStderr("Device #1: ATTENTION! out of memory")

	require.NotNil(t, info.Context)
	assert.Equal(t, "device_memory", info.Context["error_type"])
	assert.Equal(t, 1, info.Context["device_id"])
}

func TestClassifyStderr_DeviceWarningContext(t *testing.T) {
	info := ClassifyStderr("Device #3: WARNING! Kernel exec timeout is not disabled.")

	require.NotNil(t, info.Context)
	assert.Equal(t, "device_warning", info.Context["error_type"])
	assert.Equal(t, 3, info.Context["device_id"])
}

func TestClassifyStderr_BackendAPIContext(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		backendAPI string
		apiError   string
	}{
		{
			"OpenCL out of host memory",
			"OpenCL API (clCreateBuffer) CL_OUT_OF_HOST_MEMORY",
			"OpenCL",
			"CL_OUT_OF_HOST_MEMORY",
		},
		{
			"OpenCL out of resources",
			"OpenCL API (clEnqueueNDRangeKernel) CL_OUT_OF_RESOURCES",
			"OpenCL",
			"CL_OUT_OF_RESOURCES",
		},
		{
			"CUDA error",
			"cuDeviceGet() CUDA_ERROR_NO_DEVICE",
			"CUDA",
			"CUDA_ERROR_NO_DEVICE",
		},
		{
			"HIP error",
			"hipDeviceGet() HIP_ERROR_NO_DEVICE",
			"HIP",
			"HIP_ERROR_NO_DEVICE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyStderr(tt.line)

			require.NotNil(t, info.Context)
			assert.Equal(t, "backend_api_error", info.Context["error_type"])
			assert.Equal(t, tt.backendAPI, info.Context["backend_api"])
			assert.Equal(t, tt.apiError, info.Context["api_error"])
		})
	}
}

func TestClassifyStderr_KeyspaceOverflowContext(t *testing.T) {
	info := ClassifyStderr("Integer overflow detected in keyspace of mask: ?a?a?a?a?a?a?a?a?a?a")

	require.NotNil(t, info.Context)
	assert.Equal(t, "keyspace_overflow", info.Context["error_type"])
	assert.Equal(t, ErrorCategoryConfiguration, info.Category)
}

func TestClassifyStderr_StdinTimeoutContext(t *testing.T) {
	info := ClassifyStderr("No password candidates received in stdin mode, aborting")

	require.NotNil(t, info.Context)
	assert.Equal(t, "stdin_timeout", info.Context["error_type"])
	assert.Equal(t, ErrorCategoryConfiguration, info.Category)
}

func TestClassifyStderr_HashfileAccessContext(t *testing.T) {
	info := ClassifyStderr("Hashfile '/tmp/hashes.txt': No such file or directory")

	require.NotNil(t, info.Context)
	assert.Equal(t, "hashfile_access_error", info.Context["error_type"])
	assert.Equal(t, "/tmp/hashes.txt", info.Context["hashfile"])
	assert.Equal(t, "No such file or directory", info.Context["os_error"])
	assert.Equal(t, ErrorCategoryFileAccess, info.Category)
}

func TestClassifyStderr_NilContextForUnmatchedPatterns(t *testing.T) {
	info := ClassifyStderr("Some random unmatched output")

	assert.Nil(t, info.Context)
	assert.Equal(t, ErrorCategoryUnknown, info.Category)
}

func TestClassifyStderr_NilContextForInfoPatterns(t *testing.T) {
	info := ClassifyStderr("  This error happens if the wrong hash type is specified")

	assert.Nil(t, info.Context)
	assert.Equal(t, ErrorCategoryInfo, info.Category)
}

func TestClassifyStderr_V6SingleHashContext(t *testing.T) {
	info := ClassifyStderr("Hash 'abc123def': Separator unmatched")

	require.NotNil(t, info.Context)
	assert.Equal(t, "separator_unmatched", info.Context["error_type"])
	assert.Equal(t, "abc123def", info.Context["hash_preview"])
}

func TestClassifyStderr_HashPreviewTruncation(t *testing.T) {
	longHash := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789extra"
	info := ClassifyStderr("Hash '" + longHash + "': Token length exception")

	require.NotNil(t, info.Context)
	preview, ok := info.Context["hash_preview"].(string)
	require.True(t, ok)
	assert.LessOrEqual(t, len(preview), maxHashPreviewLen+3) // +3 for "..."
	assert.Contains(t, preview, "...")
}

func TestNormalizeErrorType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Token length exception", "token_length_exception"},
		{"Separator unmatched", "separator_unmatched"},
		{"Line-length exception", "line_length_exception"},
		{"Salt-length exception", "salt_length_exception"},
		{"Hash-value exception", "hash_value_exception"},
		{"  Spaces around  ", "spaces_around"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeErrorType(tt.input))
		})
	}
}

func TestClassifyStderr_MetalAPIContext(t *testing.T) {
	info := ClassifyStderr("Metal API error during kernel compilation")

	require.NotNil(t, info.Context)
	assert.Equal(t, "metal_api_error", info.Context["error_type"])
	assert.Equal(t, "Metal", info.Context["backend_api"])
}

func TestClassifyStderr_CLBuildProgramContext(t *testing.T) {
	info := ClassifyStderr("clBuildProgram(): CL_BUILD_PROGRAM_FAILURE")

	require.NotNil(t, info.Context)
	assert.Equal(t, "cl_build_program_failure", info.Context["error_type"])
	assert.Equal(t, "OpenCL", info.Context["backend_api"])
	assert.Equal(t, "CL_BUILD_PROGRAM_FAILURE", info.Context["api_error"])
	assert.Equal(t, ErrorCategoryBackend, info.Category)
}

func TestClassifyStderr_CannotLoadModuleContext(t *testing.T) {
	info := ClassifyStderr("Cannot load module /usr/share/hashcat/modules/module_99999.so")

	require.NotNil(t, info.Context)
	assert.Equal(t, "cannot_load_module", info.Context["error_type"])
	assert.Equal(t, ErrorCategoryConfiguration, info.Category)
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
