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

// --- Tests for new Priority 1 patterns ---

func TestClassifyStderr_HashCountErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"not enough hashes loaded",
			"Not enough hashes loaded - minimum is 2 for this hash-mode.",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"too many hashes loaded",
			"Too many hashes loaded - maximum is 1 for this hash-mode.",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
	})
}

func TestClassifyStderr_HashCountContext(t *testing.T) {
	info := ClassifyStderr("Not enough hashes loaded - minimum is 2 for this hash-mode.")

	require.NotNil(t, info.Context)
	assert.Equal(t, "hash_count_limit", info.Context["error_type"])
	assert.Equal(t, 2, info.Context["hash_count_limit"])
}

func TestClassifyStderr_BackendPlatformErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"no OpenCL Metal HIP CUDA platform",
			"ATTENTION! No OpenCL, Metal, HIP or CUDA compatible platform found.",
			ErrorCategoryBackend,
			api.SeverityFatal,
			false,
		},
		{
			"no OpenCL HIP CUDA platform (Linux)",
			"ATTENTION! No OpenCL, HIP or CUDA compatible platform found.",
			ErrorCategoryBackend,
			api.SeverityFatal,
			false,
		},
		{
			"outdated NVIDIA NVRTC driver",
			"Outdated NVIDIA NVRTC driver version '123' detected!",
			ErrorCategoryBackend,
			api.SeverityCritical,
			false,
		},
		{
			"outdated NVIDIA CUDA driver",
			"Outdated NVIDIA CUDA driver version '456' detected!",
			ErrorCategoryBackend,
			api.SeverityCritical,
			false,
		},
		{
			"unstable OpenCL driver",
			"* Device #1: Unstable OpenCL driver detected!",
			ErrorCategoryBackend,
			api.SeverityCritical,
			false,
		},
		{
			"TDR kernel runtime",
			"Kernel minimum runtime larger than default TDR",
			ErrorCategoryBackend,
			api.SeverityCritical,
			false,
		},
		{
			"runtime library init failure",
			"Failed to initialize the AMD main driver HIP runtime library.",
			ErrorCategoryBackend,
			api.SeverityWarning,
			true,
		},
	})
}

func TestClassifyStderr_DeviceSelfTestErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"CUDA kernel self-test failed",
			"* Device #1: ATTENTION! CUDA kernel self-test failed.",
			ErrorCategoryBackend,
			api.SeverityFatal,
			false,
		},
		{
			"OpenCL kernel self-test failed",
			"* Device #2: ATTENTION! OpenCL kernel self-test failed.",
			ErrorCategoryBackend,
			api.SeverityFatal,
			false,
		},
		{
			"self-test hash parsing error",
			"Self-test hash parsing error: Token length exception",
			ErrorCategoryBackend,
			api.SeverityCritical,
			false,
		},
	})
}

func TestClassifyStderr_NewFileAccessErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"no usable dictionary",
			"No usable dictionary file found.",
			ErrorCategoryFileAccess,
			api.SeverityCritical,
			false,
		},
		{
			"no valid rules left",
			"No valid rules left.",
			ErrorCategoryFileAccess,
			api.SeverityCritical,
			false,
		},
		{
			"empty input file",
			"/tmp/wordlist.txt: empty file.",
			ErrorCategoryFileAccess,
			api.SeverityCritical,
			false,
		},
	})
}

func TestClassifyStderr_NewConfigurationErrors(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"already running instance",
			"Already an instance 'attack-12345' running on pid 42",
			ErrorCategoryConfiguration,
			api.SeverityCritical,
			false,
		},
		{
			"restore value exceeds keyspace",
			"Restore value is greater than keyspace.",
			ErrorCategoryConfiguration,
			api.SeverityCritical,
			false,
		},
		{
			"incompatible restore file version",
			"Incompatible restore-file version.",
			ErrorCategoryRetryable,
			api.SeverityMinor,
			true,
		},
	})
}

func TestClassifyStderr_DeviceMemoryNew(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"not enough allocatable device memory",
			"* Device #1: Not enough allocatable device memory for this hashlist/ruleset.",
			ErrorCategoryDevice,
			api.SeverityFatal,
			false,
		},
		{
			"not enough allocatable memory for ruleset",
			"Not enough allocatable memory (RAM) for this ruleset.",
			ErrorCategoryDevice,
			api.SeverityFatal,
			false,
		},
	})
}

// --- Tests for new Priority 2 patterns ---

func TestClassifyStderr_StdoutWarningsNew(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		{
			"driver temperature threshold",
			"Driver temperature threshold met on GPU #1. Expect reduced performance.",
			ErrorCategoryDevice,
			api.SeverityWarning,
			true,
		},
		{
			"runtime limit reached",
			"Runtime limit reached, aborting",
			ErrorCategoryInfo,
			api.SeverityMinor,
			true,
		},
		{
			"failed to parse hashes using format",
			"Failed to parse hashes using the 'plain' format.",
			ErrorCategoryHashFormat,
			api.SeverityWarning,
			false,
		},
		{
			"hashfile changed during runtime",
			"Hashfile '/tmp/hashes.txt' on line 5: File changed during runtime. Skipping new data.",
			ErrorCategoryHashFormat,
			api.SeverityWarning,
			false,
		},
		{
			"kernel create failed",
			"* Device #1: Kernel /usr/share/hashcat/OpenCL/m00000.cl create failed.",
			ErrorCategoryBackend,
			api.SeverityCritical,
			false,
		},
		{
			"cannot convert rule for device",
			"Cannot convert rule for use on OpenCL device in file rules.rule on line 5: x",
			ErrorCategoryInfo,
			api.SeverityInfo,
			true,
		},
		{
			"pure backend kernels selected",
			"ATTENTION! Pure (unoptimized) backend kernels selected.",
			ErrorCategoryInfo,
			api.SeverityInfo,
			false,
		},
		{
			"hash-mode auto-detect",
			"Hash-mode was not specified with -m. Attempting to auto-detect hash mode.",
			ErrorCategoryInfo,
			api.SeverityInfo,
			false,
		},
		{
			"BOM detected",
			"wordlist.txt: Byte Order Mark (BOM) was detected",
			ErrorCategoryInfo,
			api.SeverityInfo,
			false,
		},
	})
}

// --- Tests for generalized machine-readable pattern ---

func TestClassifyStderr_MachineReadableGeneral(t *testing.T) {
	runStderrTests(t, []stderrTestCase{
		// Previously uncovered parser errors (PA_011-PA_047)
		{
			"machine-readable invalid hccapx file size",
			"/tmp/hashes.hccapx:1:data:Invalid hccapx file size",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable invalid truecrypt filesize",
			"/tmp/tc.img:1:data:Invalid truecrypt filesize",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable invalid veracrypt filesize",
			"/tmp/vc.img:1:data:Invalid veracrypt filesize",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable invalid key size",
			"/tmp/hashes.txt:1:data:Invalid key size",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable invalid block size",
			"/tmp/hashes.txt:1:data:Invalid block size",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable IV length exception",
			"/tmp/hashes.txt:1:data:IV length exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable CT length exception",
			"/tmp/hashes.txt:1:data:CT length exception",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
		{
			"machine-readable invalid or unsupported cipher",
			"/tmp/hashes.txt:1:data:Invalid or unsupported cipher",
			ErrorCategoryHashFormat,
			api.SeverityCritical,
			false,
		},
	})
}

func TestClassifyStderr_MachineReadableKerberos(t *testing.T) {
	// Kerberos hashes like krb5asrep$23$user@REALM$hash contain colons
	info := ClassifyStderr(
		"/tmp/hashes.txt:1:krb5asrep$23$user@REALM$longhashdata:Signature unmatched",
	)

	require.NotNil(t, info.Context)
	assert.Equal(t, "signature_unmatched", info.Context["error_type"])
	assert.Equal(t, "/tmp/hashes.txt", info.Context["hashfile"])
	assert.Equal(t, 1, info.Context["line_number"])
}

// --- Context extraction tests for new extractors ---

func TestClassifyStderr_PidContext(t *testing.T) {
	info := ClassifyStderr("Already an instance 'attack-12345' running on pid 42")

	require.NotNil(t, info.Context)
	assert.Equal(t, "already_running", info.Context["error_type"])
	assert.Equal(t, 42, info.Context["pid"])
}

func TestClassifyStderr_NoDictionaryContext(t *testing.T) {
	info := ClassifyStderr("No usable dictionary file found.")

	require.NotNil(t, info.Context)
	assert.Equal(t, "no_dictionary", info.Context["error_type"])
	assert.Equal(t, true, info.Context["terminal"])
}

func TestClassifyStderr_NoValidRulesContext(t *testing.T) {
	info := ClassifyStderr("No valid rules left.")

	require.NotNil(t, info.Context)
	assert.Equal(t, "no_valid_rules", info.Context["error_type"])
	assert.Equal(t, true, info.Context["terminal"])
}

func TestClassifyStderr_NoBackendPlatformContext(t *testing.T) {
	info := ClassifyStderr(
		"ATTENTION! No OpenCL, Metal, HIP or CUDA compatible platform found.",
	)

	require.NotNil(t, info.Context)
	assert.Equal(t, "no_backend_platform", info.Context["error_type"])
	assert.Equal(t, true, info.Context["terminal"])
	assert.Equal(t, ErrorCategoryBackend, info.Category)
	assert.Equal(t, api.SeverityFatal, info.Severity)
}

func TestClassifyStderr_DriverTemperatureThresholdContext(t *testing.T) {
	info := ClassifyStderr(
		"Driver temperature threshold met on GPU #3. Expect reduced performance.",
	)

	require.NotNil(t, info.Context)
	assert.Equal(t, "temperature_limit", info.Context["error_type"])
	assert.Equal(t, 3, info.Context["device_id"])
	assert.Equal(t, ErrorCategoryDevice, info.Category)
	assert.True(t, info.Retryable)
}

func TestClassifyStderr_DeviceNotEnoughMemoryContext(t *testing.T) {
	info := ClassifyStderr(
		"* Device #2: Not enough allocatable device memory for this hashlist/ruleset.",
	)

	require.NotNil(t, info.Context)
	assert.Equal(t, "device_memory", info.Context["error_type"])
	assert.Equal(t, 2, info.Context["device_id"])
	assert.Equal(t, ErrorCategoryDevice, info.Category)
	assert.Equal(t, api.SeverityFatal, info.Severity)
}
