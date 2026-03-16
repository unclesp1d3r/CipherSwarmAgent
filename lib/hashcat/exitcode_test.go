package hashcat

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

func TestClassifyExitCode_SuccessAndExhausted(t *testing.T) {
	tests := []struct {
		name             string
		exitCode         int
		expectedCategory ErrorCategory
		expectedSeverity api.Severity
		expectedRetry    bool
		expectedStatus   string
		expectedCtxName  string
	}{
		{
			name:             "exit code 0 - success/cracked",
			exitCode:         0,
			expectedCategory: ErrorCategorySuccess,
			expectedSeverity: api.SeverityInfo,
			expectedRetry:    false,
			expectedStatus:   "cracked",
			expectedCtxName:  "success",
		},
		{
			name:             "exit code 1 - exhausted",
			exitCode:         1,
			expectedCategory: ErrorCategorySuccess,
			expectedSeverity: api.SeverityInfo,
			expectedRetry:    false,
			expectedStatus:   "exhausted",
			expectedCtxName:  "exhausted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyExitCode(tt.exitCode)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
			assert.Equal(t, tt.expectedStatus, info.Status, "status mismatch")
			require.NotNil(t, info.Context)
			assert.Equal(t, tt.expectedCtxName, info.Context["exit_code_name"])
		})
	}
}

func TestClassifyExitCode_AbortedStates(t *testing.T) {
	tests := []struct {
		name             string
		exitCode         int
		expectedCategory ErrorCategory
		expectedSeverity api.Severity
		expectedRetry    bool
		expectedStatus   string
		expectedCtxName  string
	}{
		{
			name:             "exit code 2 - aborted",
			exitCode:         2,
			expectedCategory: ErrorCategoryRetryable,
			expectedSeverity: api.SeverityMinor,
			expectedRetry:    true,
			expectedStatus:   "aborted",
			expectedCtxName:  "aborted",
		},
		{
			name:             "exit code 3 - aborted by checkpoint",
			exitCode:         3,
			expectedCategory: ErrorCategoryRetryable,
			expectedSeverity: api.SeverityMinor,
			expectedRetry:    true,
			expectedStatus:   "checkpoint",
			expectedCtxName:  "checkpoint",
		},
		{
			name:             "exit code 4 - aborted by runtime limit",
			exitCode:         4,
			expectedCategory: ErrorCategoryRetryable,
			expectedSeverity: api.SeverityMinor,
			expectedRetry:    true,
			expectedStatus:   "runtime_limit",
			expectedCtxName:  "runtime_limit",
		},
		{
			name:             "exit code 5 - abort after finish",
			exitCode:         5,
			expectedCategory: ErrorCategoryRetryable,
			expectedSeverity: api.SeverityMinor,
			expectedRetry:    true,
			expectedStatus:   "abort_finish",
			expectedCtxName:  "abort_finish",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyExitCode(tt.exitCode)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
			assert.Equal(t, tt.expectedStatus, info.Status, "status mismatch")
			require.NotNil(t, info.Context)
			assert.Equal(t, tt.expectedCtxName, info.Context["exit_code_name"])
		})
	}
}

func TestClassifyExitCode_NegativeErrors(t *testing.T) {
	tests := []struct {
		name             string
		exitCode         int
		expectedCategory ErrorCategory
		expectedSeverity api.Severity
		expectedRetry    bool
		expectedStatus   string
		expectedCtxName  string
	}{
		{
			name:             "exit code -1 - general error",
			exitCode:         -1,
			expectedCategory: ErrorCategoryUnknown,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "error",
			expectedCtxName:  "general_error",
		},
		{
			name:             "exit code -2 - unknown (not in hashcat source)",
			exitCode:         -2,
			expectedCategory: ErrorCategoryUnknown,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "unknown",
			expectedCtxName:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyExitCode(tt.exitCode)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
			assert.Equal(t, tt.expectedStatus, info.Status, "status mismatch")
			require.NotNil(t, info.Context)
			assert.Equal(t, tt.expectedCtxName, info.Context["exit_code_name"])
		})
	}
}

func TestClassifyExitCode_BackendErrors(t *testing.T) {
	tests := []struct {
		name             string
		exitCode         int
		expectedCategory ErrorCategory
		expectedSeverity api.Severity
		expectedRetry    bool
		expectedStatus   string
		expectedCtxName  string
	}{
		{
			name:             "exit code -3 - runtime skip (all devices skipped)",
			exitCode:         -3,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "runtime_skip",
			expectedCtxName:  "runtime_skip",
		},
		{
			name:             "exit code -4 - memory hit (insufficient device memory)",
			exitCode:         -4,
			expectedCategory: ErrorCategoryDevice,
			expectedSeverity: api.SeverityFatal,
			expectedRetry:    false,
			expectedStatus:   "memory_hit",
			expectedCtxName:  "memory_hit",
		},
		{
			name:             "exit code -5 - kernel build failure",
			exitCode:         -5,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "kernel_build",
			expectedCtxName:  "kernel_build",
		},
		{
			name:             "exit code -6 - kernel create failure",
			exitCode:         -6,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "kernel_create",
			expectedCtxName:  "kernel_create",
		},
		{
			name:             "exit code -7 - kernel accel (autotune failure)",
			exitCode:         -7,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "kernel_accel",
			expectedCtxName:  "kernel_accel",
		},
		{
			name:             "exit code -8 - extra size",
			exitCode:         -8,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "extra_size",
			expectedCtxName:  "extra_size",
		},
		{
			name:             "exit code -9 - mixed warnings",
			exitCode:         -9,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "mixed_warnings",
			expectedCtxName:  "mixed_warnings",
		},
		{
			name:             "exit code -11 - selftest fail",
			exitCode:         -11,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "selftest_fail",
			expectedCtxName:  "selftest_fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyExitCode(tt.exitCode)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
			assert.Equal(t, tt.expectedStatus, info.Status, "status mismatch")
			require.NotNil(t, info.Context)
			assert.Equal(t, tt.expectedCtxName, info.Context["exit_code_name"])
		})
	}
}

func TestClassifyExitCode_UnknownCodes(t *testing.T) {
	tests := []struct {
		name             string
		exitCode         int
		expectedCategory ErrorCategory
		expectedSeverity api.Severity
		expectedRetry    bool
		expectedStatus   string
	}{
		{
			name:             "unknown positive code",
			exitCode:         99,
			expectedCategory: ErrorCategoryUnknown,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "unknown",
		},
		{
			name:             "unknown negative code",
			exitCode:         -99,
			expectedCategory: ErrorCategoryUnknown,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "unknown",
		},
		{
			name:             "exit code -10 is unknown (gap in hashcat codes)",
			exitCode:         -10,
			expectedCategory: ErrorCategoryUnknown,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "unknown",
		},
		{
			name:             "exit code -12 is unknown",
			exitCode:         -12,
			expectedCategory: ErrorCategoryUnknown,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyExitCode(tt.exitCode)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
			assert.Equal(t, tt.expectedStatus, info.Status, "status mismatch")
			require.NotNil(t, info.Context)
			assert.Equal(t, "unknown", info.Context["exit_code_name"])
		})
	}
}

func TestExitCodeInfo_ContextField(t *testing.T) {
	info := ClassifyExitCode(ExitCodeKernelBuild)

	require.NotNil(t, info.Context)
	assert.Equal(t, "kernel_build", info.Context["exit_code_name"])
	assert.Equal(t, ErrorCategoryBackend, info.Category)
	assert.Equal(t, "kernel_build", info.Status)
	assert.Equal(t, -5, info.ExitCode)
}

func TestIsExhausted(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		expected bool
	}{
		{"exit code 0 is not exhausted", 0, false},
		{"exit code 1 is exhausted", 1, true},
		{"exit code 2 is not exhausted", 2, false},
		{"exit code -1 is not exhausted", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsExhausted(tt.exitCode))
		})
	}
}

func TestIsSuccess(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		expected bool
	}{
		{"exit code 0 is success", 0, true},
		{"exit code 1 is not success", 1, false},
		{"exit code 2 is not success", 2, false},
		{"exit code -1 is not success", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsSuccess(tt.exitCode))
		})
	}
}

func TestIsNormalCompletion(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		expected bool
	}{
		{"exit code 0 is normal completion", 0, true},
		{"exit code 1 is normal completion", 1, true},
		{"exit code 2 is not normal completion", 2, false},
		{"exit code -1 is not normal completion", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsNormalCompletion(tt.exitCode))
		})
	}
}
