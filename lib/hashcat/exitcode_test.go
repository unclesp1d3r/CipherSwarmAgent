package hashcat

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	}{
		{
			name:             "exit code 0 - success/cracked",
			exitCode:         0,
			expectedCategory: ErrorCategorySuccess,
			expectedSeverity: api.SeverityInfo,
			expectedRetry:    false,
			expectedStatus:   "cracked",
		},
		{
			name:             "exit code 1 - exhausted",
			exitCode:         1,
			expectedCategory: ErrorCategorySuccess,
			expectedSeverity: api.SeverityInfo,
			expectedRetry:    false,
			expectedStatus:   "exhausted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyExitCode(tt.exitCode)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
			assert.Equal(t, tt.expectedStatus, info.Status, "status mismatch")
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
	}{
		{
			name:             "exit code 2 - aborted",
			exitCode:         2,
			expectedCategory: ErrorCategoryRetryable,
			expectedSeverity: api.SeverityMinor,
			expectedRetry:    true,
			expectedStatus:   "aborted",
		},
		{
			name:             "exit code 3 - aborted by checkpoint",
			exitCode:         3,
			expectedCategory: ErrorCategoryRetryable,
			expectedSeverity: api.SeverityMinor,
			expectedRetry:    true,
			expectedStatus:   "checkpoint",
		},
		{
			name:             "exit code 4 - aborted by runtime limit",
			exitCode:         4,
			expectedCategory: ErrorCategoryRetryable,
			expectedSeverity: api.SeverityMinor,
			expectedRetry:    true,
			expectedStatus:   "runtime_limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyExitCode(tt.exitCode)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
			assert.Equal(t, tt.expectedStatus, info.Status, "status mismatch")
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
	}{
		{
			name:             "exit code -1 - general error",
			exitCode:         -1,
			expectedCategory: ErrorCategoryUnknown,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "error",
		},
		{
			name:             "exit code -2 - GPU watchdog alarm",
			exitCode:         -2,
			expectedCategory: ErrorCategoryDevice,
			expectedSeverity: api.SeverityFatal,
			expectedRetry:    false,
			expectedStatus:   "gpu_watchdog",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyExitCode(tt.exitCode)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
			assert.Equal(t, tt.expectedStatus, info.Status, "status mismatch")
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
	}{
		{
			name:             "exit code -3 - backend abort",
			exitCode:         -3,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "backend_abort",
		},
		{
			name:             "exit code -4 - backend checkpoint abort",
			exitCode:         -4,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "backend_checkpoint",
		},
		{
			name:             "exit code -5 - backend runtime abort",
			exitCode:         -5,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "backend_runtime",
		},
		{
			name:             "exit code -6 - backend selftest fail",
			exitCode:         -6,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "selftest_fail",
		},
		{
			name:             "exit code -7 - backend autotune fail",
			exitCode:         -7,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "autotune_fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyExitCode(tt.exitCode)

			assert.Equal(t, tt.expectedCategory, info.Category, "category mismatch")
			assert.Equal(t, tt.expectedSeverity, info.Severity, "severity mismatch")
			assert.Equal(t, tt.expectedRetry, info.Retryable, "retryable mismatch")
			assert.Equal(t, tt.expectedStatus, info.Status, "status mismatch")
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
			name:             "exit code -8 backend error",
			exitCode:         -8,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "backend_error",
		},
		{
			name:             "exit code -9 backend error",
			exitCode:         -9,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "backend_error",
		},
		{
			name:             "exit code -10 backend error",
			exitCode:         -10,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "backend_error",
		},
		{
			name:             "exit code -11 backend error",
			exitCode:         -11,
			expectedCategory: ErrorCategoryBackend,
			expectedSeverity: api.SeverityCritical,
			expectedRetry:    false,
			expectedStatus:   "backend_error",
		},
		{
			name:             "exit code -12 is unknown (boundary outside backend range)",
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
		})
	}
}

func TestExitCodeInfo_Fields(t *testing.T) {
	info := ExitCodeInfo{
		Category:  ErrorCategoryDevice,
		Severity:  api.SeverityFatal,
		Retryable: false,
		Status:    "gpu_watchdog",
		ExitCode:  -2,
	}

	assert.Equal(t, ErrorCategoryDevice, info.Category)
	assert.Equal(t, api.SeverityFatal, info.Severity)
	assert.False(t, info.Retryable)
	assert.Equal(t, "gpu_watchdog", info.Status)
	assert.Equal(t, -2, info.ExitCode)
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
