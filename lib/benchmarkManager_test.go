package lib

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// TestCreateBenchmark tests the createBenchmark function.
func TestCreateBenchmark(t *testing.T) {
	tests := []struct {
		name          string
		result        benchmarkResult
		expectedError bool
		checkFields   bool
	}{
		{
			name: "valid benchmark result",
			result: benchmarkResult{
				HashType:  "0",
				RuntimeMs: "100",
				SpeedHs:   "12345.67",
				Device:    "1",
			},
			expectedError: false,
			checkFields:   true,
		},
		{
			name: "invalid hash type",
			result: benchmarkResult{
				HashType:  "invalid",
				RuntimeMs: "100",
				SpeedHs:   "12345.67",
				Device:    "1",
			},
			expectedError: true,
			checkFields:   false,
		},
		{
			name: "invalid runtime",
			result: benchmarkResult{
				HashType:  "0",
				RuntimeMs: "invalid",
				SpeedHs:   "12345.67",
				Device:    "1",
			},
			expectedError: true,
			checkFields:   false,
		},
		{
			name: "invalid speed",
			result: benchmarkResult{
				HashType:  "0",
				RuntimeMs: "100",
				SpeedHs:   "invalid",
				Device:    "1",
			},
			expectedError: true,
			checkFields:   false,
		},
		{
			name: "invalid device",
			result: benchmarkResult{
				HashType:  "0",
				RuntimeMs: "100",
				SpeedHs:   "12345.67",
				Device:    "invalid",
			},
			expectedError: true,
			checkFields:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			benchmark, err := createBenchmark(tt.result)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkFields {
					assert.Equal(t, 0, benchmark.HashType)
					assert.Equal(t, int64(100), benchmark.Runtime)
					assert.InDelta(t, 12345.67, benchmark.HashSpeed, 0.01)
					assert.Equal(t, 1, benchmark.Device)
				}
			}
		})
	}
}

// TestSendBenchmarkResults tests the sendBenchmarkResults function.
func TestSendBenchmarkResults(t *testing.T) {
	tests := []struct {
		name          string
		results       []benchmarkResult
		setupMock     func(agentID int64)
		expectedError bool
	}{
		{
			name: "successful benchmark submission",
			results: []benchmarkResult{
				{
					HashType:  "0",
					RuntimeMs: "100",
					SpeedHs:   "12345.67",
					Device:    "1",
				},
				{
					HashType:  "100",
					RuntimeMs: "200",
					SpeedHs:   "54321.09",
					Device:    "2",
				},
			},
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusNoContent, "")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern, responder)
			},
			expectedError: false,
		},
		{
			name:    "empty benchmark results",
			results: []benchmarkResult{},
			setupMock: func(_ int64) {
				// No mock needed — function returns early before API call
			},
			expectedError: true,
		},
		{
			name: "API error during submission",
			results: []benchmarkResult{
				{
					HashType:  "0",
					RuntimeMs: "100",
					SpeedHs:   "12345.67",
					Device:    "1",
				},
			},
			setupMock: func(_ int64) {
				// Use 400 Bad Request to test client error handling
				responder := httpmock.NewStringResponder(http.StatusBadRequest, "Bad Request")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern, responder)
			},
			expectedError: true,
		},
		{
			name: "benchmark results with invalid entries",
			results: []benchmarkResult{
				{
					HashType:  "0",
					RuntimeMs: "100",
					SpeedHs:   "12345.67",
					Device:    "1",
				},
				{
					HashType:  "invalid", // This should be skipped
					RuntimeMs: "200",
					SpeedHs:   "54321.09",
					Device:    "2",
				},
				{
					HashType:  "100",
					RuntimeMs: "300",
					SpeedHs:   "98765.43",
					Device:    "3",
				},
			},
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusNoContent, "")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern, responder)
			},
			expectedError: false, // Invalid entries are skipped, not causing error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			defer cleanupState()

			tt.setupMock(789)

			err := sendBenchmarkResults(tt.results)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSendBenchmarkResults_AllInvalid verifies that when every benchmark result
// fails to parse, sendBenchmarkResults returns an error indicating nothing was submitted.
func TestSendBenchmarkResults_AllInvalid(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	allInvalid := []benchmarkResult{
		{HashType: "bad", RuntimeMs: "100", SpeedHs: "100.0", Device: "1"},
		{HashType: "0", RuntimeMs: "bad", SpeedHs: "100.0", Device: "1"},
		{HashType: "0", RuntimeMs: "100", SpeedHs: "bad", Device: "1"},
	}

	err := sendBenchmarkResults(allInvalid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

// TestHandleBenchmarkStdOutLine tests parsing of hashcat benchmark stdout lines.
func TestHandleBenchmarkStdOutLine(t *testing.T) {
	tests := []struct {
		name          string
		line          string
		expectAppend  bool
		expectedCount int
	}{
		{
			name:          "valid 6-field benchmark line",
			line:          "1:0:name:100:50:12345.67",
			expectAppend:  true,
			expectedCount: 1,
		},
		{
			name:          "too few fields",
			line:          "1:0:name:100:50",
			expectAppend:  false,
			expectedCount: 0,
		},
		{
			name:          "too many fields",
			line:          "1:0:name:100:50:12345.67:extra",
			expectAppend:  false,
			expectedCount: 0,
		},
		{
			name:          "empty line",
			line:          "",
			expectAppend:  false,
			expectedCount: 0,
		},
		{
			name:          "single field",
			line:          "hello",
			expectAppend:  false,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var results []benchmarkResult
			handleBenchmarkStdOutLine(tt.line, &results)
			assert.Len(t, results, tt.expectedCount)

			if tt.expectAppend {
				assert.Equal(t, "1", results[0].Device)
				assert.Equal(t, "0", results[0].HashType)
				assert.Equal(t, "100", results[0].RuntimeMs)
				assert.Equal(t, "50", results[0].HashTimeMs)
				assert.Equal(t, "12345.67", results[0].SpeedHs)
			}
		})
	}
}

// TestHandleBenchmarkStdOutLine_MultipleLines verifies that successive valid lines
// are appended to the same results slice.
func TestHandleBenchmarkStdOutLine_MultipleLines(t *testing.T) {
	var results []benchmarkResult

	handleBenchmarkStdOutLine("1:0:md5:100:50:12345.67", &results)
	handleBenchmarkStdOutLine("2:100:sha1:200:100:54321.09", &results)
	handleBenchmarkStdOutLine("invalid:line", &results) // skipped

	assert.Len(t, results, 2)
	assert.Equal(t, "1", results[0].Device)
	assert.Equal(t, "2", results[1].Device)
}

// TestHandleBenchmarkStdErrLine tests that stderr lines are processed without panicking.
// The function calls SendAgentError, so we mock the submit_error endpoint.
func TestHandleBenchmarkStdErrLine(t *testing.T) {
	tests := []struct {
		name          string
		line          string
		expectAPICall bool
	}{
		{
			name:          "non-empty line sends error to server",
			line:          "hashcat: some warning message",
			expectAPICall: true,
		},
		{
			name:          "whitespace-only line does not send error",
			line:          "   ",
			expectAPICall: false,
		},
		{
			name:          "empty line does not send error",
			line:          "",
			expectAPICall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			defer cleanupState()

			testhelpers.MockSubmitErrorSuccess(789)

			// Should not panic
			handleBenchmarkStdErrLine(tt.line)

			if tt.expectAPICall {
				callCount := testhelpers.GetSubmitErrorCallCount(789, "https://test.api")
				assert.Positive(t, callCount, "expected submit_error API call for non-empty line")
			}
		})
	}
}

// TestCreateBenchmark_FieldMapping verifies that all fields from benchmarkResult
// are correctly mapped to the api.HashcatBenchmark struct.
func TestCreateBenchmark_FieldMapping(t *testing.T) {
	result := benchmarkResult{
		HashType:  "1000",
		RuntimeMs: "5000",
		SpeedHs:   "999999.99",
		Device:    "3",
	}

	benchmark, err := createBenchmark(result)
	require.NoError(t, err)

	assert.Equal(t, 1000, benchmark.HashType)
	assert.Equal(t, int64(5000), benchmark.Runtime)
	assert.InDelta(t, 999999.99, benchmark.HashSpeed, 0.01)
	assert.Equal(t, 3, benchmark.Device)
}

// TestUpdateBenchmarks_CachedSubmissionSuccess verifies that UpdateBenchmarks
// uses cached results when available and submission succeeds.
func TestUpdateBenchmarks_CachedSubmissionSuccess(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	// Pre-populate cache
	err := saveBenchmarkCache(sampleBenchmarkResults)
	require.NoError(t, err)

	// Mock successful benchmark submission
	pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
	httpmock.RegisterRegexpResponder("POST", pattern,
		httpmock.NewStringResponder(http.StatusNoContent, ""))

	err = UpdateBenchmarks()
	require.NoError(t, err)
	assert.True(t, agentstate.State.BenchmarksSubmitted)
}

// TestUpdateBenchmarks_CachedSubmissionFailure verifies that UpdateBenchmarks
// returns nil (non-fatal) when cached submission fails, preserving cache for retry.
func TestUpdateBenchmarks_CachedSubmissionFailure(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	// Pre-populate cache
	err := saveBenchmarkCache(sampleBenchmarkResults)
	require.NoError(t, err)

	// Mock failed benchmark submission
	pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
	httpmock.RegisterRegexpResponder("POST", pattern,
		httpmock.NewStringResponder(http.StatusInternalServerError, "Server Error"))

	err = UpdateBenchmarks()
	require.NoError(t, err, "cached submission failure should be non-fatal")
	assert.False(t, agentstate.State.BenchmarksSubmitted)

	// Cache should be preserved
	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	assert.NotNil(t, cached, "cache should be preserved for retry")
}
