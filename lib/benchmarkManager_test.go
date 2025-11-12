package lib

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
					assert.Equal(t, int64(0), benchmark.HashType)
					assert.Equal(t, int64(100), benchmark.Runtime)
					assert.InDelta(t, 12345.67, benchmark.HashSpeed, 0.01)
					assert.Equal(t, int64(1), benchmark.Device)
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
				responder := httpmock.NewStringResponder(http.StatusNoContent, "")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern, responder)
			},
			expectedError: false,
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
				// Use 400 Bad Request instead of 500 to avoid SDK retry logic causing timeouts
				responder := httpmock.NewStringResponder(http.StatusBadRequest, "Bad Request")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\\d+/submit_benchmark$`)
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
