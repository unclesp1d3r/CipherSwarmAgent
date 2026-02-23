package benchmark

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// benchmarkSubmitPattern matches the benchmark submission API endpoint.
var benchmarkSubmitPattern = regexp.MustCompile(
	`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`,
)

// makeBenchmarkLine creates a valid 6-field hashcat benchmark output line
// for the given device ID, hash type, and speed.
func makeBenchmarkLine(device, hashType int, speed float64) string {
	return fmt.Sprintf("%d:%d:name:100:50:%.2f", device, hashType, speed)
}

// makeBenchmarkLines creates n valid benchmark output lines using the given
// device ID, with hash types 0..n-1 and speeds derived from the index.
func makeBenchmarkLines(n, device int) []string {
	lines := make([]string, n)
	for i := range n {
		lines[i] = makeBenchmarkLine(device, i, float64(i*1000))
	}

	return lines
}

// TestCreateBenchmark tests the createBenchmark function.
func TestCreateBenchmark(t *testing.T) {
	tests := []struct {
		name          string
		result        display.BenchmarkResult
		expectedError bool
		checkFields   bool
	}{
		{
			name: "valid benchmark result",
			result: display.BenchmarkResult{
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
			result: display.BenchmarkResult{
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
			result: display.BenchmarkResult{
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
			result: display.BenchmarkResult{
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
			result: display.BenchmarkResult{
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
				require.Error(t, err)
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
		results       []display.BenchmarkResult
		setupMock     func(agentID int64)
		expectedError bool
	}{
		{
			name: "successful benchmark submission",
			results: []display.BenchmarkResult{
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
				httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
					httpmock.NewStringResponder(http.StatusNoContent, ""))
			},
			expectedError: false,
		},
		{
			name:    "empty benchmark results",
			results: []display.BenchmarkResult{},
			setupMock: func(_ int64) {
				// No mock needed — function returns early before API call
			},
			expectedError: true,
		},
		{
			name: "API error during submission",
			results: []display.BenchmarkResult{
				{
					HashType:  "0",
					RuntimeMs: "100",
					SpeedHs:   "12345.67",
					Device:    "1",
				},
			},
			setupMock: func(_ int64) {
				// Use 400 Bad Request to test client error handling
				httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
					httpmock.NewStringResponder(http.StatusBadRequest, "Bad Request"))
			},
			expectedError: true,
		},
		{
			name: "benchmark results with invalid entries",
			results: []display.BenchmarkResult{
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
				httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
					httpmock.NewStringResponder(http.StatusNoContent, ""))
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

			mgr := NewManager(agentstate.State.APIClient.Agents())
			err := mgr.sendBenchmarkResults(context.Background(), tt.results)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
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

	allInvalid := []display.BenchmarkResult{
		{HashType: "bad", RuntimeMs: "100", SpeedHs: "100.0", Device: "1"},
		{HashType: "0", RuntimeMs: "bad", SpeedHs: "100.0", Device: "1"},
		{HashType: "0", RuntimeMs: "100", SpeedHs: "bad", Device: "1"},
	}

	mgr := NewManager(agentstate.State.APIClient.Agents())
	err := mgr.sendBenchmarkResults(context.Background(), allInvalid)
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
			var results []display.BenchmarkResult
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
	var results []display.BenchmarkResult

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

// TestCreateBenchmark_FieldMapping verifies that all fields from display.BenchmarkResult
// are correctly mapped to the api.HashcatBenchmark struct.
func TestCreateBenchmark_FieldMapping(t *testing.T) {
	result := display.BenchmarkResult{
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
	httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusNoContent, ""))

	mgr := NewManager(agentstate.State.APIClient.Agents())
	err = mgr.UpdateBenchmarks(context.Background())
	require.NoError(t, err)
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())
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
	httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusInternalServerError, "Server Error"))

	mgr := NewManager(agentstate.State.APIClient.Agents())
	err = mgr.UpdateBenchmarks(context.Background())
	require.NoError(t, err, "cached submission failure should be non-fatal")
	assert.False(t, agentstate.State.GetBenchmarksSubmitted())

	// Cache should be preserved
	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	assert.NotNil(t, cached, "cache should be preserved for retry")
}

// TestUpdateBenchmarks_CachedAllAlreadySubmitted verifies that UpdateBenchmarks
// skips submission when all cached results are already marked as submitted.
func TestUpdateBenchmarks_CachedAllAlreadySubmitted(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	// Pre-populate cache with all-submitted results
	submitted := []display.BenchmarkResult{
		{Device: "1", HashType: "0", RuntimeMs: "100", HashTimeMs: "50", SpeedHs: "12345.67", Submitted: true},
		{Device: "2", HashType: "100", RuntimeMs: "200", HashTimeMs: "100", SpeedHs: "54321.09", Submitted: true},
	}
	err := saveBenchmarkCache(submitted)
	require.NoError(t, err)

	// No API mock needed — should not make any calls
	mgr := NewManager(agentstate.State.APIClient.Agents())
	err = mgr.UpdateBenchmarks(context.Background())
	require.NoError(t, err)
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())

	// Cache should be cleared
	_, statErr := os.Stat(agentstate.State.BenchmarkCachePath)
	assert.True(t, os.IsNotExist(statErr), "cache should be cleared")
}

// TestUpdateBenchmarks_CachedPartiallySubmitted verifies that UpdateBenchmarks
// only sends unsubmitted results from a partially submitted cache.
func TestUpdateBenchmarks_CachedPartiallySubmitted(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	// Pre-populate cache with mixed submitted/unsubmitted
	mixed := []display.BenchmarkResult{
		{Device: "1", HashType: "0", RuntimeMs: "100", HashTimeMs: "50", SpeedHs: "12345.67", Submitted: true},
		{Device: "2", HashType: "100", RuntimeMs: "200", HashTimeMs: "100", SpeedHs: "54321.09"},
	}
	err := saveBenchmarkCache(mixed)
	require.NoError(t, err)

	httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusNoContent, ""))

	mgr := NewManager(agentstate.State.APIClient.Agents())
	err = mgr.UpdateBenchmarks(context.Background())
	require.NoError(t, err)
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())
}

// --- Helper function tests ---

// TestUnsubmittedResults tests filtering of benchmark results by Submitted flag.
func TestUnsubmittedResults(t *testing.T) {
	tests := []struct {
		name     string
		input    []display.BenchmarkResult
		expected int
	}{
		{
			name:     "all unsubmitted",
			input:    []display.BenchmarkResult{{HashType: "0"}, {HashType: "1"}},
			expected: 2,
		},
		{
			name:     "all submitted",
			input:    []display.BenchmarkResult{{HashType: "0", Submitted: true}, {HashType: "1", Submitted: true}},
			expected: 0,
		},
		{
			name:     "mixed",
			input:    []display.BenchmarkResult{{HashType: "0", Submitted: true}, {HashType: "1"}},
			expected: 1,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: 0,
		},
		{
			name:     "empty input",
			input:    []display.BenchmarkResult{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := unsubmittedResults(tt.input)
			assert.Len(t, result, tt.expected)
		})
	}
}

// TestAllSubmitted tests the allSubmitted predicate.
func TestAllSubmitted(t *testing.T) {
	tests := []struct {
		name     string
		input    []display.BenchmarkResult
		expected bool
	}{
		{name: "all submitted", input: []display.BenchmarkResult{{Submitted: true}, {Submitted: true}}, expected: true},
		{name: "none submitted", input: []display.BenchmarkResult{{}, {}}, expected: false},
		{name: "mixed", input: []display.BenchmarkResult{{Submitted: true}, {}}, expected: false},
		{name: "nil", input: nil, expected: true},
		{name: "empty", input: []display.BenchmarkResult{}, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, allSubmitted(tt.input))
		})
	}
}

// TestMarkSubmitted tests marking a range of results as submitted.
func TestMarkSubmitted(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		startIdx int
		endIdx   int
		expected []bool
	}{
		{
			name:     "mark middle range",
			count:    4,
			startIdx: 1,
			endIdx:   3,
			expected: []bool{false, true, true, false},
		},
		{
			name:     "endIdx beyond length",
			count:    2,
			startIdx: 0,
			endIdx:   5,
			expected: []bool{true, true},
		},
		{
			name:     "empty range",
			count:    2,
			startIdx: 1,
			endIdx:   1,
			expected: []bool{false, false},
		},
		{
			name:     "mark all",
			count:    3,
			startIdx: 0,
			endIdx:   3,
			expected: []bool{true, true, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := make([]display.BenchmarkResult, tt.count)
			markSubmitted(results, tt.startIdx, tt.endIdx)
			for i, r := range results {
				assert.Equal(t, tt.expected[i], r.Submitted, "index %d", i)
			}
		})
	}
}

// --- processBenchmarkOutput tests ---

// TestProcessBenchmarkOutput_AllBatchesSucceed verifies that multiple batches
// are sent and all results are marked as Submitted.
func TestProcessBenchmarkOutput_AllBatchesSucceed(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	var callCount atomic.Int32
	httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
		func(_ *http.Request) (*http.Response, error) {
			callCount.Add(1)
			return httpmock.NewStringResponse(http.StatusNoContent, ""), nil
		})

	sess, err := testhelpers.NewMockSession("bench-test")
	require.NoError(t, err)

	lines := makeBenchmarkLines(15, 1)

	go func() {
		for _, line := range lines {
			sess.StdoutLines <- line
		}
		sess.DoneChan <- nil
	}()

	mgr := NewManager(agentstate.State.APIClient.Agents())
	results := mgr.processBenchmarkOutput(context.Background(), sess)

	assert.Len(t, results, 15)
	assert.True(t, allSubmitted(results), "all results should be marked as submitted")
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())
	assert.Equal(t, int32(2), callCount.Load(), "expected 2 API calls (batch of 10 + final 5)")
}

// TestProcessBenchmarkOutput_SingleBatch verifies that fewer than benchmarkBatchSize
// results are submitted as a single final batch.
func TestProcessBenchmarkOutput_SingleBatch(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	var callCount atomic.Int32
	httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
		func(_ *http.Request) (*http.Response, error) {
			callCount.Add(1)
			return httpmock.NewStringResponse(http.StatusNoContent, ""), nil
		})

	sess, err := testhelpers.NewMockSession("bench-test")
	require.NoError(t, err)

	lines := makeBenchmarkLines(5, 2)

	go func() {
		for _, line := range lines {
			sess.StdoutLines <- line
		}
		sess.DoneChan <- nil
	}()

	mgr := NewManager(agentstate.State.APIClient.Agents())
	results := mgr.processBenchmarkOutput(context.Background(), sess)

	assert.Len(t, results, 5)
	assert.True(t, allSubmitted(results))
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())
	assert.Equal(t, int32(1), callCount.Load(), "expected 1 API call (final batch only)")
}

// TestProcessBenchmarkOutput_BatchFailsFinalSucceeds verifies that when the first
// batch fails, the final send includes all unsubmitted results and marks them.
func TestProcessBenchmarkOutput_BatchFailsFinalSucceeds(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	// First call fails, second succeeds
	var callCount atomic.Int32
	httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
		func(_ *http.Request) (*http.Response, error) {
			n := callCount.Add(1)
			if n == 1 {
				return httpmock.NewStringResponse(http.StatusInternalServerError, "error"), nil
			}
			return httpmock.NewStringResponse(http.StatusNoContent, ""), nil
		})

	lines := makeBenchmarkLines(15, 3)

	sess, err := testhelpers.NewMockSession("bench-test")
	require.NoError(t, err)

	go func() {
		for _, line := range lines {
			sess.StdoutLines <- line
		}
		sess.DoneChan <- nil
	}()

	mgr := NewManager(agentstate.State.APIClient.Agents())
	results := mgr.processBenchmarkOutput(context.Background(), sess)

	assert.Len(t, results, 15)
	// First batch (10 items) fails, retry triggers on next line (11 items), succeeds.
	// Final batch sends remaining items on DoneChan.
	assert.True(t, allSubmitted(results), "all results should be submitted after retry")
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())
	assert.GreaterOrEqual(t, callCount.Load(), int32(2), "at least 2 API calls expected")
}

// TestProcessBenchmarkOutput_AllSendsFail verifies that BenchmarksSubmitted
// stays false when all submissions fail.
func TestProcessBenchmarkOutput_AllSendsFail(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusInternalServerError, "error"))

	sess, err := testhelpers.NewMockSession("bench-test")
	require.NoError(t, err)

	lines := makeBenchmarkLines(15, 4)

	go func() {
		for _, line := range lines {
			sess.StdoutLines <- line
		}
		sess.DoneChan <- nil
	}()

	mgr := NewManager(agentstate.State.APIClient.Agents())
	results := mgr.processBenchmarkOutput(context.Background(), sess)

	assert.Len(t, results, 15)
	assert.False(t, allSubmitted(results), "no results should be marked submitted")
	assert.False(t, agentstate.State.GetBenchmarksSubmitted())

	// Cache should be saved with all unsubmitted
	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	require.NotNil(t, cached)
	assert.False(t, allSubmitted(cached))
}

// TestProcessBenchmarkOutput_EmptyResults verifies behavior when the session
// completes without producing any results.
func TestProcessBenchmarkOutput_EmptyResults(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	sess, err := testhelpers.NewMockSession("bench-test")
	require.NoError(t, err)

	go func() {
		sess.DoneChan <- nil
	}()

	mgr := NewManager(agentstate.State.APIClient.Agents())
	results := mgr.processBenchmarkOutput(context.Background(), sess)

	assert.Empty(t, results)
	assert.True(t, agentstate.State.GetBenchmarksSubmitted(), "nothing to submit = done")
}

// TestProcessBenchmarkOutput_SessionError verifies that session errors are
// reported and partial results are still cached.
func TestProcessBenchmarkOutput_SessionError(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	httpmock.RegisterRegexpResponder("POST", benchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusNoContent, ""))
	testhelpers.MockSubmitErrorSuccess(789)

	sess, err := testhelpers.NewMockSession("bench-test")
	require.NoError(t, err)

	lines := makeBenchmarkLines(5, 5)

	go func() {
		for _, line := range lines {
			sess.StdoutLines <- line
		}
		sess.DoneChan <- errors.New("hashcat process exited with code 1")
	}()

	mgr := NewManager(agentstate.State.APIClient.Agents())
	results := mgr.processBenchmarkOutput(context.Background(), sess)

	assert.Len(t, results, 5)
	assert.True(t, allSubmitted(results), "results should still be submitted despite error")
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())

	// Verify error was reported
	callCount := testhelpers.GetSubmitErrorCallCount(789, "https://test.api")
	assert.Positive(t, callCount, "session error should be reported")
}
