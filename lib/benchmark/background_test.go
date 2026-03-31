package benchmark

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// bgBenchmarkSubmitPattern matches the benchmark submission API endpoint.
var bgBenchmarkSubmitPattern = regexp.MustCompile(
	`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`,
) //nolint:gochecknoglobals // test-scoped compiled regex

// --- waitForIdle tests ---

func TestWaitForIdle_AlreadyIdle(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityWaiting)

	mgr := NewManager(nil)
	cancelled := mgr.waitForIdle(context.Background())
	assert.False(t, cancelled)
}

func TestWaitForIdle_ContextCancelled(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	agentstate.State.SetCurrentActivity(agentstate.CurrentActivityBenchmarking)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mgr := NewManager(nil)
	cancelled := mgr.waitForIdle(ctx)
	assert.True(t, cancelled)
}

// --- collectSingleBenchmarkOutput tests ---

func TestCollectSingleBenchmarkOutput_Success(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	sess := hashcat.NewTestSession(true)

	go func() {
		sess.StdoutLines <- "1:0:name:100:50:12345.67"
		sess.DoneChan <- nil
	}()

	mgr := NewManager(nil)
	results := mgr.collectSingleBenchmarkOutput(context.Background(), sess)

	require.Len(t, results, 1)
	assert.Equal(t, "0", results[0].HashType)
	assert.Equal(t, "12345.67", results[0].SpeedHs)
}

func TestCollectSingleBenchmarkOutput_ContextCancelled(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	sess := hashcat.NewTestSession(true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mgr := NewManager(nil)
	results := mgr.collectSingleBenchmarkOutput(ctx, sess)

	assert.Nil(t, results)
}

func TestCollectSingleBenchmarkOutput_SessionError(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	sess := hashcat.NewTestSession(true)

	go func() {
		sess.StdoutLines <- "1:0:name:100:50:12345.67"
		sess.DoneChan <- errors.New("exit code 1")
	}()

	mgr := NewManager(nil)
	results := mgr.collectSingleBenchmarkOutput(context.Background(), sess)

	require.Len(t, results, 1)
}

func TestCollectSingleBenchmarkOutput_MultipleResults(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	sess := hashcat.NewTestSession(true)

	go func() {
		sess.StdoutLines <- "1:0:md5:100:50:50000.0"
		sess.StdoutLines <- "2:100:sha1:100:50:60000.0"
		sess.DoneChan <- nil
	}()

	mgr := NewManager(nil)
	results := mgr.collectSingleBenchmarkOutput(context.Background(), sess)

	require.Len(t, results, 2)
	assert.Equal(t, "0", results[0].HashType)
	assert.Equal(t, "100", results[1].HashType)
}

func TestCollectSingleBenchmarkOutput_NoResults(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	sess := hashcat.NewTestSession(true)

	go func() {
		sess.DoneChan <- nil
	}()

	mgr := NewManager(nil)
	results := mgr.collectSingleBenchmarkOutput(context.Background(), sess)

	assert.Empty(t, results)
}

// --- updateCacheWithResults tests ---

func TestUpdateCacheWithResults_ReplacesPlaceholder(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	t.Cleanup(cleanupHTTP)

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	t.Cleanup(cleanupState)

	initialCache := []display.BenchmarkResult{
		{HashType: "0", Device: "1", SpeedHs: "1", RuntimeMs: "0", Placeholder: true},
		{HashType: "100", Device: "1", SpeedHs: "1", RuntimeMs: "0", Placeholder: true},
	}
	err := saveBenchmarkCache(initialCache)
	require.NoError(t, err)

	httpmock.RegisterRegexpResponder("POST", bgBenchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusNoContent, ""))

	mgr := NewManager(agentstate.State.GetAPIClient().Agents())
	newResults := []display.BenchmarkResult{
		{HashType: "0", Device: "1", SpeedHs: "50000", RuntimeMs: "100"},
	}
	mgr.updateCacheWithResults(context.Background(), newResults)

	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	require.NotNil(t, cached)
	require.Len(t, cached, 2)

	for _, c := range cached {
		if c.HashType == "0" {
			assert.False(t, c.Placeholder, "replaced entry should not be placeholder")
			assert.Equal(t, "50000", c.SpeedHs)
			assert.True(t, c.Submitted)
		}
		if c.HashType == "100" {
			assert.True(t, c.Placeholder, "untouched entry should remain placeholder")
		}
	}
}

func TestUpdateCacheWithResults_EmptyResults(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	tmpDir := t.TempDir()
	agentstate.State.BenchmarkCachePath = filepath.Join(tmpDir, "benchmark_cache.json")

	initialCache := []display.BenchmarkResult{
		{HashType: "0", Device: "1", SpeedHs: "1", Placeholder: true},
	}
	err := saveBenchmarkCache(initialCache)
	require.NoError(t, err)

	mgr := NewManager(nil)
	mgr.updateCacheWithResults(context.Background(), []display.BenchmarkResult{})

	// Cache should be unchanged
	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	require.Len(t, cached, 1)
	assert.True(t, cached[0].Placeholder)
}

func TestUpdateCacheWithResults_SubmissionFails(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	t.Cleanup(cleanupHTTP)

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	t.Cleanup(cleanupState)

	initialCache := []display.BenchmarkResult{
		{HashType: "0", Device: "1", SpeedHs: "1", RuntimeMs: "0", Placeholder: true},
	}
	err := saveBenchmarkCache(initialCache)
	require.NoError(t, err)

	httpmock.RegisterRegexpResponder("POST", bgBenchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusInternalServerError, "error"))

	mgr := NewManager(agentstate.State.GetAPIClient().Agents())
	newResults := []display.BenchmarkResult{
		{HashType: "0", Device: "1", SpeedHs: "50000", RuntimeMs: "100"},
	}
	mgr.updateCacheWithResults(context.Background(), newResults)

	// Cache should have the real result saved but NOT marked as submitted
	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	require.Len(t, cached, 1)
	assert.False(t, cached[0].Placeholder, "placeholder should still be replaced in cache")
	assert.False(t, cached[0].Submitted, "should not be marked submitted since send failed")
}

func TestUpdateCacheWithResults_NilCache(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	t.Cleanup(cleanupHTTP)

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	t.Cleanup(cleanupState)

	// No cache file exists — updateCacheWithResults should attempt direct submission
	tmpDir := t.TempDir()
	agentstate.State.BenchmarkCachePath = filepath.Join(tmpDir, "benchmark_cache.json")

	httpmock.RegisterRegexpResponder("POST", bgBenchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusNoContent, ""))

	mgr := NewManager(agentstate.State.GetAPIClient().Agents())
	newResults := []display.BenchmarkResult{
		{HashType: "0", Device: "1", SpeedHs: "50000", RuntimeMs: "100"},
	}

	// Should not panic — attempts direct submission when cache is empty
	mgr.updateCacheWithResults(context.Background(), newResults)
}

// --- Capability detection output processing test ---

// TestCapabilityDetectionOutputProcessing validates the channel protocol used by
// RunCapabilityDetection without calling the actual function (which requires a
// real hashcat binary). This is a protocol-level test, not a full integration test.
func TestCapabilityDetectionOutputProcessing(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	sess := hashcat.NewTestSession(true)

	go func() {
		sess.StdoutLines <- "0 | MD5 | Raw Hash"
		sess.StdoutLines <- "100 | SHA1 | Raw Hash"
		sess.StdoutLines <- "# This is a comment"
		sess.StdoutLines <- "1000 | NTLM | Raw Hash"
		sess.DoneChan <- nil
	}()

	// Simulate the RunCapabilityDetection channel protocol
	var results []display.BenchmarkResult
	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)
		for {
			select {
			case line := <-sess.StdoutLines:
				hashTypeID, ok := parseHashInfoLine(line)
				if ok {
					results = append(results, display.BenchmarkResult{
						HashType:    hashTypeID,
						Device:      "1",
						RuntimeMs:   "0",
						HashTimeMs:  "0",
						SpeedHs:     "1",
						Placeholder: true,
					})
				}
			case <-sess.DoneChan:
				for {
					select {
					case line := <-sess.StdoutLines:
						hashTypeID, ok := parseHashInfoLine(line)
						if ok {
							results = append(results, display.BenchmarkResult{
								HashType:    hashTypeID,
								Device:      "1",
								RuntimeMs:   "0",
								HashTimeMs:  "0",
								SpeedHs:     "1",
								Placeholder: true,
							})
						}
					default:
						return
					}
				}
			}
		}
	}()

	<-waitChan

	require.Len(t, results, 3)
	assert.Equal(t, "0", results[0].HashType)
	assert.Equal(t, "100", results[1].HashType)
	assert.Equal(t, "1000", results[2].HashType)
	for _, r := range results {
		assert.True(t, r.Placeholder)
		assert.Equal(t, "1", r.SpeedHs)
		assert.Equal(t, "0", r.RuntimeMs)
	}
}

// --- RunCapabilityDetection context cancellation test ---

func TestRunCapabilityDetection_ContextCancelled(t *testing.T) {
	cleanupState := testhelpers.SetupMinimalTestState(789)
	t.Cleanup(cleanupState)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mgr := NewManager(nil)
	_, err := mgr.RunCapabilityDetection(ctx)

	// Should return an error since context was cancelled.
	// This may fail at session creation (no hashcat binary) or at context check.
	// Either way, an error should be returned.
	require.Error(t, err, "cancelled context should return an error")
}

// --- SubmitCapabilityResults tests ---

func TestSubmitCapabilityResults_Success(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	t.Cleanup(cleanupHTTP)

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	t.Cleanup(cleanupState)

	httpmock.RegisterRegexpResponder("POST", bgBenchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusNoContent, ""))

	results := []display.BenchmarkResult{
		{HashType: "0", Device: "1", RuntimeMs: "0", SpeedHs: "1", Placeholder: true},
		{HashType: "100", Device: "1", RuntimeMs: "0", SpeedHs: "1", Placeholder: true},
	}

	mgr := NewManager(agentstate.State.GetAPIClient().Agents())
	err := mgr.SubmitCapabilityResults(context.Background(), results)
	require.NoError(t, err)
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())
}

func TestSubmitCapabilityResults_SubmissionFails_CacheSaved(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	t.Cleanup(cleanupHTTP)

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	t.Cleanup(cleanupState)

	httpmock.RegisterRegexpResponder("POST", bgBenchmarkSubmitPattern,
		httpmock.NewStringResponder(http.StatusInternalServerError, "error"))

	results := []display.BenchmarkResult{
		{HashType: "0", Device: "1", RuntimeMs: "0", SpeedHs: "1", Placeholder: true},
	}

	mgr := NewManager(agentstate.State.GetAPIClient().Agents())
	err := mgr.SubmitCapabilityResults(context.Background(), results)

	// Should return nil (cache saved for retry) not an error
	require.NoError(t, err)

	// Cache should be preserved
	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	require.NotNil(t, cached)
}

// --- saveBenchmarkCacheLocked error path tests ---

func TestSaveBenchmarkCache_InvalidPath(t *testing.T) {
	// Set cache path to a directory that doesn't exist
	agentstate.State.BenchmarkCachePath = filepath.Join(t.TempDir(), "missing", "cache.json")
	t.Cleanup(func() { agentstate.State.BenchmarkCachePath = "" })

	err := saveBenchmarkCache([]display.BenchmarkResult{{HashType: "0", SpeedHs: "1"}})
	require.Error(t, err)
}

// --- trySubmitFromCache tests ---

func TestTrySubmitFromCache_CorruptCache(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	t.Cleanup(cleanupHTTP)

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	t.Cleanup(cleanupState)

	// Write corrupt JSON to cache
	require.NoError(t, os.WriteFile(agentstate.State.BenchmarkCachePath, []byte("not json"), 0o600))

	// trySubmitFromCache detects corrupt cache, then UpdateBenchmarks falls through
	// to runBenchmarks which needs a real hashcat binary. Verify cache corruption
	// is handled at the load level without panicking.
	cached, err := loadBenchmarkCache()
	require.Error(t, err)
	assert.Nil(t, cached)
	assert.ErrorIs(t, err, errCacheCorrupt)
}

func TestTrySubmitFromCache_AllSubmittedShortCircuit(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	t.Cleanup(cleanupHTTP)

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	t.Cleanup(cleanupState)

	// Pre-populate cache with all-submitted results
	submitted := []display.BenchmarkResult{
		{Device: "1", HashType: "0", RuntimeMs: "100", SpeedHs: "12345.67", Submitted: true},
	}
	err := saveBenchmarkCache(submitted)
	require.NoError(t, err)

	// No API mock — trySubmitFromCache should short-circuit without API calls
	mgr := NewManager(agentstate.State.GetAPIClient().Agents())
	err = mgr.UpdateBenchmarks(context.Background())
	require.NoError(t, err)
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())
}

// NOTE: TestUpdateBenchmarks_ForceBypassesCache requires refactoring
// runBenchmarks to accept a session factory for testability. The force-benchmark
// path calls NewHashcatSession which requires a real hashcat binary. Covered
// indirectly by existing UpdateBenchmarks cache-path tests in manager_test.go.
