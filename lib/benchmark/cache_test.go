package benchmark

import (
	"context"
	"encoding/json"
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
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// newSampleBenchmarkResults returns a fresh slice of benchmark results for each
// test invocation. This prevents mutation (e.g., Submitted flag changes) from
// leaking across subtests.
func newSampleBenchmarkResults() []display.BenchmarkResult {
	return []display.BenchmarkResult{
		{
			Device:     "1",
			HashType:   "0",
			RuntimeMs:  "100",
			HashTimeMs: "50",
			SpeedHs:    "12345.67",
		},
		{
			Device:     "2",
			HashType:   "100",
			RuntimeMs:  "200",
			HashTimeMs: "100",
			SpeedHs:    "54321.09",
		},
	}
}

func TestSaveBenchmarkCache(t *testing.T) {
	tests := []struct {
		name        string
		results     []display.BenchmarkResult
		setupPath   bool
		expectError bool
	}{
		{
			name:        "saves valid results",
			results:     newSampleBenchmarkResults(),
			setupPath:   true,
			expectError: false,
		},
		{
			name:        "empty cache path returns error",
			results:     newSampleBenchmarkResults(),
			setupPath:   false,
			expectError: true,
		},
		{
			name:        "saves empty slice",
			results:     []display.BenchmarkResult{},
			setupPath:   true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if tt.setupPath {
				agentstate.State.BenchmarkCachePath = filepath.Join(tmpDir, "benchmark_cache.json")
			} else {
				agentstate.State.BenchmarkCachePath = ""
			}

			defer func() { agentstate.State.BenchmarkCachePath = "" }()

			err := saveBenchmarkCache(tt.results)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify the file was written and is valid JSON
			data, readErr := os.ReadFile(agentstate.State.BenchmarkCachePath)
			require.NoError(t, readErr)

			var loaded []display.BenchmarkResult
			require.NoError(t, json.Unmarshal(data, &loaded))
			assert.Equal(t, tt.results, loaded)
		})
	}
}

func TestSaveBenchmarkCache_AtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "benchmark_cache.json")
	agentstate.State.BenchmarkCachePath = cachePath

	defer func() { agentstate.State.BenchmarkCachePath = "" }()

	err := saveBenchmarkCache(newSampleBenchmarkResults())
	require.NoError(t, err)

	// Verify no temp file is left behind
	tmpPath := cachePath + ".tmp"
	_, statErr := os.Stat(tmpPath)
	assert.True(t, os.IsNotExist(statErr), "temp file should not exist after successful save")
}

// TestSaveBenchmarkCache_SubmittedField verifies that the Submitted flag is
// correctly persisted and loaded from the cache.
func TestSaveBenchmarkCache_SubmittedField(t *testing.T) {
	tmpDir := t.TempDir()
	agentstate.State.BenchmarkCachePath = filepath.Join(tmpDir, "benchmark_cache.json")

	defer func() { agentstate.State.BenchmarkCachePath = "" }()

	results := []display.BenchmarkResult{
		{Device: "1", HashType: "0", RuntimeMs: "100", HashTimeMs: "50", SpeedHs: "100.0", Submitted: true},
		{Device: "2", HashType: "1", RuntimeMs: "200", HashTimeMs: "100", SpeedHs: "200.0"},
	}

	err := saveBenchmarkCache(results)
	require.NoError(t, err)

	loaded, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	require.Len(t, loaded, 2)
	assert.True(t, loaded[0].Submitted, "first result should be marked submitted")
	assert.False(t, loaded[1].Submitted, "second result should not be marked submitted")
}

func TestLoadBenchmarkCache(t *testing.T) {
	tests := []struct {
		name          string
		setupCache    func(t *testing.T, dir string) string
		expectResults bool
		expectError   bool
		resultCount   int
	}{
		{
			name: "loads valid cache",
			setupCache: func(t *testing.T, dir string) string {
				t.Helper()
				p := filepath.Join(dir, "benchmark_cache.json")
				data, err := json.Marshal(newSampleBenchmarkResults())
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(p, data, 0o600))
				return p
			},
			expectResults: true,
			expectError:   false,
			resultCount:   2,
		},
		{
			name: "returns nil for nonexistent file",
			setupCache: func(_ *testing.T, dir string) string {
				return filepath.Join(dir, "nonexistent.json")
			},
			expectResults: false,
			expectError:   false,
		},
		{
			name: "returns nil for corrupt JSON",
			setupCache: func(t *testing.T, dir string) string {
				t.Helper()
				p := filepath.Join(dir, "benchmark_cache.json")
				require.NoError(t, os.WriteFile(p, []byte("not json"), 0o600))
				return p
			},
			expectResults: false,
			expectError:   false,
		},
		{
			name: "returns nil for empty array",
			setupCache: func(t *testing.T, dir string) string {
				t.Helper()
				p := filepath.Join(dir, "benchmark_cache.json")
				require.NoError(t, os.WriteFile(p, []byte("[]"), 0o600))
				return p
			},
			expectResults: false,
			expectError:   false,
		},
		{
			name: "returns nil for empty cache path",
			setupCache: func(_ *testing.T, _ string) string {
				return ""
			},
			expectResults: false,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			agentstate.State.BenchmarkCachePath = tt.setupCache(t, tmpDir)

			defer func() { agentstate.State.BenchmarkCachePath = "" }()

			results, err := loadBenchmarkCache()

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.expectResults {
				require.NotNil(t, results)
				assert.Len(t, results, tt.resultCount)
			} else {
				assert.Nil(t, results)
			}
		})
	}
}

// TestLoadBenchmarkCache_BackwardCompatible verifies that old cache files without
// the Submitted field load correctly with Submitted defaulting to false.
func TestLoadBenchmarkCache_BackwardCompatible(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "benchmark_cache.json")
	agentstate.State.BenchmarkCachePath = cachePath

	defer func() { agentstate.State.BenchmarkCachePath = "" }()

	// Write JSON without Submitted field (simulates old cache format)
	oldFormat := `[{"device":"1","hash_type":"0","runtime":"100","hash_time":"50","hash_speed":"12345.67"}]`
	require.NoError(t, os.WriteFile(cachePath, []byte(oldFormat), 0o600))

	loaded, err := loadBenchmarkCache()
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.False(t, loaded[0].Submitted, "old cache entries should default to unsubmitted")
}

func TestSaveThenLoadBenchmarkCache(t *testing.T) {
	tmpDir := t.TempDir()
	agentstate.State.BenchmarkCachePath = filepath.Join(tmpDir, "benchmark_cache.json")

	defer func() { agentstate.State.BenchmarkCachePath = "" }()

	err := saveBenchmarkCache(newSampleBenchmarkResults())
	require.NoError(t, err)

	loaded, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	require.NotNil(t, loaded)
	assert.Equal(t, newSampleBenchmarkResults(), loaded)
}

func TestCacheAndSubmitBenchmarks(t *testing.T) {
	tests := []struct {
		name                   string
		results                []display.BenchmarkResult
		setupCachePath         func(t *testing.T) string
		setupMock              func()
		expectError            bool
		expectBenchmarksSubmit bool
	}{
		{
			name:    "cache saved and submission succeeds",
			results: newSampleBenchmarkResults(),
			setupCachePath: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "benchmark_cache.json")
			},
			setupMock: func() {
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern,
					httpmock.NewStringResponder(http.StatusNoContent, ""))
			},
			expectError:            false,
			expectBenchmarksSubmit: true,
		},
		{
			name:    "cache saved but submission fails returns nil for retry",
			results: newSampleBenchmarkResults(),
			setupCachePath: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "benchmark_cache.json")
			},
			setupMock: func() {
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern,
					httpmock.NewStringResponder(http.StatusInternalServerError, "Server Error"))
			},
			expectError:            false,
			expectBenchmarksSubmit: false,
		},
		{
			name:    "cache write failure and submission failure returns error",
			results: newSampleBenchmarkResults(),
			setupCachePath: func(_ *testing.T) string {
				// Empty path causes saveBenchmarkCache to fail
				return ""
			},
			setupMock: func() {
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern,
					httpmock.NewStringResponder(http.StatusInternalServerError, "Server Error"))
			},
			expectError:            true,
			expectBenchmarksSubmit: false,
		},
		{
			name:    "cache write failure but submission succeeds",
			results: newSampleBenchmarkResults(),
			setupCachePath: func(_ *testing.T) string {
				return ""
			},
			setupMock: func() {
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern,
					httpmock.NewStringResponder(http.StatusNoContent, ""))
			},
			expectError:            false,
			expectBenchmarksSubmit: true,
		},
		{
			name: "all already submitted skips send",
			results: []display.BenchmarkResult{
				{Device: "1", HashType: "0", RuntimeMs: "100", SpeedHs: "100.0", Submitted: true},
				{Device: "2", HashType: "1", RuntimeMs: "200", SpeedHs: "200.0", Submitted: true},
			},
			setupCachePath: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "benchmark_cache.json")
			},
			setupMock:              func() {},
			expectError:            false,
			expectBenchmarksSubmit: true,
		},
		{
			name: "partially submitted sends only unsubmitted",
			results: []display.BenchmarkResult{
				{Device: "1", HashType: "0", RuntimeMs: "100", SpeedHs: "100.0", Submitted: true},
				{Device: "2", HashType: "1", RuntimeMs: "200", SpeedHs: "200.0"},
			},
			setupCachePath: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "benchmark_cache.json")
			},
			setupMock: func() {
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern,
					httpmock.NewStringResponder(http.StatusNoContent, ""))
			},
			expectError:            false,
			expectBenchmarksSubmit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			defer cleanupState()

			agentstate.State.BenchmarkCachePath = tt.setupCachePath(t)
			agentstate.State.SetBenchmarksSubmitted(false)

			tt.setupMock()

			mgr := NewManager(agentstate.State.APIClient.Agents())
			err := mgr.cacheAndSubmitBenchmarks(context.Background(), tt.results)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "benchmark submission failed with no cache for retry")
				assert.False(t, agentstate.State.GetBenchmarksSubmitted(),
					"BenchmarksSubmitted must remain false when error is returned")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectBenchmarksSubmit, agentstate.State.GetBenchmarksSubmitted())
			}
		})
	}
}

func TestTrySubmitCachedBenchmarks(t *testing.T) {
	tests := []struct {
		name           string
		setupCache     bool
		forceBenchmark bool
		setupMock      func()
		expectSuccess  bool
		expectSubmit   bool
	}{
		{
			name:       "succeeds with valid cache and server accepts",
			setupCache: true,
			setupMock: func() {
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern,
					httpmock.NewStringResponder(http.StatusNoContent, ""))
			},
			expectSuccess: true,
			expectSubmit:  true,
		},
		{
			name:          "returns false when no cache exists",
			setupCache:    false,
			setupMock:     func() {},
			expectSuccess: false,
			expectSubmit:  false,
		},
		{
			name:       "returns false when server rejects",
			setupCache: true,
			setupMock: func() {
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
				httpmock.RegisterRegexpResponder("POST", pattern,
					httpmock.NewStringResponder(http.StatusInternalServerError, "Server Error"))
			},
			expectSuccess: false,
			expectSubmit:  false,
		},
		{
			name:           "returns false when force benchmark is set",
			setupCache:     true,
			forceBenchmark: true,
			setupMock:      func() {},
			expectSuccess:  false,
			expectSubmit:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			defer cleanupState()

			if tt.forceBenchmark {
				agentstate.State.ForceBenchmarkRun = true
				defer func() { agentstate.State.ForceBenchmarkRun = false }()
			}

			if tt.setupCache {
				err := saveBenchmarkCache(newSampleBenchmarkResults())
				require.NoError(t, err)
			}

			tt.setupMock()

			mgr := NewManager(agentstate.State.APIClient.Agents())
			result := mgr.TrySubmitCachedBenchmarks(context.Background())
			assert.Equal(t, tt.expectSuccess, result)

			if tt.expectSubmit {
				assert.True(t, agentstate.State.GetBenchmarksSubmitted())
				// Cache should be preserved with all results marked as submitted
				cached, err := loadBenchmarkCache()
				require.NoError(t, err, "cache should be preserved after successful submission")
				require.NotNil(t, cached)
				assert.True(t, allSubmitted(cached), "all cached results should be marked as submitted")
			}

			if !tt.expectSuccess && tt.setupCache && !tt.forceBenchmark {
				// Cache should be preserved on failure
				_, err := os.Stat(agentstate.State.BenchmarkCachePath)
				assert.NoError(t, err, "cache should be preserved on submission failure")
			}
		})
	}
}

// TestTrySubmitCachedBenchmarks_AllSubmittedInCache verifies that when all
// cached results are already marked as submitted, no API call is made.
func TestTrySubmitCachedBenchmarks_AllSubmittedInCache(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	submitted := []display.BenchmarkResult{
		{Device: "1", HashType: "0", RuntimeMs: "100", SpeedHs: "100.0", Submitted: true},
		{Device: "2", HashType: "1", RuntimeMs: "200", SpeedHs: "200.0", Submitted: true},
	}
	err := saveBenchmarkCache(submitted)
	require.NoError(t, err)

	// No API mock — should not make any calls
	mgr := NewManager(agentstate.State.APIClient.Agents())
	result := mgr.TrySubmitCachedBenchmarks(context.Background())
	assert.True(t, result)
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())

	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr, "cache should be preserved")
	require.NotNil(t, cached)
	assert.True(t, allSubmitted(cached), "all cached results should be marked as submitted")
}

// TestTrySubmitCachedBenchmarks_PartiallySubmitted verifies that only
// unsubmitted items are sent from a partially submitted cache.
func TestTrySubmitCachedBenchmarks_PartiallySubmitted(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	mixed := []display.BenchmarkResult{
		{Device: "1", HashType: "0", RuntimeMs: "100", SpeedHs: "100.0", Submitted: true},
		{Device: "2", HashType: "1", RuntimeMs: "200", SpeedHs: "200.0"},
	}
	err := saveBenchmarkCache(mixed)
	require.NoError(t, err)

	pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
	httpmock.RegisterRegexpResponder("POST", pattern,
		httpmock.NewStringResponder(http.StatusNoContent, ""))

	mgr := NewManager(agentstate.State.APIClient.Agents())
	result := mgr.TrySubmitCachedBenchmarks(context.Background())
	assert.True(t, result)
	assert.True(t, agentstate.State.GetBenchmarksSubmitted())

	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr, "cache should be preserved after submission")
	require.NotNil(t, cached)
	assert.True(t, allSubmitted(cached), "all cached results should be marked as submitted")
}

// TestTrySubmitCachedBenchmarks_MixedCacheServerFailure verifies that when
// the server rejects a submission of unsubmitted items, the cache is preserved.
func TestTrySubmitCachedBenchmarks_MixedCacheServerFailure(t *testing.T) {
	cleanupHTTP := testhelpers.SetupHTTPMock()
	defer cleanupHTTP()

	cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
	defer cleanupState()

	mixed := []display.BenchmarkResult{
		{Device: "1", HashType: "0", RuntimeMs: "100", SpeedHs: "100.0", Submitted: true},
		{Device: "2", HashType: "1", RuntimeMs: "200", SpeedHs: "200.0"},
	}
	err := saveBenchmarkCache(mixed)
	require.NoError(t, err)

	pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/agents/\d+/submit_benchmark$`)
	httpmock.RegisterRegexpResponder("POST", pattern,
		httpmock.NewStringResponder(http.StatusInternalServerError, "error"))

	mgr := NewManager(agentstate.State.APIClient.Agents())
	result := mgr.TrySubmitCachedBenchmarks(context.Background())
	assert.False(t, result)
	assert.False(t, agentstate.State.GetBenchmarksSubmitted())

	// Cache should be preserved with original flags
	cached, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	require.Len(t, cached, 2)
	assert.True(t, cached[0].Submitted, "first item should still be marked submitted")
	assert.False(t, cached[1].Submitted, "second item should still be unsubmitted")
}
