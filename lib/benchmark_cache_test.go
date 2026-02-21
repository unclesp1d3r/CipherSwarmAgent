package lib

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

var sampleBenchmarkResults = []benchmarkResult{
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

func TestSaveBenchmarkCache(t *testing.T) {
	tests := []struct {
		name        string
		results     []benchmarkResult
		setupPath   bool
		expectError bool
	}{
		{
			name:        "saves valid results",
			results:     sampleBenchmarkResults,
			setupPath:   true,
			expectError: false,
		},
		{
			name:        "empty cache path returns error",
			results:     sampleBenchmarkResults,
			setupPath:   false,
			expectError: true,
		},
		{
			name:        "saves empty slice",
			results:     []benchmarkResult{},
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
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify the file was written and is valid JSON
			data, readErr := os.ReadFile(agentstate.State.BenchmarkCachePath)
			require.NoError(t, readErr)

			var loaded []benchmarkResult
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

	err := saveBenchmarkCache(sampleBenchmarkResults)
	require.NoError(t, err)

	// Verify no temp file is left behind
	tmpPath := cachePath + ".tmp"
	_, statErr := os.Stat(tmpPath)
	assert.True(t, os.IsNotExist(statErr), "temp file should not exist after successful save")
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
				data, err := json.Marshal(sampleBenchmarkResults)
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
				assert.Error(t, err)
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

func TestClearBenchmarkCache(t *testing.T) {
	tests := []struct {
		name       string
		setupCache func(t *testing.T, dir string) string
	}{
		{
			name: "removes existing cache file",
			setupCache: func(t *testing.T, dir string) string {
				t.Helper()
				p := filepath.Join(dir, "benchmark_cache.json")
				require.NoError(t, os.WriteFile(p, []byte("[]"), 0o600))
				return p
			},
		},
		{
			name: "no-op for nonexistent file",
			setupCache: func(_ *testing.T, dir string) string {
				return filepath.Join(dir, "nonexistent.json")
			},
		},
		{
			name: "no-op for empty path",
			setupCache: func(_ *testing.T, _ string) string {
				return ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			agentstate.State.BenchmarkCachePath = tt.setupCache(t, tmpDir)

			defer func() { agentstate.State.BenchmarkCachePath = "" }()

			// Should not panic
			clearBenchmarkCache()

			if agentstate.State.BenchmarkCachePath != "" {
				_, err := os.Stat(agentstate.State.BenchmarkCachePath)
				assert.True(t, os.IsNotExist(err), "cache file should be removed")
			}
		})
	}
}

func TestSaveThenLoadBenchmarkCache(t *testing.T) {
	tmpDir := t.TempDir()
	agentstate.State.BenchmarkCachePath = filepath.Join(tmpDir, "benchmark_cache.json")

	defer func() { agentstate.State.BenchmarkCachePath = "" }()

	err := saveBenchmarkCache(sampleBenchmarkResults)
	require.NoError(t, err)

	loaded, loadErr := loadBenchmarkCache()
	require.NoError(t, loadErr)
	require.NotNil(t, loaded)
	assert.Equal(t, sampleBenchmarkResults, loaded)
}

func TestCacheAndSubmitBenchmarks(t *testing.T) {
	tests := []struct {
		name                   string
		setupCachePath         func(t *testing.T) string
		setupMock              func()
		expectError            bool
		expectBenchmarksSubmit bool
	}{
		{
			name: "cache saved and submission succeeds",
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
			name: "cache saved but submission fails returns nil for retry",
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
			name: "cache write failure and submission failure returns error",
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
			name: "cache write failure but submission succeeds",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			defer cleanupState()

			agentstate.State.BenchmarkCachePath = tt.setupCachePath(t)
			agentstate.State.BenchmarksSubmitted = false

			tt.setupMock()

			err := cacheAndSubmitBenchmarks(sampleBenchmarkResults)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "benchmark submission failed with no cache for retry")
				assert.False(t, agentstate.State.BenchmarksSubmitted,
					"BenchmarksSubmitted must remain false when error is returned")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectBenchmarksSubmit, agentstate.State.BenchmarksSubmitted)
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
				viper.Set("force_benchmark_run", true)
				defer viper.Set("force_benchmark_run", false)
			}

			if tt.setupCache {
				err := saveBenchmarkCache(sampleBenchmarkResults)
				require.NoError(t, err)
			}

			tt.setupMock()

			result := TrySubmitCachedBenchmarks()
			assert.Equal(t, tt.expectSuccess, result)

			if tt.expectSubmit {
				assert.True(t, agentstate.State.BenchmarksSubmitted)
				// Cache should be cleared after successful submission
				_, err := os.Stat(agentstate.State.BenchmarkCachePath)
				assert.True(t, os.IsNotExist(err), "cache should be cleared after successful submission")
			}

			if !tt.expectSuccess && tt.setupCache && !tt.forceBenchmark {
				// Cache should be preserved on failure
				_, err := os.Stat(agentstate.State.BenchmarkCachePath)
				assert.NoError(t, err, "cache should be preserved on submission failure")
			}
		})
	}
}
