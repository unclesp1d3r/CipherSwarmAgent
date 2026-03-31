package benchmark

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
)

func TestLoadPlaceholderResults(t *testing.T) {
	tests := []struct {
		name      string
		cache     []display.BenchmarkResult
		wantCount int
		wantOrder []string
		expectNil bool
	}{
		{
			name:      "no cache returns nil",
			cache:     nil,
			expectNil: true,
		},
		{
			name: "no placeholders returns nil",
			cache: []display.BenchmarkResult{
				{HashType: "0", SpeedHs: "1000", Placeholder: false},
			},
			expectNil: true,
		},
		{
			name: "returns only placeholders",
			cache: []display.BenchmarkResult{
				{HashType: "0", SpeedHs: "1000", Placeholder: false},
				{HashType: "200", SpeedHs: "1", Placeholder: true},
				{HashType: "300", SpeedHs: "1", Placeholder: true},
			},
			wantCount: 2,
			wantOrder: []string{"200", "300"},
		},
		{
			name: "priority types sort first",
			cache: []display.BenchmarkResult{
				{HashType: "500", SpeedHs: "1", Placeholder: true},
				{HashType: "100", SpeedHs: "1", Placeholder: true},
				{HashType: "0", SpeedHs: "1", Placeholder: true},
				{HashType: "1000", SpeedHs: "1", Placeholder: true},
				{HashType: "200", SpeedHs: "1", Placeholder: true},
			},
			wantCount: 5,
			// Priority: 0, 100, 1000, then numeric ascending: 200, 500
			wantOrder: []string{"0", "100", "1000", "200", "500"},
		},
		{
			name:      "empty cache returns nil",
			cache:     []display.BenchmarkResult{},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			agentstate.State.BenchmarkCachePath = filepath.Join(tmpDir, "benchmark_cache.json")
			t.Cleanup(func() { agentstate.State.BenchmarkCachePath = "" })

			if tt.cache != nil {
				err := saveBenchmarkCache(tt.cache)
				require.NoError(t, err)
			}

			results, err := loadPlaceholderResults()
			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, results)
				return
			}

			require.Len(t, results, tt.wantCount)
			for i, expected := range tt.wantOrder {
				assert.Equal(t, expected, results[i].HashType, "index %d", i)
			}
		})
	}
}

func TestLoadPlaceholderResults_SortConsistency(t *testing.T) {
	tmpDir := t.TempDir()
	agentstate.State.BenchmarkCachePath = filepath.Join(tmpDir, "benchmark_cache.json")
	t.Cleanup(func() { agentstate.State.BenchmarkCachePath = "" })

	// Mix of parseable and unparseable hash types
	cache := []display.BenchmarkResult{
		{HashType: "abc", SpeedHs: "1", Placeholder: true},
		{HashType: "500", SpeedHs: "1", Placeholder: true},
		{HashType: "xyz", SpeedHs: "1", Placeholder: true},
		{HashType: "200", SpeedHs: "1", Placeholder: true},
	}
	err := saveBenchmarkCache(cache)
	require.NoError(t, err)

	results, err := loadPlaceholderResults()
	require.NoError(t, err)
	require.Len(t, results, 4)

	// Parseable should come first (200, 500), then unparseable alphabetically (abc, xyz)
	assert.Equal(t, "200", results[0].HashType)
	assert.Equal(t, "500", results[1].HashType)
	assert.Equal(t, "abc", results[2].HashType)
	assert.Equal(t, "xyz", results[3].HashType)
}

func TestLoadPlaceholderResults_AllPlaceholdersArePriority(t *testing.T) {
	tmpDir := t.TempDir()
	agentstate.State.BenchmarkCachePath = filepath.Join(tmpDir, "benchmark_cache.json")
	t.Cleanup(func() { agentstate.State.BenchmarkCachePath = "" })

	cache := []display.BenchmarkResult{
		{HashType: "1000", SpeedHs: "1", Placeholder: true},
		{HashType: "0", SpeedHs: "1", Placeholder: true},
		{HashType: "100", SpeedHs: "1", Placeholder: true},
	}
	err := saveBenchmarkCache(cache)
	require.NoError(t, err)

	results, err := loadPlaceholderResults()
	require.NoError(t, err)
	require.Len(t, results, 3)

	assert.Equal(t, "0", results[0].HashType)
	assert.Equal(t, "100", results[1].HashType)
	assert.Equal(t, "1000", results[2].HashType)
}

func TestLoadPlaceholderResults_NoCachePath(t *testing.T) {
	agentstate.State.BenchmarkCachePath = ""

	results, err := loadPlaceholderResults()
	require.NoError(t, err)
	assert.Nil(t, results)
}
