package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise the real gopsutil-backed Source against the host running
// the test. They assert only invariants that hold across supported platforms so
// they remain reliable in CI.

func TestGopsutilSource_CPUPercent(t *testing.T) {
	src := NewGopsutilSource()
	ctx := context.Background()

	overall, err := src.CPUPercent(ctx, false)
	require.NoError(t, err)
	require.Len(t, overall, 1, "overall CPU should be a single value")
	assert.GreaterOrEqual(t, overall[0], 0.0)

	perCore, err := src.CPUPercent(ctx, true)
	require.NoError(t, err)
	assert.NotEmpty(t, perCore, "per-core CPU should have at least one core")
}

func TestGopsutilSource_VirtualMemory(t *testing.T) {
	src := NewGopsutilSource()

	stats, err := src.VirtualMemory(context.Background())
	require.NoError(t, err)
	assert.Positive(t, stats.TotalBytes, "total physical memory should be positive")
	assert.LessOrEqual(t, stats.UsedPercent, 100.0)
	assert.GreaterOrEqual(t, stats.UsedPercent, 0.0)
}

func TestGopsutilSource_SwapMemory(t *testing.T) {
	src := NewGopsutilSource()

	// Swap may be zero-sized, but the call must not error on supported platforms.
	stats, err := src.SwapMemory(context.Background())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, stats.UsedPercent, 0.0)
}

func TestGopsutilSource_LoadAverage(t *testing.T) {
	src := NewGopsutilSource()

	stats, err := src.LoadAverage(context.Background())
	if err != nil {
		// Some platforms (e.g. Windows) do not support load averages; the source
		// must normalize that to ErrLoadUnavailable.
		require.ErrorIs(t, err, ErrLoadUnavailable)
		return
	}
	assert.GreaterOrEqual(t, stats.Load1, 0.0)
}

func TestGopsutilSource_ProcessStats_Self(t *testing.T) {
	src := NewGopsutilSource()
	pid := selfPID()

	stats, err := src.ProcessStats(context.Background(), pid)
	require.NoError(t, err)
	assert.Equal(t, pid, stats.PID)
	assert.Positive(t, stats.MemoryRSSBytes, "this test process should have a resident set size")
}

func TestGopsutilSource_ProcessStats_UnknownPID(t *testing.T) {
	src := NewGopsutilSource()

	// PID 0 is not a resolvable user process on the supported platforms.
	_, err := src.ProcessStats(context.Background(), 0)
	require.Error(t, err)
}

func TestGopsutilSource_ProcessHandleCaching(t *testing.T) {
	src := NewGopsutilSource().(*gopsutilSource) //nolint:errcheck // constructor returns concrete type
	pid := selfPID()
	ctx := context.Background()

	first, err := src.processHandle(ctx, pid)
	require.NoError(t, err)
	second, err := src.processHandle(ctx, pid)
	require.NoError(t, err)
	assert.Same(t, first, second, "handle for a live PID should be cached and reused")
}

func TestErrLoadUnavailable_IsWrapped(t *testing.T) {
	wrapped := errors.Join(ErrLoadUnavailable, errors.New("underlying"))
	assert.ErrorIs(t, wrapped, ErrLoadUnavailable)
}
