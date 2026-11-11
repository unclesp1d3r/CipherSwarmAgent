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

func TestGopsutilSource_DiskIO(t *testing.T) {
	src := NewGopsutilSource()

	// Disk I/O counters may be empty in restricted environments, but the call
	// must not error on supported platforms.
	_, err := src.DiskIO(context.Background())
	require.NoError(t, err)
}

func TestGopsutilSource_NetIO(t *testing.T) {
	src := NewGopsutilSource()

	_, err := src.NetIO(context.Background())
	require.NoError(t, err)
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

func TestIsPartitionOfAny(t *testing.T) {
	names := []string{"sda", "sda1", "sda2", "nvme0n1", "nvme0n1p1", "mmcblk0", "mmcblk0p1", "disk0", "loop0"}
	tests := []struct {
		device string
		want   bool
	}{
		{"sda", false},      // whole disk
		{"sda1", true},      // SATA partition
		{"sda2", true},      // SATA partition
		{"nvme0n1", false},  // whole NVMe namespace
		{"nvme0n1p1", true}, // NVMe partition (p-separated)
		{"mmcblk0", false},  // whole eMMC device
		{"mmcblk0p1", true}, // eMMC partition (p-separated)
		{"disk0", false},    // macOS whole disk, no partition parent present
		{"loop0", false},    // loop device, no parent
		{"sdb", false},      // not present as a partition of anything
	}
	for _, tt := range tests {
		t.Run(tt.device, func(t *testing.T) {
			assert.Equal(t, tt.want, isPartitionOfAny(tt.device, names))
		})
	}
}

func TestIsAllDigits(t *testing.T) {
	assert.True(t, isAllDigits("0"))
	assert.True(t, isAllDigits("123"))
	assert.False(t, isAllDigits(""))
	assert.False(t, isAllDigits("1a"))
	assert.False(t, isAllDigits("p1"))
}
