package monitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
)

// selfPID returns the current process's PID as an int32 (the width gopsutil's
// process API expects). PIDs are always well within int32 range on supported
// platforms, so the conversion cannot overflow.
func selfPID() int32 {
	return int32(os.Getpid()) //nolint:gosec // G115 - a process ID always fits in int32
}

// ErrLoadUnavailable indicates the platform does not provide system load
// averages. It is treated as a soft failure by the monitor rather than an error.
var ErrLoadUnavailable = errors.New("system load average unavailable on this platform")

// Source abstracts host and process metric collection so the monitor can be
// unit-tested without touching real system counters. All methods take a context
// so collection honors cancellation and deadlines.
type Source interface {
	// CPUPercent returns CPU utilization (0-100). When perCore is true, it
	// returns one value per logical core; otherwise a single overall value.
	// Utilization is measured relative to the previous call (non-blocking).
	CPUPercent(ctx context.Context, perCore bool) ([]float64, error)
	// VirtualMemory returns physical memory statistics.
	VirtualMemory(ctx context.Context) (MemoryStats, error)
	// SwapMemory returns swap/page-file statistics.
	SwapMemory(ctx context.Context) (SwapStats, error)
	// LoadAverage returns system load averages, or ErrLoadUnavailable when the
	// platform does not support them.
	LoadAverage(ctx context.Context) (LoadStats, error)
	// ProcessStats returns per-process counters for pid. CPU utilization is
	// measured relative to the previous call for the same pid (non-blocking).
	ProcessStats(ctx context.Context, pid int32) (ProcessStats, error)
}

// gopsutilSource is the production Source backed by gopsutil. CPU and per-process
// utilization are delta-based: each measurement compares counters against the
// previous call, so the first sample after startup reflects usage since boot (or
// since the process was first observed). Sampling is non-blocking (interval 0).
type gopsutilSource struct {
	mu    sync.Mutex
	procs map[int32]*process.Process // cached per-PID handles for delta CPU measurement
}

// NewGopsutilSource returns a Source backed by the gopsutil library.
func NewGopsutilSource() Source {
	return &gopsutilSource{procs: make(map[int32]*process.Process)}
}

func (s *gopsutilSource) CPUPercent(ctx context.Context, perCore bool) ([]float64, error) {
	// interval 0 => compare against the previous call's counters (non-blocking).
	percentages, err := cpu.PercentWithContext(ctx, 0, perCore)
	if err != nil {
		return nil, fmt.Errorf("collecting cpu utilization: %w", err)
	}

	return percentages, nil
}

func (s *gopsutilSource) VirtualMemory(ctx context.Context) (MemoryStats, error) {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return MemoryStats{}, fmt.Errorf("collecting virtual memory: %w", err)
	}

	return MemoryStats{
		UsedPercent:    vm.UsedPercent,
		UsedBytes:      vm.Used,
		TotalBytes:     vm.Total,
		AvailableBytes: vm.Available,
	}, nil
}

func (s *gopsutilSource) SwapMemory(ctx context.Context) (SwapStats, error) {
	sw, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		return SwapStats{}, fmt.Errorf("collecting swap memory: %w", err)
	}

	return SwapStats{
		UsedPercent: sw.UsedPercent,
		UsedBytes:   sw.Used,
		TotalBytes:  sw.Total,
	}, nil
}

func (s *gopsutilSource) LoadAverage(ctx context.Context) (LoadStats, error) {
	avg, err := load.AvgWithContext(ctx)
	if err != nil {
		// gopsutil returns an error on platforms without load-average support
		// (e.g. Windows). Normalize to a sentinel the monitor can treat as soft.
		return LoadStats{}, fmt.Errorf("%w: %w", ErrLoadUnavailable, err)
	}

	return LoadStats{Load1: avg.Load1, Load5: avg.Load5, Load15: avg.Load15}, nil
}

func (s *gopsutilSource) ProcessStats(ctx context.Context, pid int32) (ProcessStats, error) {
	proc, err := s.processHandle(ctx, pid)
	if err != nil {
		return ProcessStats{}, err
	}

	// interval 0 => compare against the previous call for this handle (non-blocking).
	cpuPct, err := proc.PercentWithContext(ctx, 0)
	if err != nil {
		return ProcessStats{}, fmt.Errorf("collecting process cpu for pid %d: %w", pid, err)
	}

	memInfo, err := proc.MemoryInfoWithContext(ctx)
	if err != nil {
		return ProcessStats{}, fmt.Errorf("collecting process memory for pid %d: %w", pid, err)
	}

	return ProcessStats{PID: pid, CPUPercent: cpuPct, MemoryRSSBytes: memInfo.RSS}, nil
}

// processHandle returns a cached *process.Process for pid, creating and caching
// one on first use. Caching preserves the previous CPU counters so delta-based
// utilization works across calls. A stale handle (process exited) is evicted so
// a later process reusing the PID is re-resolved.
func (s *gopsutilSource) processHandle(ctx context.Context, pid int32) (*process.Process, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if proc, ok := s.procs[pid]; ok {
		running, err := proc.IsRunningWithContext(ctx)
		if err == nil && running {
			return proc, nil
		}
		delete(s.procs, pid)
	}

	proc, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return nil, fmt.Errorf("resolving process pid %d: %w", pid, err)
	}
	s.procs[pid] = proc

	return proc, nil
}
