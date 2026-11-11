// Package monitor provides lightweight host and process performance monitoring
// for the CipherSwarm agent. It samples CPU, memory, swap, system load, and
// optional per-process metrics on a configurable interval using gopsutil and
// reports them through the agent's structured logger.
//
// Server-side ingestion of these metrics is intentionally out of scope: the v1
// Agent API contract (docs/swagger.json) exposes no performance endpoint, so
// metrics are surfaced locally via structured logging. GPU temperature and
// utilization already flow to the server through per-device task status updates
// (see the DeviceStatus schema), so they are not duplicated here.
package monitor

import "time"

// Metrics is a single point-in-time sample of host and (optionally) process
// performance counters.
type Metrics struct {
	// Timestamp is when the sample was taken.
	Timestamp time.Time
	// CPUPercent is overall CPU utilization across all logical cores (0-100).
	CPUPercent float64
	// PerCPUPercent holds per-logical-core utilization (0-100). Empty when
	// per-core collection is disabled.
	PerCPUPercent []float64
	// Memory holds physical RAM statistics.
	Memory MemoryStats
	// Swap holds swap/page-file statistics.
	Swap SwapStats
	// Load holds system load averages. Only meaningful when LoadAvailable is true.
	Load LoadStats
	// LoadAvailable reports whether the platform provided load averages
	// (unsupported on some platforms, e.g. Windows).
	LoadAvailable bool
	// DiskIO holds cumulative disk I/O counters aggregated across all disks.
	// Only meaningful when DiskIOAvailable is true.
	DiskIO DiskIOStats
	// DiskIOAvailable reports whether disk I/O counters were collected.
	DiskIOAvailable bool
	// NetIO holds cumulative network I/O counters aggregated across all interfaces.
	// Only meaningful when NetIOAvailable is true.
	NetIO NetIOStats
	// NetIOAvailable reports whether network I/O counters were collected.
	NetIOAvailable bool
	// Process holds per-process metrics for the monitored PID, or nil when
	// process collection is disabled or the process could not be sampled.
	Process *ProcessStats
}

// DiskIOStats holds cumulative disk I/O counters (since boot) summed across all
// physical disks. These are monotonic totals; consumers delta successive samples
// to derive throughput.
type DiskIOStats struct {
	// ReadBytes is the total bytes read across all disks.
	ReadBytes uint64
	// WriteBytes is the total bytes written across all disks.
	WriteBytes uint64
}

// NetIOStats holds cumulative network I/O counters (since boot) summed across all
// interfaces. These are monotonic totals; consumers delta successive samples to
// derive throughput.
type NetIOStats struct {
	// BytesSent is the total bytes transmitted across all interfaces.
	BytesSent uint64
	// BytesRecv is the total bytes received across all interfaces.
	BytesRecv uint64
}

// MemoryStats describes physical memory usage at sample time.
type MemoryStats struct {
	// UsedPercent is the fraction of physical memory in use (0-100).
	UsedPercent float64
	// UsedBytes is the number of bytes of physical memory in use.
	UsedBytes uint64
	// TotalBytes is the total physical memory.
	TotalBytes uint64
	// AvailableBytes is the memory available for new allocations without swapping.
	AvailableBytes uint64
}

// SwapStats describes swap/page-file usage at sample time.
type SwapStats struct {
	// UsedPercent is the fraction of swap in use (0-100).
	UsedPercent float64
	// UsedBytes is the number of bytes of swap in use.
	UsedBytes uint64
	// TotalBytes is the total swap size.
	TotalBytes uint64
}

// LoadStats holds the 1-, 5-, and 15-minute system load averages.
type LoadStats struct {
	// Load1 is the 1-minute load average.
	Load1 float64
	// Load5 is the 5-minute load average.
	Load5 float64
	// Load15 is the 15-minute load average.
	Load15 float64
}

// ProcessStats holds per-process performance counters.
type ProcessStats struct {
	// PID is the process identifier that was sampled.
	PID int32
	// CPUPercent is the process CPU utilization since the previous sample (0-100
	// per logical core, so a fully-busy process may exceed 100 on multi-core hosts).
	CPUPercent float64
	// MemoryRSSBytes is the process resident set size in bytes.
	MemoryRSSBytes uint64
}
