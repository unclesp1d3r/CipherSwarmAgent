package monitor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSource is a configurable Source for deterministic tests.
type fakeSource struct {
	overall    []float64
	perCore    []float64
	memStats   MemoryStats
	swapStats  SwapStats
	loadStats  LoadStats
	diskStats  DiskIOStats
	netStats   NetIOStats
	procStats  ProcessStats
	cpuErr     error
	perCoreErr error
	memErr     error
	swapErr    error
	loadErr    error
	diskErr    error
	netErr     error
	procErr    error

	cpuCalls     atomic.Int32
	perCoreCalls atomic.Int32
	procCalls    atomic.Int32
}

func (f *fakeSource) CPUPercent(_ context.Context, perCore bool) ([]float64, error) {
	if perCore {
		f.perCoreCalls.Add(1)
		return f.perCore, f.perCoreErr
	}
	f.cpuCalls.Add(1)

	return f.overall, f.cpuErr
}

func (f *fakeSource) VirtualMemory(context.Context) (MemoryStats, error) {
	return f.memStats, f.memErr
}

func (f *fakeSource) SwapMemory(context.Context) (SwapStats, error) {
	return f.swapStats, f.swapErr
}

func (f *fakeSource) LoadAverage(context.Context) (LoadStats, error) {
	return f.loadStats, f.loadErr
}

func (f *fakeSource) DiskIO(context.Context) (DiskIOStats, error) {
	return f.diskStats, f.diskErr
}

func (f *fakeSource) NetIO(context.Context) (NetIOStats, error) {
	return f.netStats, f.netErr
}

func (f *fakeSource) ProcessStats(_ context.Context, _ int32) (ProcessStats, error) {
	f.procCalls.Add(1)
	return f.procStats, f.procErr
}

func healthySource() *fakeSource {
	return &fakeSource{
		overall:   []float64{42.5},
		perCore:   []float64{40, 45},
		memStats:  MemoryStats{UsedPercent: 68.5, UsedBytes: 8 << 30, TotalBytes: 16 << 30, AvailableBytes: 4 << 30},
		swapStats: SwapStats{UsedPercent: 10, UsedBytes: 1 << 30, TotalBytes: 8 << 30},
		loadStats: LoadStats{Load1: 2.1, Load5: 1.8, Load15: 1.6},
		diskStats: DiskIOStats{ReadBytes: 100 << 20, WriteBytes: 50 << 20},
		netStats:  NetIOStats{BytesSent: 10 << 20, BytesRecv: 20 << 20},
		procStats: ProcessStats{PID: 12345, CPUPercent: 85.3, MemoryRSSBytes: 512 << 20},
	}
}

func fixedNow() time.Time {
	return time.Date(2024, time.January, 1, 12, 0, 0, 0, time.UTC)
}

func TestNew_AppliesDefaults(t *testing.T) {
	mon := New(healthySource(), Options{})

	assert.Equal(t, DefaultInterval, mon.opts.Interval, "non-positive interval should fall back to default")
	require.NotNil(t, mon.opts.PIDProvider, "default PID provider should be set")
	pid, ok := mon.opts.PIDProvider()
	assert.True(t, ok)
	assert.Positive(t, pid, "default PID provider should return this process's PID")
	require.NotNil(t, mon.opts.Log, "default log should be a no-op, not nil")
	require.NotNil(t, mon.opts.now)
}

func TestCollect_Healthy(t *testing.T) {
	src := healthySource()
	mon := New(src, Options{
		Interval:       time.Second,
		CollectPerCPU:  true,
		CollectProcess: true,
		PIDProvider:    func() (int32, bool) { return 12345, true },
		now:            fixedNow,
	})

	metrics, err := mon.Collect(context.Background())
	require.NoError(t, err)

	assert.Equal(t, fixedNow(), metrics.Timestamp)
	assert.InDelta(t, 42.5, metrics.CPUPercent, 0.001)
	assert.Equal(t, []float64{40, 45}, metrics.PerCPUPercent)
	assert.InDelta(t, 68.5, metrics.Memory.UsedPercent, 0.001)
	assert.Equal(t, uint64(4<<30), metrics.Memory.AvailableBytes)
	assert.InDelta(t, 10.0, metrics.Swap.UsedPercent, 0.001)
	assert.True(t, metrics.LoadAvailable)
	assert.InDelta(t, 2.1, metrics.Load.Load1, 0.001)
	assert.True(t, metrics.DiskIOAvailable)
	assert.Equal(t, uint64(100<<20), metrics.DiskIO.ReadBytes)
	assert.Equal(t, uint64(50<<20), metrics.DiskIO.WriteBytes)
	assert.True(t, metrics.NetIOAvailable)
	assert.Equal(t, uint64(10<<20), metrics.NetIO.BytesSent)
	assert.Equal(t, uint64(20<<20), metrics.NetIO.BytesRecv)
	require.NotNil(t, metrics.Process)
	assert.Equal(t, int32(12345), metrics.Process.PID)
	assert.InDelta(t, 85.3, metrics.Process.CPUPercent, 0.001)
}

func TestCollect_LoadUnavailableIsSoft(t *testing.T) {
	src := healthySource()
	src.loadErr = errors.Join(ErrLoadUnavailable, errors.New("not implemented"))
	mon := New(src, Options{now: fixedNow})

	metrics, err := mon.Collect(context.Background())
	require.NoError(t, err, "unavailable load average must not fail the sample")
	assert.False(t, metrics.LoadAvailable)
	assert.Zero(t, metrics.Load.Load1)
}

func TestCollect_CoreErrorReturnsPartialMetrics(t *testing.T) {
	src := healthySource()
	src.cpuErr = errors.New("cpu boom")
	mon := New(src, Options{now: fixedNow})

	metrics, err := mon.Collect(context.Background())
	require.Error(t, err, "a core-counter failure should surface as an error")
	// Memory was still read successfully and must be present alongside the error.
	assert.InDelta(t, 68.5, metrics.Memory.UsedPercent, 0.001)
	assert.Zero(t, metrics.CPUPercent, "failed CPU read leaves the field at zero")
}

func TestCollect_ProcessDisabledSkipsSampling(t *testing.T) {
	src := healthySource()
	mon := New(src, Options{CollectProcess: false, now: fixedNow})

	metrics, err := mon.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, metrics.Process)
	assert.Zero(t, src.procCalls.Load(), "process source must not be called when disabled")
}

func TestCollect_ProcessUnavailablePIDSkips(t *testing.T) {
	src := healthySource()
	mon := New(src, Options{
		CollectProcess: true,
		PIDProvider:    func() (int32, bool) { return 0, false },
		now:            fixedNow,
	})

	metrics, err := mon.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, metrics.Process)
	assert.Zero(t, src.procCalls.Load(), "no PID available means no process sampling")
}

func TestCollect_ProcessErrorIsSoft(t *testing.T) {
	src := healthySource()
	src.procErr = errors.New("no such process")
	mon := New(src, Options{
		CollectProcess: true,
		PIDProvider:    func() (int32, bool) { return 999, true },
		now:            fixedNow,
	})

	metrics, err := mon.Collect(context.Background())
	require.NoError(t, err, "a transient process error must not fail the whole sample")
	assert.Nil(t, metrics.Process)
}

func TestCollect_AllCoreErrorsJoined(t *testing.T) {
	src := healthySource()
	src.cpuErr = errors.New("cpu boom")
	src.perCoreErr = errors.New("percpu boom")
	src.memErr = errors.New("mem boom")
	src.swapErr = errors.New("swap boom")

	mon := New(src, Options{CollectPerCPU: true, now: fixedNow})

	metrics, err := mon.Collect(context.Background())
	require.Error(t, err)
	// errors.Join surfaces every core failure.
	require.ErrorContains(t, err, "cpu boom")
	require.ErrorContains(t, err, "percpu boom")
	require.ErrorContains(t, err, "mem boom")
	require.ErrorContains(t, err, "swap boom")
	assert.Nil(t, metrics.PerCPUPercent)
}

func TestCollect_DiskAndNetErrorsAreSoft(t *testing.T) {
	src := healthySource()
	src.diskErr = errors.New("disk counters unavailable")
	src.netErr = errors.New("net counters unavailable")

	var logged []string
	mon := New(src, Options{
		now: fixedNow,
		Log: func(msg any, _ ...any) {
			if s, ok := msg.(string); ok {
				logged = append(logged, s)
			}
		},
	})

	metrics, err := mon.Collect(context.Background())
	require.NoError(t, err, "disk/net counter failures must not fail the whole sample")
	assert.False(t, metrics.DiskIOAvailable)
	assert.False(t, metrics.NetIOAvailable)
	assert.Contains(t, logged, "Disk I/O counters unavailable; suppressing repeat warnings until recovery")
	assert.Contains(t, logged, "Network I/O counters unavailable; suppressing repeat warnings until recovery")
}

func TestCollect_DiskNetSoftFailuresLogOncePerStreak(t *testing.T) {
	src := healthySource()
	src.diskErr = errors.New("disk counters unavailable")

	countDiskLogs := func(logs []string) int {
		n := 0
		for _, s := range logs {
			if s == "Disk I/O counters unavailable; suppressing repeat warnings until recovery" {
				n++
			}
		}

		return n
	}

	var logged []string
	mon := New(src, Options{
		now: fixedNow,
		Log: func(msg any, _ ...any) {
			if s, ok := msg.(string); ok {
				logged = append(logged, s)
			}
		},
	})

	// Three consecutive failing samples should log exactly once (transition in).
	for range 3 {
		_, err := mon.Collect(context.Background())
		require.NoError(t, err)
	}
	assert.Equal(t, 1, countDiskLogs(logged), "repeat failures must be suppressed")

	// Recovery re-arms the warning; the next failure logs again.
	src.diskErr = nil
	_, err := mon.Collect(context.Background())
	require.NoError(t, err)

	src.diskErr = errors.New("disk counters unavailable again")
	_, err = mon.Collect(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, countDiskLogs(logged), "a failure after recovery should log again")
}

func TestReport_IncludesAvailableSections(t *testing.T) {
	src := healthySource()
	mon := New(src, Options{
		now:            fixedNow,
		CollectProcess: true,
		PIDProvider:    func() (int32, bool) { return 12345, true },
	})

	metrics, err := mon.Collect(context.Background())
	require.NoError(t, err)

	var captured []any
	mon.opts.Log = func(msg any, keyvals ...any) {
		if msg == "System performance" {
			captured = keyvals
		}
	}
	mon.report(metrics)

	require.NotNil(t, captured)
	assert.Contains(t, captured, "disk_read")
	assert.Contains(t, captured, "net_sent")
	assert.Contains(t, captured, "load_1m")
	assert.Contains(t, captured, "proc_pid")
}

func TestReport_OmitsUnavailableSections(t *testing.T) {
	// A metrics value with everything unavailable and no process should report
	// only the always-present host fields.
	mon := New(healthySource(), Options{now: fixedNow})

	var captured []any
	mon.opts.Log = func(msg any, keyvals ...any) {
		if msg == "System performance" {
			captured = keyvals
		}
	}
	mon.report(Metrics{Timestamp: fixedNow()})

	require.NotNil(t, captured)
	assert.Contains(t, captured, "cpu_percent")
	assert.NotContains(t, captured, "load_1m")
	assert.NotContains(t, captured, "disk_read")
	assert.NotContains(t, captured, "net_sent")
	assert.NotContains(t, captured, "proc_pid")
}

func TestCollect_PerCPUDisabledSkips(t *testing.T) {
	src := healthySource()
	mon := New(src, Options{CollectPerCPU: false, now: fixedNow})

	metrics, err := mon.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, metrics.PerCPUPercent)
	assert.Zero(t, src.perCoreCalls.Load(), "per-core source must not be called when disabled")
}

func TestRun_ReportsUntilCancelled(t *testing.T) {
	src := healthySource()

	logged := make(chan []any, 8)
	var logMu sync.Mutex
	logFn := func(msg any, keyvals ...any) {
		if msg == "System performance" {
			logMu.Lock()
			defer logMu.Unlock()
			select {
			case logged <- keyvals:
			default:
			}
		}
	}

	mon := New(src, Options{
		Interval:       5 * time.Millisecond,
		CollectProcess: true,
		PIDProvider:    func() (int32, bool) { return 12345, true },
		Log:            logFn,
		now:            fixedNow,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mon.Run(ctx)
		close(done)
	}()

	// Expect at least one reported sample.
	select {
	case kv := <-logged:
		assert.Contains(t, kv, "cpu_percent")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a performance sample")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	// Run primes CPU/process counters before the loop, so both were sampled.
	assert.Positive(t, src.cpuCalls.Load())
	assert.Positive(t, src.procCalls.Load())
}

func TestRun_ReportsPartialFailure(t *testing.T) {
	src := healthySource()
	src.cpuErr = errors.New("cpu boom") // forces Collect to return an error each tick

	sawPartial := make(chan struct{}, 1)
	logFn := func(msg any, _ ...any) {
		if msg == "Performance sampling partially failed" {
			select {
			case sawPartial <- struct{}{}:
			default:
			}
		}
	}

	mon := New(src, Options{Interval: 5 * time.Millisecond, Log: logFn, now: fixedNow})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		mon.Run(ctx)
		close(done)
	}()

	select {
	case <-sawPartial:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a partial-failure log from Run")
	}
	cancel()
	<-done
}

func TestRun_PrimesPerCPUWhenEnabled(t *testing.T) {
	src := healthySource()
	mon := New(src, Options{
		Interval:      time.Hour, // long enough that the ticker never fires during the test
		CollectPerCPU: true,
		Log:           func(any, ...any) {},
		now:           fixedNow,
	})

	// A pre-cancelled context still runs the priming block before the loop exits.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mon.Run(ctx)

	assert.Positive(t, src.perCoreCalls.Load(),
		"Run must prime per-CPU counters when CollectPerCPU is enabled")
}

func TestRound2(t *testing.T) {
	tests := []struct {
		in   float64
		want float64
	}{
		{42.555, 42.56},
		{42.554, 42.55},
		{0, 0},
		{100, 100},
		{2.1, 2.1},
	}
	for _, tt := range tests {
		assert.InDelta(t, tt.want, round2(tt.in), 0.0001)
	}
}
