package monitor

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/dustin/go-humanize"
)

// DefaultInterval is the fallback sampling interval when a non-positive interval
// is supplied to New.
const DefaultInterval = 30 * time.Second

// LogFunc matches the signature of charmbracelet/log methods
// (func(msg any, keyvals ...any)) so the monitor can report through the agent's
// structured logger without importing it directly.
type LogFunc func(msg any, keyvals ...any)

// PIDProvider returns the process ID to sample and whether one is currently
// available. Returning ok=false skips process collection for that sample (for
// example, when no hashcat process is running).
type PIDProvider func() (pid int32, ok bool)

// Options configures a Monitor. The zero value is not usable; use New, which
// fills in safe defaults for any unset field.
type Options struct {
	// Interval is the sampling period. Non-positive values fall back to DefaultInterval.
	Interval time.Duration
	// CollectPerCPU enables per-logical-core CPU sampling in addition to the overall figure.
	CollectPerCPU bool
	// CollectProcess enables per-process sampling via PIDProvider.
	CollectProcess bool
	// PIDProvider selects which process to sample. When nil, the agent's own
	// process is sampled (useful for verifying monitoring overhead).
	PIDProvider PIDProvider
	// Log reports each sample and any soft failures. When nil, reporting is a no-op.
	Log LogFunc
	// now returns the current time; injected for deterministic tests. Defaults to time.Now.
	now func() time.Time
}

// Monitor samples host and process performance counters on a fixed interval and
// reports them through a structured logger. It is safe to run in a dedicated
// goroutine; a single Monitor must not be run concurrently with itself.
type Monitor struct {
	source Source
	opts   Options
}

// New returns a Monitor that draws samples from source using opts, applying
// defaults for any unset option. source must be non-nil.
func New(source Source, opts Options) *Monitor {
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.PIDProvider == nil {
		pid := selfPID()
		opts.PIDProvider = func() (int32, bool) { return pid, true }
	}
	if opts.Log == nil {
		opts.Log = func(any, ...any) {}
	}
	if opts.now == nil {
		opts.now = time.Now
	}

	return &Monitor{source: source, opts: opts}
}

// Collect gathers a single sample. Failures to read core counters (CPU, memory,
// swap) are joined into the returned error, but any counters that were read
// successfully are still populated in the returned Metrics — callers get partial
// data alongside the error. A missing system load average is not an error: it
// sets LoadAvailable=false. Process errors are likewise soft (Process stays nil)
// so a transient process is never fatal to a sample.
func (m *Monitor) Collect(ctx context.Context) (Metrics, error) {
	metrics := Metrics{Timestamp: m.opts.now()}

	var errs []error

	if overall, err := m.source.CPUPercent(ctx, false); err != nil {
		errs = append(errs, err)
	} else if len(overall) > 0 {
		metrics.CPUPercent = overall[0]
	}

	if m.opts.CollectPerCPU {
		if perCore, err := m.source.CPUPercent(ctx, true); err != nil {
			errs = append(errs, err)
		} else {
			metrics.PerCPUPercent = perCore
		}
	}

	if memStats, err := m.source.VirtualMemory(ctx); err != nil {
		errs = append(errs, err)
	} else {
		metrics.Memory = memStats
	}

	if swapStats, err := m.source.SwapMemory(ctx); err != nil {
		errs = append(errs, err)
	} else {
		metrics.Swap = swapStats
	}

	if loadStats, err := m.source.LoadAverage(ctx); err != nil {
		// Soft failure — unsupported platforms simply omit load averages.
		if !errors.Is(err, ErrLoadUnavailable) {
			m.opts.Log("Failed to read system load average", "error", err)
		}
	} else {
		metrics.Load = loadStats
		metrics.LoadAvailable = true
	}

	if m.opts.CollectProcess {
		if pid, ok := m.opts.PIDProvider(); ok {
			if procStats, err := m.source.ProcessStats(ctx, pid); err != nil {
				m.opts.Log("Failed to read process metrics", "pid", pid, "error", err)
			} else {
				metrics.Process = &procStats
			}
		}
	}

	if len(errs) > 0 {
		return metrics, errors.Join(errs...)
	}

	return metrics, nil
}

// Run samples on m's interval until ctx is cancelled, reporting each sample via
// the configured logger. The first sample is taken one interval in (the initial
// interval also primes delta-based CPU counters), and Run returns when ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	// Prime delta-based CPU counters so the first reported sample is meaningful
	// rather than measuring usage since boot. Errors here are non-fatal — the
	// priming call exists only to seed the previous-counter baseline.
	//nolint:errcheck // priming call: result and error intentionally discarded
	_, _ = m.source.CPUPercent(ctx, false)
	if m.opts.CollectProcess {
		if pid, ok := m.opts.PIDProvider(); ok {
			//nolint:errcheck // priming call: result and error intentionally discarded
			_, _ = m.source.ProcessStats(ctx, pid)
		}
	}

	ticker := time.NewTicker(m.opts.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics, err := m.Collect(ctx)
			if err != nil {
				// Partial samples are still worth reporting; note the failure.
				m.opts.Log("Performance sampling partially failed", "error", err)
			}
			m.report(metrics)
		}
	}
}

// report emits a single sample through the configured logger with
// human-readable byte counts alongside the raw percentages.
func (m *Monitor) report(metrics Metrics) {
	keyvals := []any{
		"cpu_percent", round2(metrics.CPUPercent),
		"memory_percent", round2(metrics.Memory.UsedPercent),
		"memory_available", humanize.IBytes(metrics.Memory.AvailableBytes),
		"memory_total", humanize.IBytes(metrics.Memory.TotalBytes),
		"swap_percent", round2(metrics.Swap.UsedPercent),
	}

	if metrics.LoadAvailable {
		keyvals = append(keyvals,
			"load_1m", round2(metrics.Load.Load1),
			"load_5m", round2(metrics.Load.Load5),
			"load_15m", round2(metrics.Load.Load15),
		)
	}

	if metrics.Process != nil {
		keyvals = append(keyvals,
			"proc_pid", metrics.Process.PID,
			"proc_cpu_percent", round2(metrics.Process.CPUPercent),
			"proc_memory", humanize.IBytes(metrics.Process.MemoryRSSBytes),
		)
	}

	m.opts.Log("System performance", keyvals...)
}

// twoDecimalScale scales a value so math.Round yields two-decimal precision.
const twoDecimalScale = 100

// round2 rounds a percentage/load value to two decimal places for tidy logging.
func round2(v float64) float64 {
	return math.Round(v*twoDecimalScale) / twoDecimalScale
}
