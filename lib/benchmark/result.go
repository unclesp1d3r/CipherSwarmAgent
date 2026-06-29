package benchmark

import "github.com/unclesp1d3r/cipherswarmagent/agentstate"

// Result represents the outcome of a benchmark session.
type Result struct {
	Device      string `json:"device,omitempty"`      // Device is the numeric device ID used for the benchmark.
	DeviceName  string `json:"device_name,omitempty"` // DeviceName is the human-readable device name (display-only, not sent to API).
	HashType    string `json:"hash_type,omitempty"`   // HashType is the type of hash used for the benchmark.
	RuntimeMs   string `json:"runtime,omitempty"`     // RuntimeMs is the runtime of the benchmark in milliseconds.
	HashTimeMs  string `json:"hash_time,omitempty"`   // HashTimeMs is the time taken to hash in milliseconds.
	SpeedHs     string `json:"hash_speed,omitempty"`  // SpeedHs is the hash speed in hashes per second.
	Submitted   bool   `json:"submitted,omitempty"`   // Submitted indicates whether this result has been accepted by the server.
	Placeholder bool   `json:"placeholder,omitempty"` // Placeholder indicates this is a capability-detection result, not a real benchmark.
}

// logBenchmarkResult logs the provided benchmark result using the shared Logger.
// The log includes the device, hash type, runtime in milliseconds, and speed in hashes per second.
func logBenchmarkResult(result Result) {
	keyvals := []any{
		"device", result.Device,
		"hash_type", result.HashType,
		"runtime_ms", result.RuntimeMs,
		"speed_hs", result.SpeedHs,
	}

	if result.DeviceName != "" {
		keyvals = append(keyvals, "device_name", result.DeviceName)
	}

	agentstate.Logger.Debug("Benchmark result", keyvals...)
}

// logBenchmarksComplete logs the completion of a benchmark session along with the benchmark results.
func logBenchmarksComplete(benchmarkResults []Result) {
	agentstate.Logger.Debug("Benchmark session completed", "results", benchmarkResults)
}
