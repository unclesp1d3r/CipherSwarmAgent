// Package agentstate provides common state and configuration structures used across the CipherSwarm Agent.
package agentstate

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/log"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// State represents the configuration and runtime state of the agent.
var State = agentState{} //nolint:gochecknoglobals // Global agent state

// agentState represents the state and configuration settings of an agent in the CipherSwarm system.
// Fields accessed across goroutines (heartbeat + agent loops) are synchronized via atomic.Bool
// or sync.RWMutex. Use the getter/setter methods for those fields.
type agentState struct {
	PidFile                             string        // PidFile is the path to the file containing the agent's process ID.
	HashcatPidFile                      string        // HashcatPidFile is the path to the file containing the Hashcat process ID.
	DataPath                            string        // DataPath is the path to the directory containing the agent's data files.
	CrackersPath                        string        // CrackersPath is the path to the directory containing the agent's cracker binaries.
	HashlistPath                        string        // HashlistPath is the path to the directory containing the agent's hashlists.
	ZapsPath                            string        // ZapsPath is the path to the directory containing the agent's zaps.
	PreprocessorsPath                   string        // PreprocessorsPath is the path to the directory containing the agent's preprocessors.
	ToolsPath                           string        // ToolsPath is the path to the directory containing the agent's tools.
	OutPath                             string        // OutPath is the path to the directory containing the agent's output files.
	FilePath                            string        // FilePath is the path to the file containing various files for attacks.
	RestoreFilePath                     string        // RestoreFilePath is the path to the file containing hashcat's restore data.
	BenchmarkCachePath                  string        // BenchmarkCachePath is the path to the JSON file caching benchmark results.
	Debug                               bool          // Debug specifies whether the agent is running in debug mode.
	AgentID                             int64         // AgentID is the unique identifier of the agent.
	URL                                 string        // URL is the URL of the CipherSwarm API.
	APIToken                            string        // APIToken is the token used to authenticate with the CipherSwarm API.
	AlwaysTrustFiles                    bool          // AlwaysTrustFiles specifies whether the agent should trust all files in the files directory and not check checksums.
	ExtraDebugging                      bool          // ExtraDebugging specifies whether the agent should show extra debugging information. Set once at init; safe to read from any goroutine.
	StatusTimer                         int           // StatusTimer is the interval in seconds between status updates.
	WriteZapsToFile                     bool          // WriteZapsToFile specifies whether the agent should write zaps to a file.
	RetainZapsOnCompletion              bool          // RetainZapsOnCompletion specifies whether the agent should retain zaps after a job is completed.
	EnableAdditionalHashTypes           bool          // EnableAdditionalHashTypes specifies whether the agent should enable additional hash types.
	HashcatPath                         string        // HashcatPath is the path to the Hashcat binary (empty for auto-detection).
	UseLegacyDeviceIdentificationMethod bool          // UseLegacyDeviceIdentificationMethod specifies whether the agent should use the legacy device identification method.
	APIClient                           api.APIClient // APIClient is the interface-based client for API operations (enables dependency injection).
	ForceBenchmarkRun                   bool          // ForceBenchmarkRun forces a fresh benchmark run instead of using cached results. Agent-loop-only; no cross-goroutine access.
	InsecureDownloads                   bool          // InsecureDownloads skips TLS certificate verification for downloads.
	DownloadMaxRetries                  int           // DownloadMaxRetries is the max number of download retry attempts.
	DownloadRetryDelay                  time.Duration // DownloadRetryDelay is the base delay between download retries.
	TaskTimeout                         time.Duration // TaskTimeout is the max time for a single task before forced termination.
	MaxHeartbeatBackoff                 int           // MaxHeartbeatBackoff is the max multiplier for heartbeat backoff.
	SleepOnFailure                      time.Duration // SleepOnFailure is how long to wait after a task failure before retrying.
	AlwaysUseNativeHashcat              bool          // AlwaysUseNativeHashcat forces using the system's native Hashcat binary.
	Platform                            string        // Platform is the OS platform the agent is running on (e.g., "linux", "darwin"). Set once before goroutines start; safe to read from any goroutine.
	AgentVersion                        string        // AgentVersion is the current version of the agent software. Set once in AuthenticateAgent before goroutines start; safe to read from any goroutine.

	// Synchronized fields — accessed across goroutines (heartbeat + agent loops).
	// Use getter/setter methods; do not access directly.
	reload              atomic.Bool
	jobCheckingStopped  atomic.Bool
	benchmarksSubmitted atomic.Bool
	currentActivityMu   sync.RWMutex
	currentActivity     Activity
}

// Activity represents the current state or action being carried out by an agent in the system.
type Activity string

// Activity constants define the different states an agent can be in.
const (
	// CurrentActivityStarting indicates the agent is starting up.
	CurrentActivityStarting Activity = "starting"
	// CurrentActivityBenchmarking indicates the agent is running benchmarks.
	CurrentActivityBenchmarking Activity = "benchmarking"
	// CurrentActivityUpdating indicates the agent is updating its cracker.
	CurrentActivityUpdating Activity = "updating"
	// CurrentActivityWaiting indicates the agent is waiting for tasks.
	CurrentActivityWaiting Activity = "waiting"
	// CurrentActivityCracking indicates the agent is cracking hashes.
	CurrentActivityCracking Activity = "cracking"
	// CurrentActivityDownloading indicates the agent is downloading attack files.
	CurrentActivityDownloading Activity = "downloading"
	// CurrentActivityStopping indicates the agent is stopping.
	CurrentActivityStopping Activity = "stopping"
)

// GetReload returns whether the agent should reload its configuration.
func (s *agentState) GetReload() bool {
	return s.reload.Load()
}

// SetReload sets whether the agent should reload its configuration.
func (s *agentState) SetReload(v bool) {
	s.reload.Store(v)
}

// GetJobCheckingStopped returns whether the server has directed the agent to stop checking for new jobs.
func (s *agentState) GetJobCheckingStopped() bool {
	return s.jobCheckingStopped.Load()
}

// SetJobCheckingStopped sets whether the server has directed the agent to stop checking for new jobs.
func (s *agentState) SetJobCheckingStopped(v bool) {
	s.jobCheckingStopped.Store(v)
}

// GetBenchmarksSubmitted returns whether the agent has successfully submitted its benchmark data.
func (s *agentState) GetBenchmarksSubmitted() bool {
	return s.benchmarksSubmitted.Load()
}

// SetBenchmarksSubmitted sets whether the agent has successfully submitted its benchmark data.
func (s *agentState) SetBenchmarksSubmitted(v bool) {
	s.benchmarksSubmitted.Store(v)
}

// GetCurrentActivity returns the current activity of the agent (thread-safe).
func (s *agentState) GetCurrentActivity() Activity {
	s.currentActivityMu.RLock()
	defer s.currentActivityMu.RUnlock()

	return s.currentActivity
}

// SetCurrentActivity sets the current activity of the agent (thread-safe).
func (s *agentState) SetCurrentActivity(a Activity) {
	s.currentActivityMu.Lock()
	defer s.currentActivityMu.Unlock()
	s.currentActivity = a
}

// Logger is a shared logging instance configured to output logs at InfoLevel with timestamps to os.Stdout.
var Logger = log.NewWithOptions(os.Stdout, log.Options{ //nolint:gochecknoglobals // Global logger instance
	Level:           log.InfoLevel,
	ReportTimestamp: true,
})

// ErrorLogger is a logger instance for logging critical errors with detailed error information.
var ErrorLogger = Logger.With() //nolint:gochecknoglobals // Global error logger instance
