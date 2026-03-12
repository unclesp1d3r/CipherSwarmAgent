package lib

// agentConfig holds the various configuration settings for an agent.
type agentConfig struct {
	UseNativeHashcat    bool   `json:"use_native_hashcat"        yaml:"use_native_hashcat"`        // UseNativeHashcat specifies whether to use the native Hashcat implementation.
	AgentUpdateInterval int64  `json:"agent_update_interval"     yaml:"agent_update_interval"`     // AgentUpdateInterval specifies the interval in seconds at which the agent should check in with the server.
	BackendDevices      string `json:"backend_devices,omitempty" yaml:"backend_devices,omitempty"` // BackendDevices specifies the devices to use for the backend.
	OpenCLDevices       string `json:"opencl_devices,omitempty"  yaml:"opencl_devices,omitempty"`  // OpenCLDevices specifies the OpenCL devices to use.
}

// RecommendedTimeouts holds server-recommended timeout settings (values in seconds).
type RecommendedTimeouts struct {
	ConnectTimeout int `json:"connect_timeout" yaml:"connect_timeout"`
	ReadTimeout    int `json:"read_timeout"    yaml:"read_timeout"`
	WriteTimeout   int `json:"write_timeout"   yaml:"write_timeout"`
	RequestTimeout int `json:"request_timeout" yaml:"request_timeout"`
}

// RecommendedRetry holds server-recommended retry settings.
type RecommendedRetry struct {
	MaxAttempts  int `json:"max_attempts"  yaml:"max_attempts"`
	InitialDelay int `json:"initial_delay" yaml:"initial_delay"`
	MaxDelay     int `json:"max_delay"     yaml:"max_delay"`
}

// RecommendedCircuitBreaker holds server-recommended circuit breaker settings.
type RecommendedCircuitBreaker struct {
	FailureThreshold int `json:"failure_threshold" yaml:"failure_threshold"`
	Timeout          int `json:"timeout"           yaml:"timeout"`
}

// agentConfiguration holds the configuration settings and API version for the agent client.
type agentConfiguration struct {
	Config                    agentConfig                `json:"config"                                yaml:"config"`
	APIVersion                int64                      `json:"api_version"                           yaml:"api_version"`
	BenchmarksNeeded          bool                       `json:"benchmarks_needed"                     yaml:"benchmarks_needed"`
	RecommendedTimeouts       *RecommendedTimeouts       `json:"recommended_timeouts,omitempty"        yaml:"recommended_timeouts,omitempty"`
	RecommendedRetry          *RecommendedRetry          `json:"recommended_retry,omitempty"           yaml:"recommended_retry,omitempty"`
	RecommendedCircuitBreaker *RecommendedCircuitBreaker `json:"recommended_circuit_breaker,omitempty" yaml:"recommended_circuit_breaker,omitempty"`
}
