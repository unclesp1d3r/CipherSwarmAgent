package lib

// agentConfig holds the various configuration settings for an agent.
type agentConfig struct {
	UseNativeHashcat    bool   `json:"use_native_hashcat"        yaml:"use_native_hashcat"`        // UseNativeHashcat specifies whether to use the native Hashcat implementation.
	AgentUpdateInterval int64  `json:"agent_update_interval"     yaml:"agent_update_interval"`     // AgentUpdateInterval specifies the interval in seconds at which the agent should check in with the server.
	BackendDevices      string `json:"backend_devices,omitempty" yaml:"backend_devices,omitempty"` // BackendDevices specifies the devices to use for the backend.
	OpenCLDevices       string `json:"opencl_devices,omitempty"  yaml:"opencl_devices,omitempty"`  // OpenCLDevices specifies the OpenCL devices to use.
}

// agentConfiguration holds the configuration settings and API version for the agent client.
type agentConfiguration struct {
	Config           agentConfig `json:"config"            yaml:"config"`
	APIVersion       int64       `json:"api_version"       yaml:"api_version"`       // ApiVersion represents the version of the API used by the agent client.
	BenchmarksNeeded bool        `json:"benchmarks_needed" yaml:"benchmarks_needed"` // BenchmarksNeeded indicates whether the server requires new benchmarks from this agent.
}
