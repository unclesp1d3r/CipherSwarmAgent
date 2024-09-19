package lib

import (
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
)

// agentConfig holds configuration settings for the agent.
type agentConfig struct {
	UseNativeHashcat    bool   `json:"use_native_hashcat"        yaml:"use_native_hashcat"`        // UseNativeHashcat specifies whether to use the native Hashcat implementation.
	AgentUpdateInterval int64  `json:"agent_update_interval"     yaml:"agent_update_interval"`     // AgentUpdateInterval specifies the interval in seconds at which the agent should check in with the server.
	BackendDevices      string `json:"backend_devices,omitempty" yaml:"backend_devices,omitempty"` // BackendDevices specifies the devices to use for the backend.
	OpenCLDevices       string `json:"opencl_devices,omitempty"  yaml:"opencl_devices,omitempty"`  // OpenCLDevices specifies the OpenCL devices to use.
}

// agentConfiguration holds the configuration settings for an agent, including API version and detailed agent configurations.
type agentConfiguration struct {
	Config     agentConfig `json:"config"      yaml:"config"`
	APIVersion int64       `json:"api_version" yaml:"api_version"` // ApiVersion represents the version of the API used by the agent client.
}

// parseStringToDeviceType converts a string representing the device type to a components.DeviceType constant.
// Utilizes a switch statement to match the provided device type string with the corresponding constant.
// Default case returns components.DeviceTypeCPU if no match is found.
func parseStringToDeviceType(deviceType string) components.DeviceType {
	switch deviceType {
	case "CPU":
		return components.DeviceTypeCPU
	case "GPU":
		return components.DeviceTypeGpu
	// case "fpga":
	// 	return components.DeviceTypeFPGA
	// case "asic":
	// 	return components.DeviceTypeASIC
	default:
		return components.DeviceTypeCPU
	}
}

// benchmarkResult represents the results of a benchmarking process.
type benchmarkResult struct {
	Device     string `json:"device,omitempty"`     // Device is the name of the device used for the benchmark.
	HashType   string `json:"hash_type,omitempty"`  // HashType is the type of hash used for the benchmark.
	RuntimeMs  string `json:"runtime,omitempty"`    // RuntimeMs is the runtime of the benchmark in milliseconds.
	HashTimeMs string `json:"hash_time,omitempty"`  // HashTimeMs is the time taken to hash in milliseconds.
	SpeedHs    string `json:"hash_speed,omitempty"` // SpeedHs is the hash speed in hashes per second.
}
