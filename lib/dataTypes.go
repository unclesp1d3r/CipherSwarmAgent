package lib

import (
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
)

type agentConfiguration struct {
	Config struct {
		UseNativeHashcat    bool   `json:"use_native_hashcat" yaml:"use_native_hashcat"`               // UseNativeHashcat specifies whether to use the native Hashcat implementation.
		AgentUpdateInterval int64  `json:"agent_update_interval" yaml:"agent_update_interval"`         // AgentUpdateInterval specifies the interval in seconds at which the agent should check in with the server.
		BackendDevices      string `json:"backend_devices,omitempty" yaml:"backend_devices,omitempty"` // BackendDevices specifies the devices to use for the backend.
	} `json:"config" yaml:"config"`
	APIVersion int64 `json:"api_version" yaml:"api_version"` // ApiVersion represents the version of the API used by the agent client.
}

// GetAttackMode returns the attack mode code based on the given Attack object.
// The attack mode code is used to identify the type of attack being performed.
// It maps the attack mode string to a corresponding uint8 value.
// If the attack mode is not recognized, it returns 0.

func parseStringToDeviceType(deviceType string) components.TheTypeOfTheDevice {
	switch deviceType {
	case "CPU":
		return components.TheTypeOfTheDeviceCPU
	case "GPU":
		return components.TheTypeOfTheDeviceGpu
	// case "fpga":
	// 	return components.DeviceTypeFPGA
	// case "asic":
	// 	return components.DeviceTypeASIC
	default:
		return components.TheTypeOfTheDeviceCPU
	}
}

// getWordlistFilenames returns a slice of filenames extracted from the given Attack's WordLists.
func getWordlistFilenames(a *components.Attack) []string {
	filenames := make([]string, len(a.WordLists))
	for i, wordlist := range a.WordLists {
		filenames[i] = wordlist.GetFileName()
	}
	return filenames
}

// getRulelistFilenames returns a slice of filenames extracted from the RuleLists
// of the given Attack object.
func getRulelistFilenames(a *components.Attack) []string {
	filenames := make([]string, len(a.RuleLists))
	for i, ruleList := range a.RuleLists {
		filenames[i] = ruleList.GetFileName()
	}
	return filenames
}

type BenchmarkResult struct {
	Device    string `json:"device,omitempty"`     // Device is the name of the device used for the benchmark.
	HashType  string `json:"hash_type,omitempty"`  // HashType is the type of hash used for the benchmark.
	RuntimeMs string `json:"runtime,omitempty"`    // RuntimeMs is the runtime of the benchmark in milliseconds.
	SpeedHs   string `json:"hash_speed,omitempty"` // SpeedHs is the hash speed in hashes per second.
}
