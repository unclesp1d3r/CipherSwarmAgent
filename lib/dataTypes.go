package lib

import (
	"github.com/unclesp1d3r/cipherswarm-agent-go-api"
)

type AgentConfiguration struct {
	Config struct {
		UseNativeHashcat    bool   `json:"use_native_hashcat" yaml:"use_native_hashcat"`               // UseNativeHashcat specifies whether to use the native Hashcat implementation.
		AgentUpdateInterval int32  `json:"agent_update_interval" yaml:"agent_update_interval"`         // AgentUpdateInterval specifies the interval in seconds at which the agent should check in with the server.
		BackendDevices      string `json:"backend_devices,omitempty" yaml:"backend_devices,omitempty"` // BackendDevices specifies the devices to use for the backend.
	} `json:"config" yaml:"config"`
	APIVersion int32 `json:"api_version" yaml:"api_version"` // ApiVersion represents the version of the API used by the agent client.
}

// GetAttackMode returns the attack mode code based on the given Attack object.
// The attack mode code is used to identify the type of attack being performed.
// It maps the attack mode string to a corresponding uint8 value.
// If the attack mode is not recognized, it returns 0.
func GetAttackMode(a *cipherswarm.Attack) uint8 {
	switch a.AttackMode {
	case "dictionary":
		return 0
	case "combinator":
		return 1
	case "mask":
		return 3
	case "hybrid-dictionary":
		return 6
	case "hybrid-mask":
		return 7
	default:
		return 0
	}
}

// GetWordlistFilenames returns a slice of filenames extracted from the given Attack's WordLists.
func GetWordlistFilenames(a *cipherswarm.Attack) []string {
	var filenames []string
	for _, wordlist := range a.WordLists {
		filenames = append(filenames, wordlist.GetFileName())
	}
	return filenames
}

// GetRulelistFilenames returns a slice of filenames extracted from the RuleLists
// of the given Attack object.
func GetRulelistFilenames(a *cipherswarm.Attack) []string {
	var filenames []string
	for _, rulelist := range a.RuleLists {
		filenames = append(filenames, rulelist.GetFileName())
	}
	return filenames
}

type BenchmarkResult struct {
	Device    string `json:"device,omitempty"`     // Device is the name of the device used for the benchmark.
	HashType  string `json:"hash_type,omitempty"`  // HashType is the type of hash used for the benchmark.
	RuntimeMs string `json:"runtime,omitempty"`    // RuntimeMs is the runtime of the benchmark in milliseconds.
	SpeedHs   string `json:"hash_speed,omitempty"` // SpeedHs is the hash speed in hashes per second.
}
