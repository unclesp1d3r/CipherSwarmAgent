package lib

import (
	"github.com/unclesp1d3r/cipherswarm-agent-go-api"
)

type AgentConfiguration struct {
	Config struct {
		UseNativeHashcat    bool   `json:"use_native_hashcat" yaml:"use_native_hashcat"` // UseNativeHashcat specifies whether to use the native Hashcat implementation.
		AgentUpdateInterval int    `json:"agent_update_interval" yaml:"agent_update_interval"`
		BackendDevices      string `json:"backend_devices,omitempty" yaml:"backend_devices,omitempty"`
	} `json:"config" yaml:"config"`
	APIVersion int32 `json:"api_version" yaml:"api_version"` // ApiVersion represents the version of the API used by the agent client.
}

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

func GetWordlistFilenames(a *cipherswarm.Attack) []string {
	var filenames []string
	for _, wordlist := range a.WordLists {
		filenames = append(filenames, wordlist.GetFileName())
	}
	return filenames
}

func GetRulelistFilenames(a *cipherswarm.Attack) []string {
	var filenames []string
	for _, rulelist := range a.RuleLists {
		filenames = append(filenames, rulelist.GetFileName())
	}
	return filenames
}

type BenchmarkResult struct {
	Device    string `json:"device,omitempty"`
	HashType  string `json:"hash_type,omitempty"`
	RuntimeMs string `json:"runtime,omitempty"`
	SpeedHs   string `json:"hash_speed,omitempty"`
}
