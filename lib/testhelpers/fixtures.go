// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/shirou/gopsutil/v3/host"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

const (
	defaultSpeed               = 1_000_000
	defaultUtil                = 50
	defaultTemp                = 60
	defaultUtilHigh            = 75
	defaultTempHigh            = 65
	defaultAgentInterval int64 = 300
)

const (
	wordListID = 1
	ruleListID = 2
	maskListID = 3
)

// TestAgentConfiguration represents the configuration response body for tests.
// This replaces the old operations.GetConfigurationResponseBody type.
type TestAgentConfiguration struct {
	APIVersion int                            `json:"api_version"`
	Config     api.AdvancedAgentConfiguration `json:"config"`
}

// NewTestTask creates a minimal valid Task object with the specified IDs and reasonable defaults for other fields.
// This will be used extensively across task-related tests.
func NewTestTask(id, attackID int64) *api.Task {
	now := time.Now()
	return &api.Task{
		Id:        id,
		AttackId:  attackID,
		StartDate: now,
		Status:    "pending",
	}
}

// NewTestAttack creates a test Attack object with the specified ID and attack mode,
// including mock resource files (word list, rule list, mask list) with download URLs.
func NewTestAttack(id int64, attackMode int) *api.Attack {
	hashListURL := "https://example.com/hashlist"
	checksumHex := "d41d8cd98f00b204e9800998ecf8427e"
	checksumBytes, err := hex.DecodeString(checksumHex)
	if err != nil {
		panic("invalid test checksum hex: " + err.Error())
	}
	wordListURL := "https://example.com/wordlist.txt"
	ruleListURL := "https://example.com/rules.txt"
	maskListURL := "https://example.com/masks.txt"

	attack := &api.Attack{
		Id:                id,
		AttackModeHashcat: attackMode,
		HashListId:        1,
		HashListUrl:       &hashListURL,
		HashListChecksum:  &checksumBytes,
		HashMode:          0,
		WordList: &api.AttackResourceFile{
			Id:          wordListID,
			DownloadUrl: wordListURL,
			Checksum:    checksumBytes,
			FileName:    "wordlist.txt",
		},
		RuleList: &api.AttackResourceFile{
			Id:          ruleListID,
			DownloadUrl: ruleListURL,
			Checksum:    checksumBytes,
			FileName:    "rules.txt",
		},
		MaskList: &api.AttackResourceFile{
			Id:          maskListID,
			DownloadUrl: maskListURL,
			Checksum:    checksumBytes,
			FileName:    "masks.txt",
		},
	}

	return attack
}

// NewTestHashcatStatus creates a sample hashcat.Status object with realistic values
// for all fields including devices, progress, and guess information.
// Note: The Guess field uses hashcat's internal statusGuess type which is not exported,
// so this function creates a Status with a zero-value Guess. For tests requiring Guess data,
// consider creating a helper in the hashcat package or using reflection.
func NewTestHashcatStatus(sessionName string) hashcat.Status {
	now := time.Now()
	status := hashcat.Status{
		OriginalLine:    "STATUS",
		Time:            now,
		Session:         sessionName,
		Status:          1, // Running
		Target:          "test.hsh",
		Progress:        []int64{100, 1000},
		RestorePoint:    0,
		RecoveredHashes: []int64{0},
		RecoveredSalts:  []int64{0},
		Rejected:        0,
		Devices: []hashcat.StatusDevice{
			{
				DeviceID:   0,
				DeviceName: "CPU",
				DeviceType: "CPU",
				Speed:      defaultSpeed,
				Util:       defaultUtil,
				Temp:       defaultTemp,
			},
		},
		TimeStart:     now.Unix(),
		EstimatedStop: now.Add(time.Hour).Unix(),
	}
	// Guess field will be zero-initialized since statusGuess is unexported
	return status
}

// NewTestDeviceStatus creates a test StatusDevice with the specified ID and type.
func NewTestDeviceStatus(deviceID int64, deviceType string) hashcat.StatusDevice {
	return hashcat.StatusDevice{
		DeviceID:   deviceID,
		DeviceName: deviceType + " Device",
		DeviceType: deviceType,
		Speed:      defaultSpeed,
		Util:       defaultUtilHigh,
		Temp:       defaultTempHigh,
	}
}

// NewTestAgentConfiguration creates a test agent configuration with specified settings.
func NewTestAgentConfiguration(useNativeHashcat bool) TestAgentConfiguration {
	interval := int(defaultAgentInterval)
	return TestAgentConfiguration{
		APIVersion: 1,
		Config: api.AdvancedAgentConfiguration{
			UseNativeHashcat:    &useNativeHashcat,
			AgentUpdateInterval: &interval,
		},
	}
}

// NewTestAgent creates a test Agent object with the specified ID and hostname,
// including reasonable defaults for other fields (client_signature, operating_system, devices).
func NewTestAgent(agentID int64, hostname string) api.Agent {
	return api.Agent{
		Id:              agentID,
		HostName:        hostname,
		ClientSignature: "CipherSwarm Agent/test",
		OperatingSystem: "linux",
		Devices:         []string{"CPU", "GPU0"},
	}
}

// MockHostInfo is a placeholder that always returns an error.
// Go's host.Info() cannot be easily mocked without interfaces or build tags.
// Tests requiring host info should use build tags or accept real host.Info() calls.
func MockHostInfo() (*host.InfoStat, error) {
	// This is a placeholder - actual tests should use build tags or accept real host.Info()
	// Returning a sentinel error avoids returning nil, nil which linters disallow.
	return nil, errors.New("mock not implemented")
}

// MockDevicesList returns a mock list of device names for testing device discovery.
func MockDevicesList() []string {
	return []string{"CPU", "GPU0", "GPU1"}
}
