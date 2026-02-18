// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"errors"
	"net/http"
	"time"

	"github.com/shirou/gopsutil/v3/host"
	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
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

// NewTestTask creates a minimal valid Task object with the specified IDs and reasonable defaults for other fields.
// This will be used extensively across task-related tests.
func NewTestTask(id, attackID int64) *components.Task {
	now := time.Now()
	return &components.Task{
		ID:        id,
		AttackID:  attackID,
		StartDate: now,
		Status:    "pending",
	}
}

// NewTestAttack creates a test Attack object with the specified ID and attack mode,
// including mock resource files (word list, rule list, mask list) with download URLs.
func NewTestAttack(id int64, attackMode int) *components.Attack {
	mode := int64(attackMode)
	hashListURL := "https://example.com/hashlist"
	checksum := "d41d8cd98f00b204e9800998ecf8427e"
	wordListURL := "https://example.com/wordlist.txt"
	ruleListURL := "https://example.com/rules.txt"
	maskListURL := "https://example.com/masks.txt"

	attack := &components.Attack{
		ID:                id,
		AttackModeHashcat: &mode,
		HashListID:        1,
		HashListURL:       &hashListURL,
		HashListChecksum:  &checksum,
		HashMode:          new(int64),
		WordList: &components.AttackResourceFile{
			ID:          wordListID,
			DownloadURL: wordListURL,
			Checksum:    checksum,
			FileName:    "wordlist.txt",
		},
		RuleList: &components.AttackResourceFile{
			ID:          ruleListID,
			DownloadURL: ruleListURL,
			Checksum:    checksum,
			FileName:    "rules.txt",
		},
		MaskList: &components.AttackResourceFile{
			ID:          maskListID,
			DownloadURL: maskListURL,
			Checksum:    checksum,
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
func NewTestAgentConfiguration(useNativeHashcat bool) operations.GetConfigurationResponseBody {
	interval := defaultAgentInterval
	return operations.GetConfigurationResponseBody{
		APIVersion: 1,
		Config: components.AdvancedAgentConfiguration{
			UseNativeHashcat:    &useNativeHashcat,
			AgentUpdateInterval: &interval,
		},
	}
}

// NewTestSDKClient creates a configured SDK client instance pointing to the provided base URL
// (typically a test server). This should be used after calling SetupHTTPMock().
// When httpmock.Activate() is called, it wraps http.DefaultTransport, so the SDK will
// automatically use the mocked transport when using the default client.
// For custom clients, use SetupHTTPMockForClient() and pass that client to this function.
func NewTestSDKClient(baseURL string) *sdk.CipherSwarmAgentSDK {
	return sdk.New(
		sdk.WithServerURL(baseURL),
		sdk.WithSecurity("test-token"), // Set a default test token for authentication
		// Don't override the client - let SDK use default client which httpmock.Activate() wraps
	)
}

// NewTestSDKClientWithClient creates a configured SDK client instance with a custom http.Client.
// This should be used after calling SetupHTTPMockForClient(client). The same client instance
// passed to SetupHTTPMockForClient must be passed here.
func NewTestSDKClientWithClient(baseURL string, client *http.Client) *sdk.CipherSwarmAgentSDK {
	return sdk.New(
		sdk.WithServerURL(baseURL),
		sdk.WithSecurity("test-token"), // Set a default test token for authentication
		sdk.WithClient(client),
	)
}

// NewTestAgent creates a test Agent object with the specified ID and hostname,
// including reasonable defaults for other fields (client_signature, operating_system, devices).
func NewTestAgent(agentID int64, hostname string) components.Agent {
	return components.Agent{
		ID:              agentID,
		HostName:        hostname,
		ClientSignature: "CipherSwarm Agent/test",
		OperatingSystem: "linux",
		Devices:         []string{"CPU", "GPU0"},
	}
}

// MockHostInfo returns a mock host.InfoStat object with test data (hostname, OS, kernel arch).
// Note: Go doesn't support easy function mocking without interfaces.
// Tests using UpdateAgentMetadata should either use build tags or accept that real host info is used.
func MockHostInfo() (*host.InfoStat, error) {
	// This is a placeholder - actual tests should use build tags or accept real host.Info()
	// Returning a sentinel error avoids returning nil, nil which linters disallow.
	return nil, errors.New("mock not implemented")
}

// MockDevicesList returns a mock list of device names for testing device discovery.
func MockDevicesList() []string {
	return []string{"CPU", "GPU0", "GPU1"}
}
