package shared

import (
	"context"
	"os"

	"github.com/charmbracelet/log"
	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
)

// State represents the configuration and runtime state of the agent.
var State = agentState{}

// agentState represents the state and configuration settings of an agent in the CipherSwarm system.
type agentState struct {
	PidFile                             string                   // PidFile is the path to the file containing the agent's process ID.
	HashcatPidFile                      string                   // HashcatPidFile is the path to the file containing the Hashcat process ID.
	DataPath                            string                   // DataPath is the path to the directory containing the agent's data files.
	CrackersPath                        string                   // CrackersPath is the path to the directory containing the agent's cracker binaries.
	HashlistPath                        string                   // HashlistPath is the path to the directory containing the agent's hashlists.
	ZapsPath                            string                   // ZapsPath is the path to the directory containing the agent's zaps.
	PreprocessorsPath                   string                   // PreprocessorsPath is the path to the directory containing the agent's preprocessors.
	ToolsPath                           string                   // ToolsPath is the path to the directory containing the agent's tools.
	OutPath                             string                   // OutPath is the path to the directory containing the agent's output files.
	FilePath                            string                   // FilePath is the path to the file containing various files for attacks.
	RestoreFilePath                     string                   // RestoreFilePath is the path to the file containing hashcat's restore data.
	Debug                               bool                     // Debug specifies whether the agent is running in debug mode.
	AgentID                             int64                    // AgentID is the unique identifier of the agent.
	URL                                 string                   // URL is the URL of the CipherSwarm API.
	APIToken                            string                   // APIToken is the token used to authenticate with the CipherSwarm API.
	Reload                              bool                     // Reload specifies whether the agent should reload its configuration.
	CurrentActivity                     activity                 // CurrentActivity is the current activity of the agent.
	AlwaysTrustFiles                    bool                     // AlwaysTrustFiles specifies whether the agent should trust all files in the files directory and not check checksums.
	ExtraDebugging                      bool                     // ExtraDebugging specifies whether the agent should show extra debugging information.
	StatusTimer                         int                      // StatusTimer is the interval in seconds between status updates.
	WriteZapsToFile                     bool                     // WriteZapsToFile specifies whether the agent should write zaps to a file.
	RetainZapsOnCompletion              bool                     // RetainZapsOnCompletion specifies whether the agent should retain zaps after a job is completed.
	EnableAdditionalHashTypes           bool                     // EnableAdditionalHashTypes specifies whether the agent should enable additional hash types.
	JobCheckingStopped                  bool                     // JobCheckingStopped indicates that the server has directed the agent to stop checking for new jobs.
	UseLegacyDeviceIdentificationMethod bool                     // UseLegacyDeviceIdentificationMethod specifies whether the agent should use the legacy device identification method.
	SdkClient                           *sdk.CipherSwarmAgentSDK // SdkClient is the client for interacting with the CipherSwarm API.
	Context                             context.Context          // Context represents the context of the agent.
}

// activity represents the current state or action being carried out by an agent in the system.
type activity string

const (
	CurrentActivityStarting     activity = "starting"
	CurrentActivityBenchmarking activity = "benchmarking"
	CurrentActivityUpdating     activity = "updating"
	CurrentActivityWaiting      activity = "waiting"
	CurrentActivityCracking     activity = "cracking"
	CurrentActivityStopping     activity = "stopping"
)

// Logger is a shared logging instance configured to output logs at InfoLevel with timestamps to os.Stdout.
var Logger = log.NewWithOptions(os.Stdout, log.Options{
	Level:           log.InfoLevel,
	ReportTimestamp: true,
})

// ErrorLogger is a logger instance for logging critical errors with detailed error information.
var ErrorLogger = Logger.With()
