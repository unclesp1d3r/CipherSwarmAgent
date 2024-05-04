package shared

var SharedState = AgentState{}

type AgentState struct {
	PidFile           string // PidFile is the path to the file containing the agent's process ID.
	HashcatPidFile    string // HashcatPidFile is the path to the file containing the Hashcat process ID.
	DataPath          string // DataPath is the path to the directory containing the agent's data files.
	CrackersPath      string // CrackersPath is the path to the directory containing the agent's cracker binaries.
	HashlistPath      string // HashlistPath is the path to the directory containing the agent's hashlists.
	ZapsPath          string // ZapsPath is the path to the directory containing the agent's zaps.
	PreprocessorsPath string // PreprocessorsPath is the path to the directory containing the agent's preprocessors.
	ToolsPath         string // ToolsPath is the path to the directory containing the agent's tools.
	OutPath           string // OutPath is the path to the directory containing the agent's output files.
	FilePath          string // FilePath is the path to the file containing various files for attacks.
	Debug             bool   // Debug specifies whether the agent is running in debug mode.
	AgentID           int64  // AgentID is the unique identifier of the agent.
}
