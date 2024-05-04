package shared

var SharedState = AgentState{}

type AgentState struct {
	PidFile           string
	HashcatPidFile    string
	DataPath          string
	CrackersPath      string
	HashlistPath      string
	ZapsPath          string
	PreprocessorsPath string
	ToolsPath         string
	OutPath           string
	FilePath          string
	Debug             bool
	AgentID           int64
}
