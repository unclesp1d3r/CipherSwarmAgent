package task

// Config holds injected path and timer configuration for a Manager.
// It is a value type (safe to copy).
type Config struct {
	// HashlistPath is the directory where hash list files are stored.
	HashlistPath string
	// RestoreFilePath is the directory where hashcat restore files are stored.
	RestoreFilePath string
	// FilePath is the directory where attack resource files are stored.
	FilePath string
	// OutPath is the directory where hashcat output files are written.
	OutPath string
	// ZapsPath is the directory where zap (cracked hash) files are stored.
	ZapsPath string
	// StatusTimer is the interval in seconds between status updates.
	StatusTimer int
	// RetainZapsOnCompletion specifies whether zap files are kept after task completion.
	RetainZapsOnCompletion bool
}
