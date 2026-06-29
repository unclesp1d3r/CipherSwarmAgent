package benchmark

// Config holds injected path and benchmark-mode configuration for a Manager.
// It is a value type (safe to copy), mirroring task.Config and devices.DeviceConfig,
// so benchmark sessions are constructable without reading agentstate directly.
type Config struct {
	// OutPath is the directory for hashcat output and charset temp files.
	OutPath string
	// ZapsPath is the directory for zap files, removed on cleanup unless retained.
	ZapsPath string
	// RetainZapsOnCompletion keeps the zaps directory after a session completes.
	RetainZapsOnCompletion bool
	// EnableAdditionalHashTypes enables all hash types in full benchmark mode.
	EnableAdditionalHashTypes bool
}
