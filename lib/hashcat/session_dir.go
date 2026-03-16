package hashcat

import (
	"os"
	"path/filepath"
	"runtime"
)

// sessionsSubdir is the subdirectory name hashcat uses for session files.
const sessionsSubdir = "sessions"

// hashcatSessionDir resolves the directory where hashcat stores session files
// (.log, .pid, .restore). This mirrors the logic in hashcat's folder.c:
//
// POSIX:
//  1. ~/.hashcat/sessions (if ~/.hashcat exists)
//  2. $XDG_DATA_HOME/hashcat/sessions (if XDG_DATA_HOME is set)
//  3. ~/.local/share/hashcat/sessions (fallback)
//
// Windows:
//
//	<hashcat binary directory> (hashcat uses its install dir on Windows)
//
// The binaryPath parameter is used on Windows to derive the install directory.
func hashcatSessionDir(binaryPath string) string {
	if runtime.GOOS == "windows" {
		return filepath.Dir(binaryPath)
	}

	return posixSessionDir()
}

// posixSessionDir resolves the hashcat session directory on POSIX systems.
func posixSessionDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback: if we can't determine home, use CWD (best effort)
		return "."
	}

	// Check if ~/.hashcat exists (legacy path)
	dotHashcat := filepath.Join(home, ".hashcat")
	if info, statErr := os.Stat(dotHashcat); statErr == nil && info.IsDir() {
		return filepath.Join(dotHashcat, sessionsSubdir)
	}

	// Check XDG_DATA_HOME
	if xdgDataHome := os.Getenv("XDG_DATA_HOME"); xdgDataHome != "" {
		return filepath.Join(xdgDataHome, "hashcat", sessionsSubdir)
	}

	// Default: ~/.local/share/hashcat/sessions
	return filepath.Join(home, ".local", "share", "hashcat", sessionsSubdir)
}
