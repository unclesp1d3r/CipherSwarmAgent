package hashcat

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

const (
	// sessionsSubdir is the subdirectory name hashcat uses for session files.
	sessionsSubdir = "sessions"
	// sessionPrefix is the prefix used for all agent-created hashcat session names.
	sessionPrefix = "attack-"
)

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

// CleanupOrphanedSessionFiles removes stale session .log and .pid files
// from hashcat's session directory. It is safe to call at agent startup —
// at that point, any leftover attack-* files are orphaned by definition.
// Errors are logged but never returned; cleanup failure must not prevent
// agent startup. On Windows, cleanup is skipped because the session
// directory is the hashcat binary directory, which is too broad for removal.
func CleanupOrphanedSessionFiles(binaryPath string) {
	if runtime.GOOS == "windows" {
		return
	}

	sessDir := hashcatSessionDir(binaryPath)
	cleanupOrphanedInDir(sessDir)
}

// cleanupOrphanedInDir scans the given directory for orphaned session files
// matching the attack-* naming pattern and removes them. Only regular files
// are removed — symlinks, directories, and special files are skipped.
func cleanupOrphanedInDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			agentstate.Logger.Warn("couldn't read session directory", "dir", dir, "error", err)
		}

		return
	}

	removed := 0

	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() {
			continue
		}

		if !strings.HasPrefix(name, sessionPrefix) {
			continue
		}

		if !strings.HasSuffix(name, ".log") && !strings.HasSuffix(name, ".pid") {
			continue
		}

		err := os.Remove(filepath.Join(dir, name))
		switch {
		case err == nil:
			removed++
		case os.IsNotExist(err):
			// File already gone — skip silently
		default:
			agentstate.Logger.Error("couldn't remove orphaned session file", "file", name, "error", err)
		}
	}

	if removed > 0 {
		agentstate.Logger.Debug("removed orphaned session files", "count", removed, "dir", dir)
	}
}
