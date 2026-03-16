package hashcat

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

const windowsOS = "windows"

func TestHashcatSessionDir_PosixLegacyDotHashcat(t *testing.T) {
	if runtime.GOOS == windowsOS {
		t.Skip("POSIX-only test")
	}

	// Create a fake ~/.hashcat directory
	home := t.TempDir()
	t.Setenv("HOME", home)
	dotHashcat := filepath.Join(home, ".hashcat")
	require.NoError(t, os.Mkdir(dotHashcat, 0o750))

	result := posixSessionDir()
	require.Equal(t, filepath.Join(dotHashcat, "sessions"), result)
}

func TestHashcatSessionDir_PosixXDGDataHome(t *testing.T) {
	if runtime.GOOS == windowsOS {
		t.Skip("POSIX-only test")
	}

	// No ~/.hashcat, but XDG_DATA_HOME is set
	home := t.TempDir()
	t.Setenv("HOME", home)
	xdgDir := filepath.Join(t.TempDir(), "xdg-data")
	t.Setenv("XDG_DATA_HOME", xdgDir)

	result := posixSessionDir()
	require.Equal(t, filepath.Join(xdgDir, "hashcat", "sessions"), result)
}

func TestHashcatSessionDir_PosixDefaultFallback(t *testing.T) {
	if runtime.GOOS == windowsOS {
		t.Skip("POSIX-only test")
	}

	// No ~/.hashcat, no XDG_DATA_HOME
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")

	result := posixSessionDir()
	require.Equal(t, filepath.Join(home, ".local", "share", "hashcat", "sessions"), result)
}

func TestHashcatSessionDir_WindowsUsesBinaryDir(t *testing.T) {
	// hashcatSessionDir with a binary path should return its parent directory on Windows
	binaryPath := filepath.Join("C:", "tools", "hashcat", "hashcat.exe")
	result := hashcatSessionDir(binaryPath)

	if runtime.GOOS == windowsOS {
		require.Equal(t, filepath.Join("C:", "tools", "hashcat"), result)
	} else {
		// On non-Windows, hashcatSessionDir ignores binaryPath and uses POSIX logic
		require.NotEqual(t, filepath.Dir(binaryPath), result)
	}
}
