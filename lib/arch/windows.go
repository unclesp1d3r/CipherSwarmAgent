//go:build windows

// Package arch provides OS- and architecture-specific helpers for process management and system interactions.
package arch

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// allowedBinaries defines the set of binaries that are safe to execute.
var allowedBinaries = map[string]struct{}{
	"hashcat.exe": {},
	"wmic.exe":    {},
	"7z.exe":      {},
	"cmd.exe":     {},
}

// isAllowedBinary checks if a binary is in the allowlist for safe execution.
func isAllowedBinary(bin string) bool {
	_, ok := allowedBinaries[strings.ToLower(filepath.Base(bin))]
	return ok
}

// validateArgs ensures command arguments don't contain shell metacharacters or unsafe content.
func validateArgs(args []string) error {
	for _, a := range args {
		if strings.ContainsAny(a, "&|;><`$") || strings.Contains(a, "\n") || strings.Contains(a, "\r") {
			return fmt.Errorf("unsafe argument detected: %q", a)
		}
	}
	return nil
}

// execSafeCommand creates a secure exec.Cmd with input validation
// #nosec G204 -- Inputs are validated by isAllowedBinary and validateArgs; we use exec.CommandContext with direct args (no shell).
func execSafeCommand(ctx context.Context, bin string, args ...string) (*exec.Cmd, error) {
	if !isAllowedBinary(bin) {
		return nil, fmt.Errorf("binary %q not allowed", bin)
	}
	if err := validateArgs(args); err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, bin, args...), nil
}

// GetDevices retrieves a list of GPU devices available on a Windows system.
// It uses WMI to query the Win32_VideoController class and extracts the names
// of the GPU devices.
//
// Parameters:
//   - ctx: Context for cancellation and deadline control.
//
// Returns:
//
//	[]string: A slice of strings containing the names of the GPU devices.
//	error: An error object if there was an issue executing the command or parsing the output.
func GetDevices(ctx context.Context) ([]string, error) {
	shared.Logger.Debug("Getting GPU devices")
	cmd, err := execSafeCommand(ctx, "wmic", "path", "win32_videocontroller", "get", "name")
	if err != nil {
		return nil, fmt.Errorf("failed to create secure command: %w", err)
	}
	out, err := cmd.Output()
	if err != nil {
		shared.Logger.Error("Error executing wmic command", "error", err)
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	var devices []string
	for _, line := range lines {
		device := strings.TrimSpace(line)
		if device != "" && device != "Name" {
			devices = append(devices, device)
		}
	}

	if len(devices) == 0 {
		shared.Logger.Warn("No GPU devices found")
		return nil, nil
	}

	return devices, nil
}

// GetHashcatVersion retrieves the version of Hashcat installed at the specified path.
// It runs the Hashcat executable with the "--version" and "--quiet" flags and returns
// the version as a string. If an error occurs during execution, it returns "0.0.0"
// and the error.
//
// Parameters:
//   - ctx: Context for cancellation and deadline control.
//   - hashcatPath: The file path to the Hashcat executable.
//
// Returns:
//   - A string representing the Hashcat version.
//   - An error if the command execution fails.
func GetHashcatVersion(ctx context.Context, hashcatPath string) (string, error) {
	cmd, err := execSafeCommand(ctx, hashcatPath, "--version", "--quiet")
	if err != nil {
		return "0.0.0", fmt.Errorf("failed to create secure command: %w", err)
	}
	out, err := cmd.Output()
	if err != nil {
		return "0.0.0", err
	}
	return strings.TrimSpace(string(out)), nil
}

// GetPlatform returns the platform identifier for the current system.
// On Windows systems, this function always returns "windows".
func GetPlatform() string {
	return "windows"
}

// Extract7z extracts the contents of a 7z archive to a specified directory.
// It takes the source file path of the 7z archive and the destination directory
// where the contents should be extracted.
//
// Parameters:
//   - ctx: Context for cancellation and deadline control.
//   - srcFile: The path to the 7z archive file.
//   - destDir: The directory where the contents of the archive will be extracted.
//
// Returns:
//   - error: An error object if the extraction fails, otherwise nil.
func Extract7z(ctx context.Context, srcFile, destDir string) error {
	cmd, err := execSafeCommand(ctx, "7z", "x", srcFile, "-o"+destDir)
	if err != nil {
		return fmt.Errorf("failed to create secure command: %w", err)
	}
	_, err = cmd.Output()
	return err
}

// GetDefaultHashcatBinaryName returns the default binary name for the Hashcat tool on Windows systems.
// This function is useful for determining the standard executable name used by Hashcat.
func GetDefaultHashcatBinaryName() string {
	return "hashcat.exe"
}

// GetAdditionalHashcatArgs returns a slice of additional arguments to be passed to Hashcat.
// Currently, it returns an empty slice, but it can be extended to include more arguments as needed.
func GetAdditionalHashcatArgs() []string {
	return []string{}
}
