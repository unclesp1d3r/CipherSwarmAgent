//go:build linux

// Package arch provides architecture-specific functionality for Linux systems.
// It includes utilities for device detection, platform identification, and
// execution of system-specific commands like hashcat and 7z.
package arch

import (
	"context"
	"os/exec"
	"regexp"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// GetDevices retrieves a list of GPU devices available on a Linux system.
// It executes the "lspci" command to list all PCI devices and filters out
// the ones that are VGA compatible controllers (typically GPUs).
//
// Parameters:
//   - ctx: A context for cancellation and deadlines. The command will be cancelled if ctx is cancelled.
//
// Returns:
//
//	[]string: A slice of strings containing the names of the GPU devices.
//	error: An error object if there was an issue executing the command or parsing the output.
func GetDevices(ctx context.Context) ([]string, error) {
	shared.Logger.Debug("Getting GPU devices")

	out, err := exec.CommandContext(ctx, "lspci").Output()
	if err != nil {
		shared.Logger.Error("Error executing lspci command", "error", err)
		return nil, err
	}

	commandResult := string(out)
	// Improved regular expression to match VGA compatible controllers more reliably
	re := regexp.MustCompile(`VGA compatible controller: (.+?) \(`)
	matches := re.FindAllStringSubmatch(commandResult, -1)

	if matches == nil {
		shared.Logger.Warn("No GPU devices found")
		return nil, nil
	}

	var devices []string
	for _, match := range matches {
		if len(match) > 1 {
			devices = append(devices, strings.TrimSpace(match[1]))
		}
	}

	if len(devices) == 0 {
		shared.Logger.Error("No GPU devices found after parsing")
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
//   - ctx: A context for cancellation and deadlines. The command will be cancelled if ctx is cancelled.
//   - hashcatPath: The file path to the Hashcat executable.
//
// Returns:
//   - A string representing the Hashcat version.
//   - An error if the command execution fails.
func GetHashcatVersion(ctx context.Context, hashcatPath string) (string, error) {
	out, err := exec.CommandContext(ctx, hashcatPath, "--version", "--quiet").Output()
	if err != nil {
		return "0.0.0", err
	}
	return strings.TrimSpace(string(out)), nil
}

// GetPlatform returns the platform identifier for Linux systems.
func GetPlatform() string {
	return "linux"
}

// Extract7z extracts the contents of a 7z archive to a specified directory.
// It takes the source file path of the 7z archive and the destination directory
// where the contents should be extracted.
//
// Parameters:
//   - ctx: A context for cancellation and deadlines. The command will be cancelled if ctx is cancelled.
//   - srcFile: The path to the 7z archive file.
//   - destDir: The directory where the contents of the archive will be extracted.
//
// Returns:
//   - error: An error object if the extraction fails, otherwise nil.
func Extract7z(ctx context.Context, srcFile, destDir string) error {
	//nolint:gosec // srcFile and destDir are validated by caller
	_, err := exec.CommandContext(ctx, "7z", "x", srcFile, "-o"+destDir).
		Output()

	return err
}

// GetDefaultHashcatBinaryName returns the default binary name for the Hashcat tool on Linux systems.
// This function is useful for determining the standard executable name used by Hashcat.
func GetDefaultHashcatBinaryName() string {
	return "hashcat"
}

// GetAdditionalHashcatArgs returns a slice of additional arguments to be passed to Hashcat.
// Currently, it returns an empty slice, but it can be extended to include more arguments as needed.
func GetAdditionalHashcatArgs() []string {
	return []string{}
}
