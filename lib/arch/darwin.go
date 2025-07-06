//go:build darwin

// Package arch provides platform-specific functionality for macOS systems.
package arch

import (
	"errors"
	"os/exec"
	"regexp"
	"strings"
)

var (
	// ErrNoDisplayDevices is returned when no display devices are found.
	ErrNoDisplayDevices = errors.New("no display devices found")
	// ErrNoValidDeviceNames is returned when no valid display device names can be extracted.
	ErrNoValidDeviceNames = errors.New("no valid display device names extracted")
)

// GetDevices retrieves a list of display device names on a macOS system.
// It executes the "system_profiler" command to get display information and parses the output
// to extract the chipset model names.
//
// Returns:
//   - []string: A slice containing the names of the display devices.
//   - error: An error object if the command execution or parsing fails.
func GetDevices() ([]string, error) {
	out, err := exec.Command("system_profiler", "SPDisplaysDataType", "-detaillevel", "mini").Output()
	if err != nil {
		return nil, err
	}

	commandResult := string(out)
	re := regexp.MustCompile(`Chipset Model: (.*)`)

	matches := re.FindAllStringSubmatch(commandResult, -1)
	if matches == nil {
		return nil, ErrNoDisplayDevices
	}

	var newArray []string

	for _, match := range matches {
		if len(match) > 1 {
			newArray = append(newArray, strings.TrimSpace(match[1]))
		}
	}

	if len(newArray) == 0 {
		return nil, ErrNoValidDeviceNames
	}

	return newArray, nil
}

// GetHashcatVersion retrieves the version of Hashcat installed at the specified path.
// It runs the Hashcat executable with the "--version" and "--quiet" flags and returns the output as a string.
//
// Parameters:
//   - hashcatPath: The file path to the Hashcat executable.
//
// Returns:
//   - A string representing the version of Hashcat.
//   - An error if the command execution fails or if Hashcat is not found.
func GetHashcatVersion(hashcatPath string) (string, error) {
	out, err := exec.Command(hashcatPath, "--version", "--quiet").Output()
	if err != nil {
		return "0.0.0", err
	}

	return strings.TrimSpace(string(out)), nil
}

// Extract7z extracts the contents of a 7z archive to the specified destination directory.
// It uses the `7z` command-line tool to perform the extraction.
//
// Parameters:
//   - srcFile: The path to the source 7z archive file.
//   - destDir: The path to the destination directory where the contents will be extracted.
//
// Returns:
//   - error: An error object if the extraction fails, otherwise nil.
func Extract7z(srcFile, destDir string) error {
	_, err := exec.Command("7z", "x", srcFile, "-o"+destDir).Output() //nolint:gosec // 7z command is safe here

	return err
}

// GetDefaultHashcatBinaryName returns the default binary name for Hashcat on Darwin (macOS) systems.
// This function is used to identify the standard executable name for Hashcat, which is "hashcat.bin".
func GetDefaultHashcatBinaryName() string {
	return "hashcat.bin"
}

// GetAdditionalHashcatArgs returns a slice of strings containing additional
// arguments to be passed to Hashcat. Specifically, it includes an argument
// to ignore OpenCL backend, which is useful for certain configurations
// where OpenCL is not desired or supported.
//
// Returns:
//
//	[]string: A slice containing the additional Hashcat arguments.
func GetAdditionalHashcatArgs() []string {
	return []string{"--backend-ignore-opencl"}
}
