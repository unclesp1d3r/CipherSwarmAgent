//go:build darwin

package arch

import (
	"os/exec"
	"regexp"

	"github.com/duke-git/lancet/v2/strutil"
)

// GetDevices retrieves a list of devices using the system_profiler command.
// It executes the "system_profiler SPDisplaysDataType -detaillevel mini" command
// and parses the output to extract the Chipset Model information.
// The function returns a slice of strings containing the Chipset Model of each device found.
// If an error occurs during the execution of the command, an empty slice and the error are returned.
//
//goland:noinspection SpellCheckingInspection
func GetDevices() ([]string, error) {
	out, err := exec.Command("system_profiler", "SPDisplaysDataType", "-detaillevel", "mini").Output()
	if err != nil {
		return []string{}, err
	}

	commandResult := string(out)
	re := regexp.MustCompile(`Chipset Model: (.*)`)
	matches := re.FindAllStringSubmatch(commandResult, -1)

	var newArray []string //nolint:prealloc
	for _, match := range matches {
		newArray = append(newArray, strutil.Trim(match[1]))
	}

	return newArray, nil
}

// GetHashcatVersion returns the version of Hashcat installed at the specified path.
// It executes the Hashcat command with the "--version" and "--quiet" flags and captures the output.
// The version string is trimmed and returned along with any error that occurred during the execution.
func GetHashcatVersion(hashcatPath string) (string, error) {
	out, err := exec.Command(hashcatPath, "--version", "--quiet").Output()
	if err != nil {
		return "0.0.0", err
	}

	return strutil.Trim(strutil.BytesToString(out)), nil
}

// Extract7z extracts the contents of a 7z archive file to the specified destination directory.
// It uses the "7z" command-line tool to perform the extraction.
// srcFile is the path to the 7z archive file.
// destDir is the destination directory where the contents will be extracted.
// Returns an error if the extraction fails.
//
//goland:noinspection GoLinter
func Extract7z(srcFile string, destDir string) error {
	_, err := exec.Command("7z", "x", srcFile, "-o"+destDir).Output() //nolint:gosec

	return err
}

// GetDefaultHashcatBinaryName returns the default name of the Hashcat binary for the Darwin (macOS) platform.
func GetDefaultHashcatBinaryName() string {
	return "hashcat.bin"
}

// GetAdditionalHashcatArgs returns additional arguments to be passed to Hashcat.
// In this case, it returns ["--backend-ignore-opencl"] to ignore OpenCL backend.
func GetAdditionalHashcatArgs() []string {
	return []string{"--backend-ignore-opencl"}
}
