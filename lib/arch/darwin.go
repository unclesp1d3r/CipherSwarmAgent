//go:build darwin

package arch

import (
	"os/exec"
	"regexp"
	"strings"
)

func GetDevices() ([]string, error) {
	out, err := exec.Command("system_profiler", "SPDisplaysDataType", "-detaillevel", "mini").Output()
	if err != nil {
		return []string{}, err
	}

	commandResult := string(out)
	re := regexp.MustCompile(`Chipset Model: (.*)`)
	matches := re.FindAllStringSubmatch(commandResult, -1)

	var newArray []string
	for _, match := range matches {
		newArray = append(newArray, strings.TrimSpace(match[1]))
	}

	return newArray, nil
}

func GetHashcatVersion(hashcatPath string) (string, error) {
	out, err := exec.Command(hashcatPath, "--version", "--quiet").Output()
	if err != nil {
		return "0.0.0", err
	}
	return strings.TrimSpace(string(out)), nil
}

func GetPlatform() string {
	return "darwin"
}

func Extract7z(srcFile string, destDir string) error {
	_, err := exec.Command("7z", "x", srcFile, "-o"+destDir).Output()
	return err
}

func GetDefaultHashcatBinaryName() string {
	return "hashcat.bin"
}

func GetAdditionalHashcatArgs() []string {
	return []string{"--backend-ignore-opencl"}
}
