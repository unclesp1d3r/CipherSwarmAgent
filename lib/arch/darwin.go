//go:build darwin

package arch

import (
	"os/exec"
	"path"
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
	execPath := path.Join(hashcatPath, "hashcat")
	out, err := exec.Command(execPath, "--version").Output()
	if err != nil {
		return "0.0.0", err
	}
	return strings.TrimSpace(string(out)), nil
}

func GetPlatform() string {
	return "darwin"
}
