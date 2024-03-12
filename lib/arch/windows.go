//go:build windows

package arch

import log "github.com/sirupsen/logrus"

import (
	"os/exec"
	"regexp"
	"strings"
)

func GetDevices() ([]string, error) {
	// TODO: Implement GetDevices for Windows. Or maybe not. Not sure if we should support Windows.
	log.Debugln("Getting GPU devices")
	out, err := exec.Command("wmic path win32_VideoController get name").Output()
	if err != nil {
		log.Errorf("Error getting GPU devices: %v", err)
		return []string{}, err
	}

	commandResult := string(out)
	// TODO: Implement the correct regular expression for Windows. Needs to be tested.
	re := regexp.MustCompile(`Name: (.*)`)
	matches := re.FindAllStringSubmatch(commandResult, -1)

	var newArray []string
	for _, match := range matches {
		newArray = append(newArray, strings.TrimSpace(match[1]))
	}

	return newArray, nil
}
func GetDefaultHashcatBinaryName() string {
	return "hashcat.exe"
}
