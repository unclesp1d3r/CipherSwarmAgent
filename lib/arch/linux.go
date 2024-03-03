//go:build linux

package arch

import (
	log "github.com/sirupsen/logrus"

	"os/exec"
	"regexp"
	"strings"
)

func GetDevices() ([]string, error) {
	log.Debugln("Getting GPU devices")
	out, err := exec.Command("lspci").Output()
	if err != nil {
		log.Errorf("Error getting GPU devices: %v", err)
		return []string{}, err
	}

	commandResult := string(out)
	// TODO: Implement the correct regular expression for Linux. Needs to be tested.
	re := regexp.MustCompile(`VGA compatible controller: (.*)`)
	matches := re.FindAllStringSubmatch(commandResult, -1)

	var newArray []string
	for _, match := range matches {
		newArray = append(newArray, strings.TrimSpace(match[1]))
	}

	return newArray, nil
}
