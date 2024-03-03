//go:build darwin

package arch

import (
	log "github.com/sirupsen/logrus"
	"os/exec"
	"regexp"
	"strings"
)

func GetDevices() ([]string, error) {
	log.Debugln("Getting GPU devices")
	out, err := exec.Command("system_profiler", "SPDisplaysDataType", "-detaillevel", "mini").Output()
	if err != nil {
		log.Errorf("Error getting GPU devices: %v", err)
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
