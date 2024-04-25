//go:build linux

package arch

import (
	"os/exec"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

//goland:noinspection SpellCheckingInspection
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

func GetHashcatVersion(hashcatPath string) (string, error) {
	out, err := exec.Command(hashcatPath, "--version", "--quiet").Output()
	if err != nil {
		return "0.0.0", err
	}
	return strings.TrimSpace(string(out)), nil
}

func GetPlatform() string {
	return "linux"
}

func Extract7z(srcFile string, destDir string) error {
	_, err := exec.Command("7z", "x", srcFile, "-o"+destDir).Output()
	return err
}

func GetDefaultHashcatBinaryName() string {
	return "hashcat.bin"
}

func GetAdditionalHashcatArgs() []string {
	return []string{}
}
