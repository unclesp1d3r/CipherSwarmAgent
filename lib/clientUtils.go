package lib

import (
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/unclesp1d3r/cipherswarmagent/shared"

	"github.com/charmbracelet/log"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
)

var (
	AppFs  = afero.NewOsFs()
	Logger = log.NewWithOptions(os.Stderr, log.Options{
		Prefix:          "cipherswarm-agent",
		Level:           log.InfoLevel,
		ReportTimestamp: true,
		ReportCaller:    true,
	})
)

// GetCurrentHashcatVersion retrieves the current version of Hashcat.
// It checks if the Hashcat directory exists and then uses the arch.GetHashcatVersion
// function to get the version from the specified path.
// If the Hashcat directory does not exist, it returns "0.0.0" and an error.
// If there is an error retrieving the version, it also returns "0.0.0" and the error.
// Otherwise, it returns the Hashcat version and no error.
func GetCurrentHashcatVersion() (string, error) {
	afs := &afero.Afero{Fs: AppFs}

	// Check where the hashcat binary should be
	hashcatExists, _ := afs.Exists(viper.GetString("hashcat_path"))
	if !hashcatExists {
		Logger.Error("Cannot find hashcat binary, checking fallback location.", "path", viper.GetString("hashcat_path"))

		// Check if the hashcat binary exists in the crackers directory
		fallbackPath := path.Join(
			shared.SharedState.CrackersPath,
			"hashcat",
			arch.GetDefaultHashcatBinaryName(),
		)
		hashcatExists, _ = afs.Exists(fallbackPath)
		if hashcatExists {
			Logger.Debug("Using hashcat binary from crackers directory", "path", fallbackPath)
			viper.Set("hashcat_path", fallbackPath)
		} else {
			Logger.Error("Hashcat binary does not exist", "path", fallbackPath)
		}
	}
	if !hashcatExists {
		Logger.Error("Hashcat binary does not exist", "path", viper.GetString("hashcat_path"))
		return "0.0.0", errors.New("hashcat binary does not exist")
	}

	// Found the hashcat binary, get the version
	hashcatVersion, err := arch.GetHashcatVersion(viper.GetString("hashcat_path"))
	if err != nil {
		return "0.0.0", err
	}
	Logger.Debug("Current hashcat version", "version", hashcatVersion)
	return hashcatVersion, nil
}

// GetPlatform returns the platform of the current system.
func GetPlatform() string {
	return arch.GetPlatform()
}

// CheckForExistingClient checks if the specified PID file exists.
// It returns true if the file exists, and false otherwise.
func CheckForExistingClient(pidFilePath string) bool {
	pidExists, err := afero.Exists(AppFs, pidFilePath)
	if err != nil {
		return false
	}

	return pidExists
}

// CreateLockFile creates a lock file at the specified path using the configured PID file path.
// It returns the created file and any error encountered during the process.
func CreateLockFile() (afero.File, error) {
	lockFilePath := shared.SharedState.PidFile
	currentPid := os.Getpid()

	pidFile, err := AppFs.Create(lockFilePath)
	if err != nil {
		Logger.Fatal("Failed to create PID file", "error", lockFilePath)
	}
	defer func(pidFile afero.File) {
		err := pidFile.Close()
		if err != nil {
			Logger.Fatal("Failed to close PID file", "error", err)
		}
	}(pidFile)
	_, err = pidFile.WriteString(strconv.Itoa(currentPid))
	Logger.Debug("PID file created", "path", lockFilePath, "pid", currentPid)
	return pidFile, err
}

// CleanString removes any non-printable characters from the input string.
// It uses the strings.Map function to iterate over each rune in the string
// and checks if it is printable using the unicode.IsPrint function.
// If a rune is printable, it is returned as is, otherwise it is replaced with -1.
// The resulting string with only printable characters is returned.
func CleanString(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}

// CreateDataDirs creates the necessary data directories for the CipherSwarmAgent.
// It checks if the directories already exist, and if not, it creates them.
// Returns an error if there was a problem creating the directories.
func CreateDataDirs() error {
	dataDirs := []string{
		shared.SharedState.FilePath,
		shared.SharedState.CrackersPath,
		shared.SharedState.HashlistPath,
		shared.SharedState.ZapsPath,
		shared.SharedState.PreprocessorsPath,
		shared.SharedState.ToolsPath,
		shared.SharedState.OutPath,
	}
	for _, dir := range dataDirs {
		if dir == "" {
			Logger.Error("Data directory not set")
		}

		if _, err := AppFs.Stat(dir); os.IsNotExist(err) {
			err := AppFs.MkdirAll(dir, 0o755)
			if err != nil {
				return err
			}
			Logger.Info("Created directory", "path", dir)
		}
	}
	return nil
}
