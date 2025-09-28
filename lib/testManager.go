package lib

import (
	"context"
	"encoding/json"
	"strings"

	pkg_errors "github.com/pkg/errors"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// getDevices initializes a test Hashcat session and runs a test task, returning the names of available OpenCL devices.
// An error is logged and returned if the session creation or test task execution fails.
func getDevices() ([]string, error) {
	jobParams := hashcat.Params{
		AttackMode:     hashcat.AttackModeMask,
		AdditionalArgs: arch.GetAdditionalHashcatArgs(),
		HashFile:       "60b725f10c9c85c70d97880dfe8191b3", // "a"
		Mask:           "?l",
		OpenCLDevices:  "1,2,3",
	}

	sess, err := hashcat.NewHashcatSession(context.Background(), "test", jobParams)
	if err != nil {
		return nil, cserrors.LogAndSendError("Failed to create test session", err, operations.SeverityMajor, nil)
	}

	testStatus, err := runTestTask(sess)
	if err != nil {
		return nil, cserrors.LogAndSendError("Error running test task", err, operations.SeverityFatal, nil)
	}

	return extractDeviceNames(testStatus.Devices), nil
}

// extractDeviceNames extracts the device names from a slice of hashcat.StatusDevice and returns them as a slice of strings.
func extractDeviceNames(deviceStatuses []hashcat.StatusDevice) []string {
	devices := make([]string, len(deviceStatuses))
	for i, device := range deviceStatuses {
		devices[i] = device.DeviceName
	}

	return devices
}

// runTestTask runs a hashcat test session, handles various output channels, and returns the session status or an error.
func runTestTask(sess *hashcat.Session) (*hashcat.Status, error) {
	err := sess.Start()
	if err != nil {
		shared.Logger.Error("Failed to start hashcat startup test session", "error", err)
		SendAgentError(err.Error(), nil, operations.SeverityFatal)

		return nil, err
	}

	var (
		testResults *hashcat.Status
		errorResult error
	)

	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)

		for {
			select {
			case stdoutLine := <-sess.StdoutLines:
				handleTestStdOutLine(stdoutLine)
			case stdErrLine := <-sess.StderrMessages:
				if err := handleTestStdErrLine(stdErrLine); err != nil {
					errorResult = err
				}
			case statusUpdate := <-sess.StatusUpdates:
				testResults = &statusUpdate
			case crackedHash := <-sess.CrackedHashes:
				if err := handleTestCrackedHash(crackedHash); err != nil {
					errorResult = err
				}
			case err := <-sess.DoneChan:
				if err := handleTestDoneChan(err); err != nil {
					errorResult = err
				}

				sess.Cleanup()

				return
			}
		}
	}()

	<-waitChan

	return testResults, errorResult
}

// handleTestStdOutLine processes a line of standard output from a test, logging an error if the line isn't valid JSON.
func handleTestStdOutLine(stdoutLine string) {
	if !json.Valid([]byte(stdoutLine)) {
		shared.Logger.Error("Failed to parse status update", "output", stdoutLine)
	}
}

// handleTestStdErrLine sends the specified stderr line to the central server and returns an error if the line is not empty.
func handleTestStdErrLine(stdErrLine string) error {
	if strings.TrimSpace(stdErrLine) != "" {
		SendAgentError(stdErrLine, nil, operations.SeverityMinor)
		return pkg_errors.New(stdErrLine)
	}

	return nil
}

// handleTestCrackedHash processes a cracked hash result from hashcat and returns an error if the plaintext is blank.
func handleTestCrackedHash(crackedHash hashcat.Result) error {
	if strings.TrimSpace(crackedHash.Plaintext) == "" {
		return pkg_errors.New("received empty cracked hash")
	}

	return nil
}

// handleTestDoneChan handles errors from the test session's done channel, sends them to central server if not exit status 1.
func handleTestDoneChan(err error) error {
	if err != nil && err.Error() != "exit status 1" {
		SendAgentError(err.Error(), nil, operations.SeverityCritical)
		return err
	}

	return nil
}
