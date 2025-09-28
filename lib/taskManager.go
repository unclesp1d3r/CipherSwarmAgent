package lib

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

var (
	// ErrTaskBadResponse is returned when the server returns a bad response.
	ErrTaskBadResponse = errors.New("bad response")
	// ErrTaskIsNil is returned when a task parameter is nil.
	ErrTaskIsNil = errors.New("task is nil")
	// ErrNoTaskAvailable is returned when no task is available from the server.
	ErrNoTaskAvailable = errors.New("no task available")
)

// GetNewTask retrieves a new task from the server.
// It sends a request using SdkClient, handles any errors, and returns the task if available.
// If the server responds with no content, it means no new task is available, and the function returns nil without error.
// For any other unexpected response status, an error is returned.
func GetNewTask() (*components.Task, error) {
	response, err := shared.State.SdkClient.Tasks.GetNewTask(context.Background())
	if err != nil {
		handleAPIError("Error getting new task", err)

		return nil, err
	}

	switch response.StatusCode {
	case http.StatusNoContent:
		// No new task available
		return nil, ErrNoTaskAvailable
	case http.StatusOK:
		// New task available
		return response.Task, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrTaskBadResponse, response.RawResponse.Status)
	}
}

// GetAttackParameters retrieves the attack parameters for a given attackID via the SdkClient.
// Returns an Attack object if the API call is successful and the response status is OK.
func GetAttackParameters(attackID int64) (*components.Attack, error) {
	response, err := shared.State.SdkClient.Attacks.GetAttack(context.Background(), attackID)
	if err != nil {
		handleAPIError("Error getting attack parameters", err)

		return nil, err
	}

	if response.StatusCode == http.StatusOK {
		return response.Attack, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrTaskBadResponse, response.RawResponse.Status)
}

// createJobParams creates hashcat parameters from the given Task and Attack objects.
// The function initializes a hashcat.Params struct by extracting and converting fields
// from the Task and Attack objects. It includes path settings for various resources
// like hash files, word lists, rule lists, and restore files.
func createJobParams(task *components.Task, attack *components.Attack) hashcat.Params {
	unwrapOr := func(val *int64) int64 {
		if val == nil {
			return 0
		}

		return *val
	}

	unwrapOrBool := func(val *bool, def bool) bool {
		if val == nil {
			return def
		}

		return *val
	}

	unwrapOrString := func(val *string) string {
		if val == nil {
			return ""
		}

		return *val
	}

	return hashcat.Params{
		AttackMode:       unwrapOr(attack.AttackModeHashcat),
		HashType:         unwrapOr(attack.HashMode),
		HashFile:         path.Join(shared.State.HashlistPath, strconv.FormatInt(attack.GetHashListID(), 10)+".txt"),
		Mask:             unwrapOrString(attack.GetMask()),
		MaskIncrement:    unwrapOrBool(attack.GetIncrementMode(), false),
		MaskIncrementMin: attack.GetIncrementMinimum(),
		MaskIncrementMax: attack.GetIncrementMaximum(),
		MaskCustomCharsets: []string{
			unwrapOrString(attack.GetCustomCharset1()),
			unwrapOrString(attack.GetCustomCharset2()),
			unwrapOrString(attack.GetCustomCharset3()),
			unwrapOrString(attack.GetCustomCharset4()),
		},
		WordListFilename: resourceNameOrBlank(attack.WordList),
		RuleListFilename: resourceNameOrBlank(attack.RuleList),
		MaskListFilename: resourceNameOrBlank(attack.MaskList),
		AdditionalArgs:   arch.GetAdditionalHashcatArgs(),
		OptimizedKernels: *attack.Optimized,
		SlowCandidates:   *attack.SlowCandidateGenerators,
		Skip:             unwrapOr(task.GetSkip()),
		Limit:            unwrapOr(task.GetLimit()),
		BackendDevices:   Configuration.Config.BackendDevices,
		OpenCLDevices:    Configuration.Config.OpenCLDevices,
		RestoreFilePath:  path.Join(shared.State.RestoreFilePath, strconv.FormatInt(attack.GetID(), 10)+".restore"),
	}
}

func resourceNameOrBlank(resource *components.AttackResourceFile) string {
	if resource == nil {
		return ""
	}

	return resource.FileName
}

// AcceptTask attempts to accept the given task identified by its ID.
// It logs an error and returns if the task is nil.
// If the task is successfully accepted, it logs a debug message indicating success.
// In case of an error during task acceptance, it handles the error and returns it.
func AcceptTask(task *components.Task) error {
	if task == nil {
		shared.Logger.Error("Task is nil")

		return ErrTaskIsNil
	}

	_, err := shared.State.SdkClient.Tasks.SetTaskAccepted(context.Background(), task.GetID())
	if err != nil {
		handleAcceptTaskError(err)

		return err
	}

	shared.Logger.Debug("Task accepted")

	return nil
}

// markTaskExhausted marks the given task as exhausted by notifying the server.
// Logs an error if the task is nil or if notifying the server fails.
func markTaskExhausted(task *components.Task) {
	if task == nil {
		shared.Logger.Error("Task is nil")

		return
	}

	_, err := shared.State.SdkClient.Tasks.SetTaskExhausted(context.Background(), task.GetID())
	if err != nil {
		handleTaskError(err, "Error notifying server of task exhaustion")
	}
}

// AbandonTask sets the given task to an abandoned state using the SdkClient and logs any errors that occur.
// If the task is nil, it logs an error and returns immediately.
func AbandonTask(task *components.Task) {
	if task == nil {
		shared.Logger.Error("Task is nil")

		return
	}

	_, err := shared.State.SdkClient.Tasks.SetTaskAbandoned(context.Background(), task.GetID())
	if err != nil {
		handleTaskError(err, "Error notifying server of task abandonment")
	}
}

// RunTask performs a hashcat attack based on the provided task and attack objects.
// It initializes the task, creates job parameters, starts the hashcat session, and handles task completion or errors.
// Parameters:
//   - task: Pointer to the Task object to be run.
//   - attack: Pointer to the Attack object describing the specifics of the attack.
//
// Returns an error if the task could not be run or if the attack session could not be started.
func RunTask(task *components.Task, attack *components.Attack) error {
	displayRunTaskStarting(task)

	if attack == nil {
		return cserrors.LogAndSendError("Attack is nil", nil, operations.SeverityCritical, task)
	}

	jobParams := createJobParams(task, attack)

	sess, err := hashcat.NewHashcatSession(context.Background(), strconv.FormatInt(attack.GetID(), 10), jobParams)
	if err != nil {
		return cserrors.LogAndSendError("Failed to create attack session", err, operations.SeverityCritical, task)
	}

	runAttackTask(sess, task)
	displayRunTaskCompleted()

	return nil
}
