package lib

import (
	"errors"
	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/pointer"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
	"net/http"
	"path"
)

// GetNewTask retrieves a new task from the server.
// It sends a request using SdkClient, handles any errors, and returns the task if available.
// If the server responds with no content, it means no new task is available, and the function returns nil without error.
// For any other unexpected response status, an error is returned.
func GetNewTask() (*components.Task, error) {
	response, err := SdkClient.Tasks.GetNewTask(Context)
	if err != nil {
		handleAPIError("Error getting new task", err, operations.SeverityCritical)

		return nil, err
	}

	switch response.StatusCode {
	case http.StatusNoContent:
		// No new task available
		return nil, nil
	case http.StatusOK:
		// New task available
		return response.Task, nil
	default:
		return nil, errors.New("bad response: " + response.RawResponse.Status)
	}
}

// GetAttackParameters retrieves the attack parameters for a given attackID via the SdkClient.
// Returns an Attack object if the API call is successful and the response status is OK.
func GetAttackParameters(attackID int64) (*components.Attack, error) {
	response, err := SdkClient.Attacks.GetAttack(Context, attackID)
	if err != nil {
		handleAPIError("Error getting attack parameters", err, operations.SeverityCritical)

		return nil, err
	}

	if response.StatusCode == http.StatusOK {
		return response.Attack, nil
	}

	return nil, errors.New("bad response: " + response.RawResponse.Status)
}

// createJobParams creates hashcat parameters from the given Task and Attack objects.
// The function initializes a hashcat.Params struct by extracting and converting fields
// from the Task and Attack objects. It includes path settings for various resources
// like hash files, word lists, rule lists, and restore files.
func createJobParams(task *components.Task, attack *components.Attack) hashcat.Params {
	return hashcat.Params{
		AttackMode:       pointer.UnwrapOr(attack.AttackModeHashcat),
		HashType:         pointer.UnwrapOr(attack.HashMode),
		HashFile:         path.Join(shared.State.HashlistPath, convertor.ToString(attack.GetHashListID())+".txt"),
		Mask:             pointer.UnwrapOr(attack.GetMask(), ""),
		MaskIncrement:    pointer.UnwrapOr(attack.GetIncrementMode(), false),
		MaskIncrementMin: attack.GetIncrementMinimum(),
		MaskIncrementMax: attack.GetIncrementMaximum(),
		MaskCustomCharsets: []string{
			pointer.UnwrapOr(attack.GetCustomCharset1(), ""),
			pointer.UnwrapOr(attack.GetCustomCharset2(), ""),
			pointer.UnwrapOr(attack.GetCustomCharset3(), ""),
			pointer.UnwrapOr(attack.GetCustomCharset4(), ""),
		},
		WordListFilename: resourceNameOrBlank(attack.WordList),
		RuleListFilename: resourceNameOrBlank(attack.RuleList),
		MaskListFilename: resourceNameOrBlank(attack.MaskList),
		AdditionalArgs:   arch.GetAdditionalHashcatArgs(),
		OptimizedKernels: *attack.Optimized,
		SlowCandidates:   *attack.SlowCandidateGenerators,
		Skip:             pointer.UnwrapOr(task.GetSkip(), 0),
		Limit:            pointer.UnwrapOr(task.GetLimit(), 0),
		BackendDevices:   Configuration.Config.BackendDevices,
		OpenCLDevices:    Configuration.Config.OpenCLDevices,
		RestoreFilePath:  path.Join(shared.State.RestoreFilePath, convertor.ToString(attack.GetID())+".restore"),
	}
}

// AcceptTask attempts to accept the given task identified by its ID.
// It logs an error and returns if the task is nil.
// If the task is successfully accepted, it logs a debug message indicating success.
// In case of an error during task acceptance, it handles the error and returns it.
func AcceptTask(task *components.Task) error {
	if task == nil {
		shared.Logger.Error("Task is nil")

		return errors.New("task is nil")
	}

	_, err := SdkClient.Tasks.SetTaskAccepted(Context, task.GetID())
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

	_, err := SdkClient.Tasks.SetTaskExhausted(Context, task.GetID())
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

	_, err := SdkClient.Tasks.SetTaskAbandoned(Context, task.GetID())
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
		return logAndSendError("Attack is nil", errors.New("attack is nil"), operations.SeverityCritical, task)
	}

	jobParams := createJobParams(task, attack)
	sess, err := hashcat.NewHashcatSession(convertor.ToString(attack.GetID()), jobParams)
	if err != nil {
		return logAndSendError("Failed to create attack session", err, operations.SeverityCritical, task)
	}

	runAttackTask(sess, task)
	displayRunTaskCompleted()

	return nil
}
