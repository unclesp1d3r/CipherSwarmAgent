package lib

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
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
// It sends a request using the API client interface, handles any errors, and returns the task if available.
// If the server responds with no content, it means no new task is available, and the function returns nil without error.
// For any other unexpected response status, an error is returned.
func GetNewTask() (*api.Task, error) {
	response, err := agentstate.State.APIClient.Tasks().GetNewTask(context.Background())
	if err != nil {
		handleAPIError("Error getting new task", err)

		return nil, err
	}

	switch response.StatusCode() {
	case http.StatusNoContent:
		// No new task available
		return nil, ErrNoTaskAvailable
	case http.StatusOK:
		if response.JSON200 == nil {
			agentstate.Logger.Warn("Server returned HTTP 200 but task body was empty or unparseable")

			return nil, fmt.Errorf("%w: HTTP 200 with nil task body", ErrTaskBadResponse)
		}

		return response.JSON200, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrTaskBadResponse, response.Status())
	}
}

// GetAttackParameters retrieves the attack parameters for a given attackID via the API client interface.
// Returns an Attack object if the API call is successful and the response status is OK.
func GetAttackParameters(attackID int64) (*api.Attack, error) {
	response, err := agentstate.State.APIClient.Attacks().GetAttack(context.Background(), attackID)
	if err != nil {
		handleAPIError("Error getting attack parameters", err)

		return nil, err
	}

	if response.StatusCode() == http.StatusOK {
		if response.JSON200 == nil {
			agentstate.Logger.Warn("Server returned HTTP 200 but attack body was empty or unparseable",
				"attack_id", attackID)

			return nil, fmt.Errorf("%w: HTTP 200 with nil attack body for attack_id %d", ErrTaskBadResponse, attackID)
		}

		return response.JSON200, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrTaskBadResponse, response.Status())
}

// createJobParams creates hashcat parameters from the given Task and Attack objects.
// The function initializes a hashcat.Params struct by extracting and converting fields
// from the Task and Attack objects. It includes path settings for various resources
// like hash files, word lists, rule lists, and restore files.
func createJobParams(task *api.Task, attack *api.Attack) hashcat.Params {
	unwrapOr := func(val *int64) int64 {
		if val == nil {
			return 0
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
		AttackMode: int64(attack.AttackModeHashcat),
		HashType:   int64(attack.HashMode),
		HashFile: path.Join(
			agentstate.State.HashlistPath,
			strconv.FormatInt(attack.HashListId, 10)+".txt",
		),
		Mask:             unwrapOrString(attack.Mask),
		MaskIncrement:    attack.IncrementMode,
		MaskIncrementMin: int64(attack.IncrementMinimum),
		MaskIncrementMax: int64(attack.IncrementMaximum),
		MaskCustomCharsets: []string{
			unwrapOrString(attack.CustomCharset1),
			unwrapOrString(attack.CustomCharset2),
			unwrapOrString(attack.CustomCharset3),
			unwrapOrString(attack.CustomCharset4),
		},
		WordListFilename: resourceNameOrBlank(attack.WordList),
		RuleListFilename: resourceNameOrBlank(attack.RuleList),
		MaskListFilename: resourceNameOrBlank(attack.MaskList),
		AdditionalArgs:   arch.GetAdditionalHashcatArgs(),
		OptimizedKernels: attack.Optimized,
		SlowCandidates:   attack.SlowCandidateGenerators,
		Skip:             unwrapOr(task.Skip),
		Limit:            unwrapOr(task.Limit),
		BackendDevices:   Configuration.Config.BackendDevices,
		OpenCLDevices:    Configuration.Config.OpenCLDevices,
		RestoreFilePath:  path.Join(agentstate.State.RestoreFilePath, strconv.FormatInt(attack.Id, 10)+".restore"),
	}
}

func resourceNameOrBlank(resource *api.AttackResourceFile) string {
	if resource == nil {
		return ""
	}

	return resource.FileName
}

// AcceptTask attempts to accept the given task identified by its ID.
// It logs an error and returns if the task is nil.
// If the task is successfully accepted, it logs a debug message indicating success.
// In case of an error during task acceptance, it handles the error and returns it.
func AcceptTask(task *api.Task) error {
	if task == nil {
		agentstate.Logger.Error("Task is nil")

		return ErrTaskIsNil
	}

	_, err := agentstate.State.APIClient.Tasks().SetTaskAccepted(context.Background(), task.Id)
	if err != nil {
		handleAcceptTaskError(err)

		return err
	}

	agentstate.Logger.Debug("Task accepted")

	return nil
}

// markTaskExhausted marks the given task as exhausted by notifying the server.
// Logs an error if the task is nil or if notifying the server fails.
func markTaskExhausted(task *api.Task) {
	if task == nil {
		agentstate.Logger.Error("Task is nil")

		return
	}

	_, err := agentstate.State.APIClient.Tasks().SetTaskExhausted(context.Background(), task.Id)
	if err != nil {
		handleTaskError(err, "Error notifying server of task exhaustion")
	}
}

// AbandonTask sets the given task to an abandoned state using the API client interface and logs any errors that occur.
// If the task is nil, it logs an error and returns immediately.
func AbandonTask(task *api.Task) {
	if task == nil {
		agentstate.Logger.Error("Task is nil")

		return
	}

	_, err := agentstate.State.APIClient.Tasks().SetTaskAbandoned(context.Background(), task.Id)
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
func RunTask(task *api.Task, attack *api.Attack) error {
	displayRunTaskStarting(task)

	if attack == nil {
		return cserrors.LogAndSendError("Attack is nil", nil, api.SeverityCritical, task)
	}

	jobParams := createJobParams(task, attack)

	sess, err := hashcat.NewHashcatSession(strconv.FormatInt(attack.Id, 10), jobParams)
	if err != nil {
		return cserrors.LogAndSendError("Failed to create attack session", err, api.SeverityCritical, task)
	}

	runAttackTask(sess, task)
	displayRunTaskCompleted()

	return nil
}
