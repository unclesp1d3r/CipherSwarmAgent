// Package task provides task management and execution logic for the CipherSwarm agent.
// It handles the full task lifecycle: retrieval, acceptance, execution, status reporting,
// and error handling.
package task

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// Manager orchestrates task lifecycle operations using injected API clients.
type Manager struct {
	tasksClient    api.TasksClient
	attacksClient  api.AttacksClient
	BackendDevices string
	OpenCLDevices  string
}

// NewManager creates a new task Manager with the given API clients.
func NewManager(tc api.TasksClient, ac api.AttacksClient) *Manager {
	return &Manager{
		tasksClient:   tc,
		attacksClient: ac,
	}
}

var (
	// ErrTaskBadResponse is returned when the server returns a bad response.
	ErrTaskBadResponse = errors.New("bad response")
	// ErrTaskIsNil is returned when a task parameter is nil.
	ErrTaskIsNil = errors.New("task is nil")
	// ErrNoTaskAvailable is returned when no task is available from the server.
	ErrNoTaskAvailable = errors.New("no task available")
)

// GetNewTask retrieves a new task from the server.
// If the server responds with no content, it means no new task is available, and the function returns nil without error.
// For any other unexpected response status, an error is returned.
func (m *Manager) GetNewTask(ctx context.Context) (*api.Task, error) {
	response, err := m.tasksClient.GetNewTask(ctx)
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
func (m *Manager) GetAttackParameters(ctx context.Context, attackID int64) (*api.Attack, error) {
	response, err := m.attacksClient.GetAttack(ctx, attackID)
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

// AcceptTask attempts to accept the given task identified by its ID.
// It logs an error and returns if the task is nil.
func (m *Manager) AcceptTask(ctx context.Context, task *api.Task) error {
	if task == nil {
		agentstate.Logger.Error("Task is nil")

		return ErrTaskIsNil
	}

	_, err := m.tasksClient.SetTaskAccepted(ctx, task.Id)
	if err != nil {
		handleAcceptTaskError(err)

		return err
	}

	agentstate.Logger.Debug("Task accepted")

	return nil
}

// markTaskExhausted marks the given task as exhausted by notifying the server.
// Logs an error if the task is nil or if notifying the server fails.
func (m *Manager) markTaskExhausted(ctx context.Context, task *api.Task) {
	if task == nil {
		agentstate.Logger.Error("Task is nil")

		return
	}

	_, err := m.tasksClient.SetTaskExhausted(ctx, task.Id)
	if err != nil {
		handleTaskError(err, "Error notifying server of task exhaustion")
	}
}

// AbandonTask sets the given task to an abandoned state and logs any errors that occur.
// If the task is nil, it logs an error and returns immediately.
func (m *Manager) AbandonTask(ctx context.Context, task *api.Task) {
	if task == nil {
		agentstate.Logger.Error("Task is nil")

		return
	}

	_, err := m.tasksClient.SetTaskAbandoned(ctx, task.Id)
	if err != nil {
		handleTaskError(err, "Error notifying server of task abandonment")
	}
}

// RunTask performs a hashcat attack based on the provided task and attack objects.
// It initializes the task, creates job parameters, starts the hashcat session, and handles task completion or errors.
func (m *Manager) RunTask(ctx context.Context, task *api.Task, attack *api.Attack) error {
	display.RunTaskStarting(task)

	if attack == nil {
		return cserrors.LogAndSendError("Attack is nil", errors.New("attack is nil"), api.SeverityCritical, task)
	}

	jobParams := m.createJobParams(task, attack)

	sess, err := hashcat.NewHashcatSession(strconv.FormatInt(attack.Id, 10), jobParams)
	if err != nil {
		return cserrors.LogAndSendError("Failed to create attack session", err, api.SeverityCritical, task)
	}

	m.runAttackTask(ctx, sess, task)
	display.RunTaskCompleted()

	return nil
}

// createJobParams creates hashcat parameters from the given Task and Attack objects.
func (m *Manager) createJobParams(task *api.Task, attack *api.Attack) hashcat.Params {
	return hashcat.Params{
		AttackMode: int64(attack.AttackModeHashcat),
		HashType:   int64(attack.HashMode),
		HashFile: filepath.Join(
			agentstate.State.HashlistPath,
			strconv.FormatInt(attack.Id, 10)+".hsh",
		),
		Mask:             unwrapOr(attack.Mask, ""),
		MaskIncrement:    attack.IncrementMode,
		MaskIncrementMin: int64(attack.IncrementMinimum),
		MaskIncrementMax: int64(attack.IncrementMaximum),
		MaskCustomCharsets: []string{
			unwrapOr(attack.CustomCharset1, ""),
			unwrapOr(attack.CustomCharset2, ""),
			unwrapOr(attack.CustomCharset3, ""),
			unwrapOr(attack.CustomCharset4, ""),
		},
		WordListFilename: resourceNameOrBlank(attack.WordList),
		RuleListFilename: resourceNameOrBlank(attack.RuleList),
		MaskListFilename: resourceNameOrBlank(attack.MaskList),
		AdditionalArgs:   arch.GetAdditionalHashcatArgs(),
		OptimizedKernels: attack.Optimized,
		SlowCandidates:   attack.SlowCandidateGenerators,
		Skip:             unwrapOr(task.Skip, 0),
		Limit:            unwrapOr(task.Limit, 0),
		BackendDevices:   m.BackendDevices,
		OpenCLDevices:    m.OpenCLDevices,
		RestoreFilePath:  filepath.Join(agentstate.State.RestoreFilePath, strconv.FormatInt(attack.Id, 10)+".restore"),
	}
}

func resourceNameOrBlank(resource *api.AttackResourceFile) string {
	if resource == nil {
		return ""
	}

	return resource.FileName
}

// unwrapOr returns the dereferenced pointer value, or the given default if the pointer is nil.
func unwrapOr[T any](ptr *T, defaultVal T) T {
	if ptr != nil {
		return *ptr
	}

	return defaultVal
}
