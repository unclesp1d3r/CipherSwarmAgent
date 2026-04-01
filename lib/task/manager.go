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
	"github.com/unclesp1d3r/cipherswarmagent/lib"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/apierrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/devices"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

// Manager orchestrates task lifecycle operations using injected API clients.
type Manager struct {
	tasksClient   api.TasksClient
	attacksClient api.AttacksClient
	DeviceConfig  devices.DeviceConfig
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
	// ErrTaskAcceptNotFound is returned when the server responds 404 to SetTaskAccepted.
	ErrTaskAcceptNotFound = errors.New("task not found during acceptance")
	// ErrTaskAcceptFailed is returned for non-404 SetTaskAccepted failures.
	ErrTaskAcceptFailed = errors.New("task acceptance failed")
)

// GetNewTask retrieves a new task from the server.
// If the server responds with HTTP 204 (no content), it returns (nil, ErrNoTaskAvailable).
// For any other unexpected response status, an error is returned.
func (m *Manager) GetNewTask(ctx context.Context) (*api.Task, error) {
	response, err := m.tasksClient.GetNewTask(ctx)
	if err != nil {
		handleAPIError(ctx, "Error getting new task", err)

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
		handleAPIError(ctx, "Error getting attack parameters", err)

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
		handleAcceptTaskError(ctx, err)

		if apierrors.IsNotFoundError(err) {
			return fmt.Errorf("%w: %w", ErrTaskAcceptNotFound, err)
		}

		return fmt.Errorf("%w: %w", ErrTaskAcceptFailed, err)
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
		handleTaskError(ctx, err, "Error notifying server of task exhaustion")
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
		handleTaskError(ctx, err, "Error notifying server of task abandonment")
	}
}

// RunTask performs a hashcat attack based on the provided task and attack objects.
// It initializes the task, creates job parameters, starts the hashcat session, and handles task completion or errors.
func (m *Manager) RunTask(ctx context.Context, task *api.Task, attack *api.Attack) error {
	display.RunTaskStarting(task)

	if attack == nil {
		return cserrors.LogAndSendError(ctx, "Attack is nil", errors.New("attack is nil"), api.SeverityCritical, task)
	}

	jobParams := m.createJobParams(task, attack)

	sess, err := hashcat.NewHashcatSession(ctx, strconv.FormatInt(attack.Id, 10), jobParams)
	if err != nil {
		if detail := hashFileErrorDetail(err); detail != "" {
			agentstate.ErrorLogger.Error("Hash file validation failed", "error", err)
			cserrors.SendAgentError(
				ctx, "Hash file validation failed", task, api.SeverityCritical,
				cserrors.WithClassification("file_access", false),
				cserrors.WithContext(map[string]any{
					"error_type":    "hash_file_validation",
					"detail":        detail,
					"error_message": err.Error(),
				}),
			)
		} else {
			return cserrors.LogAndSendError(ctx, "Failed to create attack session", err, api.SeverityCritical, task)
		}

		return err
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
		Mask:             lib.UnwrapOr(attack.Mask, ""),
		MaskIncrement:    attack.IncrementMode,
		MaskIncrementMin: int64(attack.IncrementMinimum),
		MaskIncrementMax: int64(attack.IncrementMaximum),
		MaskCustomCharsets: []string{
			lib.UnwrapOr(attack.CustomCharset1, ""),
			lib.UnwrapOr(attack.CustomCharset2, ""),
			lib.UnwrapOr(attack.CustomCharset3, ""),
			lib.UnwrapOr(attack.CustomCharset4, ""),
		},
		WordListFilename: resourceNameOrBlank(attack.WordList),
		RuleListFilename: resourceNameOrBlank(attack.RuleList),
		MaskListFilename: resourceNameOrBlank(attack.MaskList),
		AdditionalArgs:   arch.GetAdditionalHashcatArgs(),
		OptimizedKernels: attack.Optimized,
		SlowCandidates:   attack.SlowCandidateGenerators,
		Skip:             lib.UnwrapOr(task.Skip, 0),
		Limit:            lib.UnwrapOr(task.Limit, 0),
		BackendDevices:   m.DeviceConfig.ResolvedBackendDevices(),
		OpenCLDevices:    m.DeviceConfig.ResolvedOpenCLDevices(),
		RestoreFilePath: filepath.Join(
			agentstate.State.RestoreFilePath,
			strconv.FormatInt(attack.Id, 10)+".restore",
		),
	}
}

func resourceNameOrBlank(resource *api.AttackResourceFile) string {
	if resource == nil {
		return ""
	}

	return resource.FileName
}

// hashFileErrorDetail returns a short detail string for hash file validation errors,
// or empty string if the error is not a hash file validation error.
func hashFileErrorDetail(err error) string {
	switch {
	case errors.Is(err, hashcat.ErrHashFileNotReadable):
		return "not_readable"
	case errors.Is(err, hashcat.ErrHashFileEmpty):
		return "empty"
	case errors.Is(err, hashcat.ErrHashFileWhitespaceOnly):
		return "whitespace_only"
	default:
		return ""
	}
}
