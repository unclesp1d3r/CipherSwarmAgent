// Package cserrors provides error handling and logging utilities for CipherSwarm.
package cserrors

import (
	"context"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// LogAndSendError logs an error message with severity and sends it to the CipherSwarm API.
// When task is nil, the error is reported without a task context. API submission is
// skipped only when the APIClient has not been initialized yet.
// Returns the original error for further handling.
func LogAndSendError(message string, err error, severity api.Severity, task *api.Task) error {
	agentstate.ErrorLogger.Error(message, "error", err)

	// Send to API when client is initialized. TaskId is a pointer, so nil task
	// results in a nil TaskId — the server accepts errors without a task context.
	if agentstate.State.APIClient != nil {
		var taskID *int64
		if task != nil {
			taskID = &task.Id
		}

		agentError := api.SubmitErrorAgentJSONRequestBody(api.SubmitErrorAgentJSONBody{
			AgentId:  agentstate.State.AgentID,
			Message:  message,
			Severity: severity,
			TaskId:   taskID,
			Metadata: &struct {
				ErrorDate time.Time       `json:"error_date"`
				Other     *map[string]any `json:"other"`
			}{
				ErrorDate: time.Now(),
			},
		})

		_, apiErr := agentstate.State.APIClient.Agents().SubmitErrorAgent(
			context.Background(),
			agentstate.State.AgentID,
			agentError,
		)
		if apiErr != nil {
			agentstate.Logger.Error("Error sending error to server", "error", apiErr)
		}
	}

	return err
}
