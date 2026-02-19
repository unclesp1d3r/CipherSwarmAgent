// Package cserrors provides error handling and logging utilities for CipherSwarm.
package cserrors

import (
	"context"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// LogAndSendError logs an error message with severity and optionally sends it to the CipherSwarm API.
// It constructs an AgentError object and sends it to the API if a task is provided and APIClient is initialized.
// Returns the original error for further handling.
func LogAndSendError(message string, err error, severity api.Severity, task *api.Task) error {
	agentstate.ErrorLogger.Error(message, "error", err)

	// Only attempt API submission if task is provided and APIClient is initialized
	if task != nil && agentstate.State.APIClient != nil {
		taskID := &task.Id

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
