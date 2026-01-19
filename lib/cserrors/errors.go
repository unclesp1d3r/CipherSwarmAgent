// Package cserrors provides error handling and logging utilities for CipherSwarm.
package cserrors

import (
	"context"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// LogAndSendError logs an error message with severity and optionally sends it to the CipherSwarm API.
// It constructs an AgentError object and sends it to the API if a task is provided and APIClient is initialized.
// Returns the original error for further handling.
func LogAndSendError(message string, err error, severity operations.Severity, task *components.Task) error {
	agentstate.ErrorLogger.Error(message, "error", err)

	// Only attempt API submission if task is provided and APIClient is initialized
	if task != nil && agentstate.State.APIClient != nil {
		taskID := &task.ID

		agentError := &operations.SubmitErrorAgentRequestBody{
			AgentID:  agentstate.State.AgentID,
			Message:  message,
			Severity: severity,
			TaskID:   taskID,
		}

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
