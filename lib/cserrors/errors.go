// Package cserrors provides error handling and logging utilities for CipherSwarm.
package cserrors

import (
	"context"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// LogAndSendError logs an error message with severity and optionally sends it to the CipherSwarm API.
// It constructs an AgentError object and sends it to the API if a task is provided.
// Returns the original error for further handling.
func LogAndSendError(message string, err error, severity operations.Severity, task *components.Task) error {
	agentstate.ErrorLogger.Error(message, "error", err)

	if task != nil {
		taskID := &task.ID

		agentError := &operations.SubmitErrorAgentRequestBody{
			AgentID:  agentstate.State.AgentID,
			Message:  message,
			Severity: severity,
			TaskID:   taskID,
		}

		_, err := agentstate.State.SdkClient.Agents.SubmitErrorAgent(
			context.Background(),
			agentstate.State.AgentID,
			agentError,
		)
		if err != nil {
			agentstate.Logger.Error("Error sending error to server", "error", err)
		}
	}

	return err
}
