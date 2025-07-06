// Package cserrors provides error handling and logging utilities for CipherSwarm.
package cserrors

import (
	"context"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// LogAndSendError logs an error message with severity and optionally sends it to the CipherSwarm API.
// It constructs an AgentError object and sends it to the API if a task is provided.
// Returns the original error for further handling.
func LogAndSendError(message string, err error, severity operations.Severity, task *components.Task) error {
	shared.ErrorLogger.Error(message, "error", err)

	if task != nil {
		var taskID *int64
		if task != nil {
			taskID = &task.ID
		}

		agentError := &operations.SubmitErrorAgentRequestBody{
			AgentID:  shared.State.AgentID,
			Message:  message,
			Severity: severity,
			TaskID:   taskID,
		}

		_, err := shared.State.SdkClient.Agents.SubmitErrorAgent(context.Background(), shared.State.AgentID, agentError)
		if err != nil {
			shared.Logger.Error("Error sending error to server", "error", err)
		}
	}

	return err
}
