// Package zap provides functionality for handling CipherSwarm zap files and hash list processing.
package zap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
)

const (
	zapLineParts = 2 // Expected number of parts when splitting zap line by colon
)

// GetZaps fetches zap data for a given task, handles errors, and processes the response stream if available.
// Logs an error if the task is nil, displays job progress, and retrieves zaps via the API client interface.
func GetZaps(task *components.Task, sendCrackedHashFunc func(time.Time, string, string, *components.Task)) {
	if task == nil {
		agentstate.Logger.Error("Task is nil")

		return
	}

	res, err := agentstate.State.APIClient.Tasks().GetTaskZaps(context.Background(), task.GetID())
	if err != nil {
		return
	}

	if res.ResponseStream != nil {
		//nolint:errcheck // Error already being handled
		_ = handleResponseStream(
			task,
			res.ResponseStream,
			sendCrackedHashFunc,
		)
	}
}

// removeExistingZapFile removes the zap file at the given path if it exists, logging debug information.
// Returns an error if the file removal fails.
func removeExistingZapFile(zapFilePath string) error {
	err := os.Remove(zapFilePath)
	if err != nil && !os.IsNotExist(err) {
		agentstate.Logger.Debug("Error removing zap file", "path", zapFilePath, "error", err)
		return err
	}

	return nil
}

// createAndWriteZapFile creates a zap file at the specified path and writes data from the provided responseStream.
// The task parameter is used for logging and error reporting in case of failures.
// Returns an error if file creation, writing, or closing fails.
func createAndWriteZapFile(zapFilePath string, responseStream io.Reader, task *components.Task) error {
	outFile, err := os.Create(
		zapFilePath,
	)
	if err != nil {
		return fmt.Errorf("error creating zap file: %w", err)
	}

	if _, err := io.Copy(outFile, responseStream); err != nil {
		return fmt.Errorf("error writing zap file: %w", err)
	}

	if cerr := outFile.Close(); cerr != nil {
		return cserrors.LogAndSendError("Error closing zap file", cerr, operations.SeverityCritical, task)
	}

	return nil
}

// handleResponseStream processes the response stream from a zap request.
// It creates a temporary file, writes the stream to it, and then processes the zap file.
func handleResponseStream(
	task *components.Task,
	responseStream io.ReadCloser,
	sendCrackedHashFunc func(time.Time, string, string, *components.Task),
) error {
	defer func(responseStream io.ReadCloser) {
		err := responseStream.Close()
		if err != nil {
			agentstate.Logger.Error("Error closing response stream", "error", err)
		}
	}(responseStream)

	zapFilePath := path.Join(agentstate.State.ZapsPath, fmt.Sprintf("%d.zap", task.GetID()))
	if err := removeExistingZapFile(zapFilePath); err != nil {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error removing existing zap file",
			err,
			operations.SeverityCritical,
			task,
		)
	}

	if err := createAndWriteZapFile(zapFilePath, responseStream, task); err != nil {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error creating and writing zap file",
			err,
			operations.SeverityCritical,
			task,
		)
	}

	if err := processZapFile(zapFilePath, task, sendCrackedHashFunc); err != nil {
		//nolint:errcheck // Error already being handled
		_ = cserrors.LogAndSendError(
			"Error processing zap file",
			err,
			operations.SeverityCritical,
			task,
		)
	}

	return nil
}

// processZapFile reads a zap file line by line, processes each line as a cracked hash,
// and sends it to the server. It returns an error if the file cannot be opened or read.
func processZapFile(
	zapFilePath string,
	task *components.Task,
	sendCrackedHashFunc func(time.Time, string, string, *components.Task),
) error {
	file, err := os.Open(
		zapFilePath,
	)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			agentstate.Logger.Error("Error closing zap file", "error", err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.SplitN(line, ":", zapLineParts)
		if len(parts) != zapLineParts {
			continue
		}

		hash := parts[0]
		plaintext := parts[1]
		sendCrackedHashFunc(time.Now(), hash, plaintext, task)
	}

	return scanner.Err()
}
