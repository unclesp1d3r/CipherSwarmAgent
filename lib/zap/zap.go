// Package zap provides functionality for handling CipherSwarm zap files and hash list processing.
package zap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
)

const (
	zapPlaintextSeparator = ":"   // Default hash-list separator the server joins hash and plaintext with
	zapFileMode           = 0o600 // Restrictive permissions for cracked hash data
)

// GetZaps fetches zap data for a given task, handles errors, and processes the response stream if available.
// Logs an error if the task is nil, displays job progress, and retrieves zaps via the injected TasksClient.
// zapsPath is the directory where zap files should be written.
func GetZaps(
	ctx context.Context,
	tasksClient api.TasksClient,
	task *api.Task,
	sendCrackedHashFunc func(context.Context, time.Time, string, string, *api.Task),
	zapsPath string,
) {
	if task == nil {
		agentstate.Logger.Error("Task is nil")

		return
	}

	res, err := tasksClient.GetTaskZaps(ctx, task.Id)
	if err != nil {
		agentstate.Logger.Error("Error fetching zaps for task", "task_id", task.Id, "error", err)

		return
	}

	responseStream := api.ResponseStream(res)
	if responseStream == nil {
		agentstate.Logger.Warn("Zaps response was successful but contained no data",
			"task_id", task.Id, "status_code", res.StatusCode())

		return
	}

	if err := handleResponseStream(ctx, task, responseStream, sendCrackedHashFunc, zapsPath); err != nil {
		agentstate.Logger.Warn("Failed to process zap response stream; cracked hashes may be lost",
			"task_id", task.Id, "error", err)
	}
}

// removeExistingZapFile removes the zap file at the given path if it exists, logging debug information.
// Returns an error if the file removal fails.
func removeExistingZapFile(zapFilePath string) error {
	err := os.Remove(zapFilePath)
	if err != nil && !os.IsNotExist(err) {
		agentstate.Logger.Debug("Error removing zap file", "path", zapFilePath, "error", err)
		return fmt.Errorf("removing existing zap file %q: %w", zapFilePath, err)
	}

	return nil
}

// createAndWriteZapFile creates a zap file at the specified path and writes data from the provided responseStream.
// The task parameter is used for logging and error reporting in case of failures.
// Returns an error if file creation, writing, or closing fails.
func createAndWriteZapFile(ctx context.Context, zapFilePath string, responseStream io.Reader, task *api.Task) error {
	outFile, err := os.OpenFile(zapFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zapFileMode)
	if err != nil {
		return fmt.Errorf("error creating zap file: %w", err)
	}

	// Best-effort chmod to enforce 0600 on pre-existing files.
	// Non-fatal: network shares (NFS, SMB) may not support chmod.
	if err := outFile.Chmod(zapFileMode); err != nil {
		agentstate.Logger.Warn("Could not set zap file permissions (network share?)",
			"path", zapFilePath, "error", err)
	}

	defer func() {
		if cerr := outFile.Close(); cerr != nil {
			//nolint:errcheck // LogAndSendError handles logging+sending internally
			_ = cserrors.LogAndSendError(ctx, "Error closing zap file", cerr, api.SeverityCritical, task)
		}
	}()

	if _, err := io.Copy(outFile, responseStream); err != nil {
		return fmt.Errorf("error writing zap file: %w", err)
	}

	return nil
}

// handleResponseStream processes the response stream from a zap request.
// It writes the stream to a zap file on disk and then processes its contents.
// zapsPath is the directory where the zap file should be written.
func handleResponseStream(
	ctx context.Context,
	task *api.Task,
	responseStream io.ReadCloser,
	sendCrackedHashFunc func(context.Context, time.Time, string, string, *api.Task),
	zapsPath string,
) error {
	defer func(responseStream io.ReadCloser) {
		err := responseStream.Close()
		if err != nil {
			agentstate.Logger.Error("Error closing response stream", "error", err)
		}
	}(responseStream)

	zapFilePath := filepath.Join(zapsPath, fmt.Sprintf("%d.zap", task.Id))
	if err := removeExistingZapFile(zapFilePath); err != nil {
		// Log but continue — os.OpenFile in createAndWriteZapFile will truncate the file anyway.
		//nolint:errcheck // LogAndSendError handles logging+sending internally
		_ = cserrors.LogAndSendError(
			ctx,
			"Error removing existing zap file",
			err,
			api.SeverityWarning,
			task,
		)
	}

	if err := createAndWriteZapFile(ctx, zapFilePath, responseStream, task); err != nil {
		return cserrors.LogAndSendError(ctx, "Error creating and writing zap file", err, api.SeverityCritical, task)
	}

	if err := processZapFile(ctx, zapFilePath, task, sendCrackedHashFunc); err != nil {
		return cserrors.LogAndSendError(ctx, "Error processing zap file", err, api.SeverityCritical, task)
	}

	return nil
}

// processZapFile reads a zap file line by line, processes each line as a cracked hash,
// and sends it to the server. It returns an error if the file cannot be opened or read.
func processZapFile(
	ctx context.Context,
	zapFilePath string,
	task *api.Task,
	sendCrackedHashFunc func(context.Context, time.Time, string, string, *api.Task),
) error {
	file, err := os.Open(
		zapFilePath,
	)
	if err != nil {
		return fmt.Errorf("opening zap file %q: %w", zapFilePath, err)
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

		// The server serializes each cracked entry as `hash<sep>plaintext` using the
		// hash list's separator (default ":"). Many hash types embed colons (NTLMv2,
		// Kerberos krb5asrep, PBKDF2 sha256:rounds:salt), so split on the LAST
		// separator: everything before it is the hash (internal colons preserved),
		// everything after is the plaintext.
		//
		// Limitation (KTD3): a plaintext that itself contains a colon is
		// misattributed. This is accepted because hash colons are systematic while
		// plaintext colons are rare, and LastIndex is strictly better than splitting
		// on the first colon, which truncated every colon-bearing hash.
		idx := strings.LastIndex(line, zapPlaintextSeparator)
		if idx < 0 {
			continue
		}

		hash := line[:idx]
		plaintext := line[idx+len(zapPlaintextSeparator):]
		sendCrackedHashFunc(ctx, time.Now(), hash, plaintext, task)
	}

	return scanner.Err()
}
