// Package api provides interfaces for the CipherSwarm API client.
// These interfaces enable dependency injection and improve testability
// by allowing mock implementations in tests.
package api

import (
	"context"
	"io"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
)

// TasksClient defines the interface for task-related API operations.
// This enables mocking in tests and decouples code from the concrete SDK implementation.
type TasksClient interface {
	// GetNewTask retrieves a new task from the server.
	GetNewTask(ctx context.Context) (*operations.GetNewTaskResponse, error)

	// SetTaskAccepted marks a task as accepted.
	SetTaskAccepted(ctx context.Context, id int64) (*operations.SetTaskAcceptedResponse, error)

	// SetTaskExhausted marks a task as exhausted (keyspace fully searched).
	SetTaskExhausted(ctx context.Context, id int64) (*operations.SetTaskExhaustedResponse, error)

	// SetTaskAbandoned marks a task as abandoned.
	SetTaskAbandoned(ctx context.Context, id int64) (*operations.SetTaskAbandonedResponse, error)

	// SendStatus sends a status update for a running task.
	SendStatus(ctx context.Context, id int64, status components.TaskStatus) (*operations.SendStatusResponse, error)

	// SendCrack sends a cracked hash result.
	SendCrack(ctx context.Context, id int64, result *components.HashcatResult) (*operations.SendCrackResponse, error)

	// GetTaskZaps retrieves previously cracked hashes for a task.
	GetTaskZaps(ctx context.Context, id int64) (*operations.GetTaskZapsResponse, error)
}

// AttacksClient defines the interface for attack-related API operations.
type AttacksClient interface {
	// GetAttack retrieves attack parameters by ID.
	GetAttack(ctx context.Context, id int64) (*operations.GetAttackResponse, error)

	// GetHashList retrieves the hash list for an attack.
	GetHashList(ctx context.Context, id int64) (*operations.GetHashListResponse, error)
}

// AgentsClient defines the interface for agent-related API operations.
type AgentsClient interface {
	// SendHeartbeat sends a heartbeat to the server.
	SendHeartbeat(ctx context.Context, id int64) (*operations.SendHeartbeatResponse, error)

	// UpdateAgent updates agent metadata.
	UpdateAgent(
		ctx context.Context,
		id int64,
		body *operations.UpdateAgentRequestBody,
	) (*operations.UpdateAgentResponse, error)

	// SubmitBenchmark submits benchmark results.
	SubmitBenchmark(
		ctx context.Context,
		id int64,
		body operations.SubmitBenchmarkRequestBody,
	) (*operations.SubmitBenchmarkResponse, error)

	// SubmitErrorAgent reports an error to the server.
	SubmitErrorAgent(
		ctx context.Context,
		id int64,
		body *operations.SubmitErrorAgentRequestBody,
	) (*operations.SubmitErrorAgentResponse, error)

	// SetAgentShutdown notifies the server of agent shutdown.
	SetAgentShutdown(ctx context.Context, id int64) (*operations.SetAgentShutdownResponse, error)
}

// AuthClient defines the interface for authentication-related API operations.
type AuthClient interface {
	// Authenticate verifies agent credentials with the server.
	Authenticate(ctx context.Context) (*operations.AuthenticateResponse, error)

	// GetConfiguration retrieves agent configuration from the server.
	GetConfiguration(ctx context.Context) (*operations.GetConfigurationResponse, error)
}

// CrackersClient defines the interface for cracker-related API operations.
type CrackersClient interface {
	// CheckForCrackerUpdate checks if a new cracker version is available.
	CheckForCrackerUpdate(ctx context.Context, os, version *string) (*operations.CheckForCrackerUpdateResponse, error)
}

// Client is the aggregate interface combining all API subsystems.
// This can be implemented by a wrapper around the SDK client or by mocks in tests.
type Client interface {
	Tasks() TasksClient
	Attacks() AttacksClient
	Agents() AgentsClient
	Auth() AuthClient
	Crackers() CrackersClient
}

// HashListResponse provides a simplified interface for hash list download responses.
// This abstracts away the SDK's ResponseStream handling.
type HashListResponse struct {
	StatusCode     int
	Status         string
	ResponseStream io.Reader
}
