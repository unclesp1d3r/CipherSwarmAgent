// Package api provides interfaces for the CipherSwarm API client.
// These interfaces enable dependency injection and improve testability
// by allowing mock implementations in tests.
package api

import (
	"context"
)

// TasksClient defines the interface for task-related API operations.
// This enables mocking in tests and decouples code from the concrete SDK implementation.
type TasksClient interface {
	// GetNewTask retrieves a new task from the server.
	GetNewTask(ctx context.Context) (*GetNewTaskResponse, error)

	// SetTaskAccepted marks a task as accepted.
	SetTaskAccepted(ctx context.Context, id int64) (*SetTaskAcceptedResponse, error)

	// SetTaskExhausted marks a task as exhausted (keyspace fully searched).
	SetTaskExhausted(ctx context.Context, id int64) (*SetTaskExhaustedResponse, error)

	// SetTaskAbandoned marks a task as abandoned.
	SetTaskAbandoned(ctx context.Context, id int64) (*SetTaskAbandonedResponse, error)

	// SendStatus sends a status update for a running task.
	SendStatus(ctx context.Context, id int64, status TaskStatus) (*SendStatusResponse, error)

	// SendCrack sends a cracked hash result.
	SendCrack(ctx context.Context, id int64, result HashcatResult) (*SendCrackResponse, error)

	// GetTaskZaps retrieves previously cracked hashes for a task.
	GetTaskZaps(ctx context.Context, id int64) (*GetTaskZapsResponse, error)
}

// AttacksClient defines the interface for attack-related API operations.
type AttacksClient interface {
	// GetAttack retrieves attack parameters by ID.
	GetAttack(ctx context.Context, id int64) (*GetAttackResponse, error)

	// GetHashList retrieves the hash list for an attack.
	GetHashList(ctx context.Context, id int64) (*GetHashListResponse, error)
}

// AgentsClient defines the interface for agent-related API operations.
type AgentsClient interface {
	// SendHeartbeat sends a heartbeat to the server.
	SendHeartbeat(ctx context.Context, id int64) (*SendHeartbeatResponse, error)

	// UpdateAgent updates agent metadata.
	UpdateAgent(
		ctx context.Context,
		id int64,
		body UpdateAgentJSONRequestBody,
	) (*UpdateAgentResponse, error)

	// SubmitBenchmark submits benchmark results.
	SubmitBenchmark(
		ctx context.Context,
		id int64,
		body SubmitBenchmarkJSONRequestBody,
	) (*SubmitBenchmarkResponse, error)

	// SubmitErrorAgent reports an error to the server.
	SubmitErrorAgent(
		ctx context.Context,
		id int64,
		body SubmitErrorAgentJSONRequestBody,
	) (*SubmitErrorAgentResponse, error)

	// SetAgentShutdown notifies the server of agent shutdown.
	SetAgentShutdown(ctx context.Context, id int64) (*SetAgentShutdownResponse, error)
}

// AuthClient defines the interface for authentication-related API operations.
type AuthClient interface {
	// Authenticate verifies agent credentials with the server.
	Authenticate(ctx context.Context) (*AuthenticateResponse, error)

	// GetConfiguration retrieves agent configuration from the server.
	GetConfiguration(ctx context.Context) (*GetConfigurationResponse, error)
}

// CrackersClient defines the interface for cracker-related API operations.
type CrackersClient interface {
	// CheckForCrackerUpdate checks if a new cracker version is available.
	CheckForCrackerUpdate(ctx context.Context, os, version *string) (*CheckForCrackerUpdateResponse, error)
}

// APIClient is the aggregate interface combining all API subsystems.
// This can be implemented by a wrapper around the SDK client or by mocks in tests.
//
//nolint:revive // Client name is taken by oapi-codegen generated struct in client.gen.go
type APIClient interface {
	Tasks() TasksClient
	Attacks() AttacksClient
	Agents() AgentsClient
	Auth() AuthClient
	Crackers() CrackersClient
}
