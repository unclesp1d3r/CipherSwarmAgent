package api

import (
	"context"
)

// Compile-time interface compliance checks for mocks.
var (
	_ APIClient      = (*MockClient)(nil)
	_ TasksClient    = (*MockTasksClient)(nil)
	_ AttacksClient  = (*MockAttacksClient)(nil)
	_ AgentsClient   = (*MockAgentsClient)(nil)
	_ AuthClient     = (*MockAuthClient)(nil)
	_ CrackersClient = (*MockCrackersClient)(nil)
)

// MockClient is a test double for the Client interface.
// Each subsystem client can be configured independently.
type MockClient struct {
	TasksImpl    TasksClient
	AttacksImpl  AttacksClient
	AgentsImpl   AgentsClient
	AuthImpl     AuthClient
	CrackersImpl CrackersClient
}

// Tasks returns the configured TasksClient implementation.
func (m *MockClient) Tasks() TasksClient { return m.TasksImpl }

// Attacks returns the configured AttacksClient implementation.
func (m *MockClient) Attacks() AttacksClient { return m.AttacksImpl }

// Agents returns the configured AgentsClient implementation.
func (m *MockClient) Agents() AgentsClient { return m.AgentsImpl }

// Auth returns the configured AuthClient implementation.
func (m *MockClient) Auth() AuthClient { return m.AuthImpl }

// Crackers returns the configured CrackersClient implementation.
func (m *MockClient) Crackers() CrackersClient { return m.CrackersImpl }

// MockTasksClient is a configurable mock for TasksClient.
// Set the function fields to control mock behavior.
type MockTasksClient struct {
	GetNewTaskFunc       func(ctx context.Context) (*GetNewTaskResponse, error)
	SetTaskAcceptedFunc  func(ctx context.Context, id int64) (*SetTaskAcceptedResponse, error)
	SetTaskExhaustedFunc func(ctx context.Context, id int64) (*SetTaskExhaustedResponse, error)
	SetTaskAbandonedFunc func(ctx context.Context, id int64) (*SetTaskAbandonedResponse, error)
	SendStatusFunc       func(ctx context.Context, id int64, status TaskStatus) (*SendStatusResponse, error)
	SendCrackFunc        func(ctx context.Context, id int64, result HashcatResult) (*SendCrackResponse, error)
	GetTaskZapsFunc      func(ctx context.Context, id int64) (*GetTaskZapsResponse, error)
}

// GetNewTask calls the configured function or returns nil if not configured.
func (m *MockTasksClient) GetNewTask(ctx context.Context) (*GetNewTaskResponse, error) {
	if m.GetNewTaskFunc != nil {
		return m.GetNewTaskFunc(ctx)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// SetTaskAccepted calls the configured function or returns nil if not configured.
func (m *MockTasksClient) SetTaskAccepted(ctx context.Context, id int64) (*SetTaskAcceptedResponse, error) {
	if m.SetTaskAcceptedFunc != nil {
		return m.SetTaskAcceptedFunc(ctx, id)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// SetTaskExhausted calls the configured function or returns nil if not configured.
func (m *MockTasksClient) SetTaskExhausted(
	ctx context.Context,
	id int64,
) (*SetTaskExhaustedResponse, error) {
	if m.SetTaskExhaustedFunc != nil {
		return m.SetTaskExhaustedFunc(ctx, id)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// SetTaskAbandoned calls the configured function or returns nil if not configured.
func (m *MockTasksClient) SetTaskAbandoned(
	ctx context.Context,
	id int64,
) (*SetTaskAbandonedResponse, error) {
	if m.SetTaskAbandonedFunc != nil {
		return m.SetTaskAbandonedFunc(ctx, id)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// SendStatus calls the configured function or returns nil if not configured.
func (m *MockTasksClient) SendStatus(
	ctx context.Context,
	id int64,
	status TaskStatus,
) (*SendStatusResponse, error) {
	if m.SendStatusFunc != nil {
		return m.SendStatusFunc(ctx, id, status)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// SendCrack calls the configured function or returns nil if not configured.
func (m *MockTasksClient) SendCrack(
	ctx context.Context,
	id int64,
	result HashcatResult,
) (*SendCrackResponse, error) {
	if m.SendCrackFunc != nil {
		return m.SendCrackFunc(ctx, id, result)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// GetTaskZaps calls the configured function or returns nil if not configured.
func (m *MockTasksClient) GetTaskZaps(ctx context.Context, id int64) (*GetTaskZapsResponse, error) {
	if m.GetTaskZapsFunc != nil {
		return m.GetTaskZapsFunc(ctx, id)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// MockAttacksClient is a configurable mock for AttacksClient.
type MockAttacksClient struct {
	GetAttackFunc   func(ctx context.Context, id int64) (*GetAttackResponse, error)
	GetHashListFunc func(ctx context.Context, id int64) (*GetHashListResponse, error)
}

// GetAttack calls the configured function or returns nil if not configured.
func (m *MockAttacksClient) GetAttack(ctx context.Context, id int64) (*GetAttackResponse, error) {
	if m.GetAttackFunc != nil {
		return m.GetAttackFunc(ctx, id)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// GetHashList calls the configured function or returns nil if not configured.
func (m *MockAttacksClient) GetHashList(ctx context.Context, id int64) (*GetHashListResponse, error) {
	if m.GetHashListFunc != nil {
		return m.GetHashListFunc(ctx, id)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// MockAgentsClient is a configurable mock for AgentsClient.
type MockAgentsClient struct {
	SendHeartbeatFunc    func(ctx context.Context, id int64) (*SendHeartbeatResponse, error)
	UpdateAgentFunc      func(ctx context.Context, id int64, body UpdateAgentJSONRequestBody) (*UpdateAgentResponse, error)
	SubmitBenchmarkFunc  func(ctx context.Context, id int64, body SubmitBenchmarkJSONRequestBody) (*SubmitBenchmarkResponse, error)
	SubmitErrorAgentFunc func(ctx context.Context, id int64, body SubmitErrorAgentJSONRequestBody) (*SubmitErrorAgentResponse, error)
	SetAgentShutdownFunc func(ctx context.Context, id int64) (*SetAgentShutdownResponse, error)
}

// SendHeartbeat calls the configured function or returns nil if not configured.
func (m *MockAgentsClient) SendHeartbeat(ctx context.Context, id int64) (*SendHeartbeatResponse, error) {
	if m.SendHeartbeatFunc != nil {
		return m.SendHeartbeatFunc(ctx, id)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// UpdateAgent calls the configured function or returns nil if not configured.
func (m *MockAgentsClient) UpdateAgent(
	ctx context.Context,
	id int64,
	body UpdateAgentJSONRequestBody,
) (*UpdateAgentResponse, error) {
	if m.UpdateAgentFunc != nil {
		return m.UpdateAgentFunc(ctx, id, body)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// SubmitBenchmark calls the configured function or returns nil if not configured.
func (m *MockAgentsClient) SubmitBenchmark(
	ctx context.Context,
	id int64,
	body SubmitBenchmarkJSONRequestBody,
) (*SubmitBenchmarkResponse, error) {
	if m.SubmitBenchmarkFunc != nil {
		return m.SubmitBenchmarkFunc(ctx, id, body)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// SubmitErrorAgent calls the configured function or returns nil if not configured.
func (m *MockAgentsClient) SubmitErrorAgent(
	ctx context.Context,
	id int64,
	body SubmitErrorAgentJSONRequestBody,
) (*SubmitErrorAgentResponse, error) {
	if m.SubmitErrorAgentFunc != nil {
		return m.SubmitErrorAgentFunc(ctx, id, body)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// SetAgentShutdown calls the configured function or returns nil if not configured.
func (m *MockAgentsClient) SetAgentShutdown(
	ctx context.Context,
	id int64,
) (*SetAgentShutdownResponse, error) {
	if m.SetAgentShutdownFunc != nil {
		return m.SetAgentShutdownFunc(ctx, id)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// MockAuthClient is a configurable mock for AuthClient.
type MockAuthClient struct {
	AuthenticateFunc     func(ctx context.Context) (*AuthenticateResponse, error)
	GetConfigurationFunc func(ctx context.Context) (*GetConfigurationResponse, error)
}

// Authenticate calls the configured function or returns nil if not configured.
func (m *MockAuthClient) Authenticate(ctx context.Context) (*AuthenticateResponse, error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(ctx)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// GetConfiguration calls the configured function or returns nil if not configured.
func (m *MockAuthClient) GetConfiguration(ctx context.Context) (*GetConfigurationResponse, error) {
	if m.GetConfigurationFunc != nil {
		return m.GetConfigurationFunc(ctx)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}

// MockCrackersClient is a configurable mock for CrackersClient.
type MockCrackersClient struct {
	CheckForCrackerUpdateFunc func(ctx context.Context, os, version *string) (*CheckForCrackerUpdateResponse, error)
}

// CheckForCrackerUpdate calls the configured function or returns nil if not configured.
func (m *MockCrackersClient) CheckForCrackerUpdate(
	ctx context.Context,
	os, version *string,
) (*CheckForCrackerUpdateResponse, error) {
	if m.CheckForCrackerUpdateFunc != nil {
		return m.CheckForCrackerUpdateFunc(ctx, os, version)
	}

	return nil, nil //nolint:nilnil // Intentional for unconfigured mock methods
}
