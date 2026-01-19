package api

import (
	"context"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
)

// Compile-time interface compliance checks for mocks.
var (
	_ Client         = (*MockClient)(nil)
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

func (m *MockClient) Tasks() TasksClient       { return m.TasksImpl }
func (m *MockClient) Attacks() AttacksClient   { return m.AttacksImpl }
func (m *MockClient) Agents() AgentsClient     { return m.AgentsImpl }
func (m *MockClient) Auth() AuthClient         { return m.AuthImpl }
func (m *MockClient) Crackers() CrackersClient { return m.CrackersImpl }

// MockTasksClient is a configurable mock for TasksClient.
// Set the function fields to control mock behavior.
type MockTasksClient struct {
	GetNewTaskFunc       func(ctx context.Context) (*operations.GetNewTaskResponse, error)
	SetTaskAcceptedFunc  func(ctx context.Context, id int64) (*operations.SetTaskAcceptedResponse, error)
	SetTaskExhaustedFunc func(ctx context.Context, id int64) (*operations.SetTaskExhaustedResponse, error)
	SetTaskAbandonedFunc func(ctx context.Context, id int64) (*operations.SetTaskAbandonedResponse, error)
	SendStatusFunc       func(ctx context.Context, id int64, status components.TaskStatus) (*operations.SendStatusResponse, error)
	SendCrackFunc        func(ctx context.Context, id int64, result *components.HashcatResult) (*operations.SendCrackResponse, error)
	GetTaskZapsFunc      func(ctx context.Context, id int64) (*operations.GetTaskZapsResponse, error)
}

func (m *MockTasksClient) GetNewTask(ctx context.Context) (*operations.GetNewTaskResponse, error) {
	if m.GetNewTaskFunc != nil {
		return m.GetNewTaskFunc(ctx)
	}
	return nil, nil
}

func (m *MockTasksClient) SetTaskAccepted(ctx context.Context, id int64) (*operations.SetTaskAcceptedResponse, error) {
	if m.SetTaskAcceptedFunc != nil {
		return m.SetTaskAcceptedFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockTasksClient) SetTaskExhausted(
	ctx context.Context,
	id int64,
) (*operations.SetTaskExhaustedResponse, error) {
	if m.SetTaskExhaustedFunc != nil {
		return m.SetTaskExhaustedFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockTasksClient) SetTaskAbandoned(
	ctx context.Context,
	id int64,
) (*operations.SetTaskAbandonedResponse, error) {
	if m.SetTaskAbandonedFunc != nil {
		return m.SetTaskAbandonedFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockTasksClient) SendStatus(
	ctx context.Context,
	id int64,
	status components.TaskStatus,
) (*operations.SendStatusResponse, error) {
	if m.SendStatusFunc != nil {
		return m.SendStatusFunc(ctx, id, status)
	}
	return nil, nil
}

func (m *MockTasksClient) SendCrack(
	ctx context.Context,
	id int64,
	result *components.HashcatResult,
) (*operations.SendCrackResponse, error) {
	if m.SendCrackFunc != nil {
		return m.SendCrackFunc(ctx, id, result)
	}
	return nil, nil
}

func (m *MockTasksClient) GetTaskZaps(ctx context.Context, id int64) (*operations.GetTaskZapsResponse, error) {
	if m.GetTaskZapsFunc != nil {
		return m.GetTaskZapsFunc(ctx, id)
	}
	return nil, nil
}

// MockAttacksClient is a configurable mock for AttacksClient.
type MockAttacksClient struct {
	GetAttackFunc   func(ctx context.Context, id int64) (*operations.GetAttackResponse, error)
	GetHashListFunc func(ctx context.Context, id int64) (*operations.GetHashListResponse, error)
}

func (m *MockAttacksClient) GetAttack(ctx context.Context, id int64) (*operations.GetAttackResponse, error) {
	if m.GetAttackFunc != nil {
		return m.GetAttackFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockAttacksClient) GetHashList(ctx context.Context, id int64) (*operations.GetHashListResponse, error) {
	if m.GetHashListFunc != nil {
		return m.GetHashListFunc(ctx, id)
	}
	return nil, nil
}

// MockAgentsClient is a configurable mock for AgentsClient.
type MockAgentsClient struct {
	SendHeartbeatFunc    func(ctx context.Context, id int64) (*operations.SendHeartbeatResponse, error)
	UpdateAgentFunc      func(ctx context.Context, id int64, body *operations.UpdateAgentRequestBody) (*operations.UpdateAgentResponse, error)
	SubmitBenchmarkFunc  func(ctx context.Context, id int64, body operations.SubmitBenchmarkRequestBody) (*operations.SubmitBenchmarkResponse, error)
	SubmitErrorAgentFunc func(ctx context.Context, id int64, body *operations.SubmitErrorAgentRequestBody) (*operations.SubmitErrorAgentResponse, error)
	SetAgentShutdownFunc func(ctx context.Context, id int64) (*operations.SetAgentShutdownResponse, error)
}

func (m *MockAgentsClient) SendHeartbeat(ctx context.Context, id int64) (*operations.SendHeartbeatResponse, error) {
	if m.SendHeartbeatFunc != nil {
		return m.SendHeartbeatFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockAgentsClient) UpdateAgent(
	ctx context.Context,
	id int64,
	body *operations.UpdateAgentRequestBody,
) (*operations.UpdateAgentResponse, error) {
	if m.UpdateAgentFunc != nil {
		return m.UpdateAgentFunc(ctx, id, body)
	}
	return nil, nil
}

func (m *MockAgentsClient) SubmitBenchmark(
	ctx context.Context,
	id int64,
	body operations.SubmitBenchmarkRequestBody,
) (*operations.SubmitBenchmarkResponse, error) {
	if m.SubmitBenchmarkFunc != nil {
		return m.SubmitBenchmarkFunc(ctx, id, body)
	}
	return nil, nil
}

func (m *MockAgentsClient) SubmitErrorAgent(
	ctx context.Context,
	id int64,
	body *operations.SubmitErrorAgentRequestBody,
) (*operations.SubmitErrorAgentResponse, error) {
	if m.SubmitErrorAgentFunc != nil {
		return m.SubmitErrorAgentFunc(ctx, id, body)
	}
	return nil, nil
}

func (m *MockAgentsClient) SetAgentShutdown(
	ctx context.Context,
	id int64,
) (*operations.SetAgentShutdownResponse, error) {
	if m.SetAgentShutdownFunc != nil {
		return m.SetAgentShutdownFunc(ctx, id)
	}
	return nil, nil
}

// MockAuthClient is a configurable mock for AuthClient.
type MockAuthClient struct {
	AuthenticateFunc     func(ctx context.Context) (*operations.AuthenticateResponse, error)
	GetConfigurationFunc func(ctx context.Context) (*operations.GetConfigurationResponse, error)
}

func (m *MockAuthClient) Authenticate(ctx context.Context) (*operations.AuthenticateResponse, error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(ctx)
	}
	return nil, nil
}

func (m *MockAuthClient) GetConfiguration(ctx context.Context) (*operations.GetConfigurationResponse, error) {
	if m.GetConfigurationFunc != nil {
		return m.GetConfigurationFunc(ctx)
	}
	return nil, nil
}

// MockCrackersClient is a configurable mock for CrackersClient.
type MockCrackersClient struct {
	CheckForCrackerUpdateFunc func(ctx context.Context, os, version *string) (*operations.CheckForCrackerUpdateResponse, error)
}

func (m *MockCrackersClient) CheckForCrackerUpdate(
	ctx context.Context,
	os, version *string,
) (*operations.CheckForCrackerUpdateResponse, error) {
	if m.CheckForCrackerUpdateFunc != nil {
		return m.CheckForCrackerUpdateFunc(ctx, os, version)
	}
	return nil, nil
}
