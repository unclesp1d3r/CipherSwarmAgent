package api

import (
	"context"

	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
)

// Compile-time interface compliance checks.
var (
	_ Client         = (*SDKWrapper)(nil)
	_ TasksClient    = (*sdkTasksWrapper)(nil)
	_ AttacksClient  = (*sdkAttacksWrapper)(nil)
	_ AgentsClient   = (*sdkAgentsWrapper)(nil)
	_ AuthClient     = (*sdkAuthWrapper)(nil)
	_ CrackersClient = (*sdkCrackersWrapper)(nil)
)

// SDKWrapper wraps the CipherSwarm SDK client and implements the Client interface.
// This enables dependency injection while maintaining compatibility with the existing SDK.
type SDKWrapper struct {
	sdk      *sdk.CipherSwarmAgentSDK
	tasks    *sdkTasksWrapper
	attacks  *sdkAttacksWrapper
	agents   *sdkAgentsWrapper
	auth     *sdkAuthWrapper
	crackers *sdkCrackersWrapper
}

// NewSDKWrapper creates a new SDKWrapper from an existing SDK client.
func NewSDKWrapper(sdkClient *sdk.CipherSwarmAgentSDK) *SDKWrapper {
	return &SDKWrapper{
		sdk:      sdkClient,
		tasks:    &sdkTasksWrapper{sdk: sdkClient},
		attacks:  &sdkAttacksWrapper{sdk: sdkClient},
		agents:   &sdkAgentsWrapper{sdk: sdkClient},
		auth:     &sdkAuthWrapper{sdk: sdkClient},
		crackers: &sdkCrackersWrapper{sdk: sdkClient},
	}
}

// Tasks returns the TasksClient implementation.
func (w *SDKWrapper) Tasks() TasksClient {
	return w.tasks
}

// Attacks returns the AttacksClient implementation.
func (w *SDKWrapper) Attacks() AttacksClient {
	return w.attacks
}

// Agents returns the AgentsClient implementation.
func (w *SDKWrapper) Agents() AgentsClient {
	return w.agents
}

// Auth returns the AuthClient implementation.
func (w *SDKWrapper) Auth() AuthClient {
	return w.auth
}

// Crackers returns the CrackersClient implementation.
func (w *SDKWrapper) Crackers() CrackersClient {
	return w.crackers
}

// sdkTasksWrapper wraps SDK Tasks operations.
type sdkTasksWrapper struct {
	sdk *sdk.CipherSwarmAgentSDK
}

func (w *sdkTasksWrapper) GetNewTask(ctx context.Context) (*operations.GetNewTaskResponse, error) {
	return w.sdk.Tasks.GetNewTask(ctx)
}

func (w *sdkTasksWrapper) SetTaskAccepted(ctx context.Context, id int64) (*operations.SetTaskAcceptedResponse, error) {
	return w.sdk.Tasks.SetTaskAccepted(ctx, id)
}

func (w *sdkTasksWrapper) SetTaskExhausted(
	ctx context.Context,
	id int64,
) (*operations.SetTaskExhaustedResponse, error) {
	return w.sdk.Tasks.SetTaskExhausted(ctx, id)
}

func (w *sdkTasksWrapper) SetTaskAbandoned(
	ctx context.Context,
	id int64,
) (*operations.SetTaskAbandonedResponse, error) {
	return w.sdk.Tasks.SetTaskAbandoned(ctx, id)
}

func (w *sdkTasksWrapper) SendStatus(
	ctx context.Context,
	id int64,
	status components.TaskStatus,
) (*operations.SendStatusResponse, error) {
	return w.sdk.Tasks.SendStatus(ctx, id, status)
}

func (w *sdkTasksWrapper) SendCrack(
	ctx context.Context,
	id int64,
	result *components.HashcatResult,
) (*operations.SendCrackResponse, error) {
	return w.sdk.Tasks.SendCrack(ctx, id, result)
}

func (w *sdkTasksWrapper) GetTaskZaps(ctx context.Context, id int64) (*operations.GetTaskZapsResponse, error) {
	return w.sdk.Tasks.GetTaskZaps(ctx, id)
}

// sdkAttacksWrapper wraps SDK Attacks operations.
type sdkAttacksWrapper struct {
	sdk *sdk.CipherSwarmAgentSDK
}

func (w *sdkAttacksWrapper) GetAttack(ctx context.Context, id int64) (*operations.GetAttackResponse, error) {
	return w.sdk.Attacks.GetAttack(ctx, id)
}

func (w *sdkAttacksWrapper) GetHashList(ctx context.Context, id int64) (*operations.GetHashListResponse, error) {
	return w.sdk.Attacks.GetHashList(ctx, id)
}

// sdkAgentsWrapper wraps SDK Agents operations.
type sdkAgentsWrapper struct {
	sdk *sdk.CipherSwarmAgentSDK
}

func (w *sdkAgentsWrapper) SendHeartbeat(ctx context.Context, id int64) (*operations.SendHeartbeatResponse, error) {
	return w.sdk.Agents.SendHeartbeat(ctx, id)
}

func (w *sdkAgentsWrapper) UpdateAgent(
	ctx context.Context,
	id int64,
	body *operations.UpdateAgentRequestBody,
) (*operations.UpdateAgentResponse, error) {
	return w.sdk.Agents.UpdateAgent(ctx, id, body)
}

func (w *sdkAgentsWrapper) SubmitBenchmark(
	ctx context.Context,
	id int64,
	body operations.SubmitBenchmarkRequestBody,
) (*operations.SubmitBenchmarkResponse, error) {
	return w.sdk.Agents.SubmitBenchmark(ctx, id, body)
}

func (w *sdkAgentsWrapper) SubmitErrorAgent(
	ctx context.Context,
	id int64,
	body *operations.SubmitErrorAgentRequestBody,
) (*operations.SubmitErrorAgentResponse, error) {
	return w.sdk.Agents.SubmitErrorAgent(ctx, id, body)
}

func (w *sdkAgentsWrapper) SetAgentShutdown(
	ctx context.Context,
	id int64,
) (*operations.SetAgentShutdownResponse, error) {
	return w.sdk.Agents.SetAgentShutdown(ctx, id)
}

// sdkAuthWrapper wraps SDK Client (auth) operations.
type sdkAuthWrapper struct {
	sdk *sdk.CipherSwarmAgentSDK
}

func (w *sdkAuthWrapper) Authenticate(ctx context.Context) (*operations.AuthenticateResponse, error) {
	return w.sdk.Client.Authenticate(ctx)
}

func (w *sdkAuthWrapper) GetConfiguration(ctx context.Context) (*operations.GetConfigurationResponse, error) {
	return w.sdk.Client.GetConfiguration(ctx)
}

// sdkCrackersWrapper wraps SDK Crackers operations.
type sdkCrackersWrapper struct {
	sdk *sdk.CipherSwarmAgentSDK
}

func (w *sdkCrackersWrapper) CheckForCrackerUpdate(
	ctx context.Context,
	operatingSystem, version *string,
) (*operations.CheckForCrackerUpdateResponse, error) {
	return w.sdk.Crackers.CheckForCrackerUpdate(ctx, operatingSystem, version)
}
