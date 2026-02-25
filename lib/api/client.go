package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
)

// Compile-time interface compliance checks.
var (
	_ APIClient     = (*AgentClient)(nil)
	_ TasksClient   = (*agentTasksClient)(nil)
	_ AttacksClient = (*agentAttacksClient)(nil)
	_ AgentsClient  = (*agentAgentsClient)(nil)
	_ AuthClient    = (*agentAuthClient)(nil)
)

// AgentClient wraps the generated ClientWithResponses and implements the APIClient interface.
type AgentClient struct {
	client *ClientWithResponses
}

// NewAgentClient creates a new AgentClient from a server URL and bearer token.
func NewAgentClient(serverURL, token string) (*AgentClient, error) {
	httpClient := &http.Client{}
	authEditor := WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	})

	c, err := NewClientWithResponses(serverURL, WithHTTPClient(httpClient), authEditor)
	if err != nil {
		return nil, fmt.Errorf("creating API client: %w", err)
	}

	return &AgentClient{
		client: c,
	}, nil
}

// Tasks returns a sub-client for task-related API operations.
func (a *AgentClient) Tasks() TasksClient { return &agentTasksClient{client: a.client} }

// Attacks returns a sub-client for attack-related API operations.
func (a *AgentClient) Attacks() AttacksClient { return &agentAttacksClient{client: a.client} }

// Agents returns a sub-client for agent-related API operations.
func (a *AgentClient) Agents() AgentsClient { return &agentAgentsClient{client: a.client} }

// Auth returns a sub-client for authentication-related API operations.
func (a *AgentClient) Auth() AuthClient { return &agentAuthClient{client: a.client} }

// ---------------------------------------------------------------------------
// Tasks sub-client
// ---------------------------------------------------------------------------

type agentTasksClient struct {
	client *ClientWithResponses
}

func (t *agentTasksClient) GetNewTask(ctx context.Context) (*GetNewTaskResponse, error) {
	resp, err := t.client.GetNewTaskWithResponse(ctx)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (t *agentTasksClient) SetTaskAccepted(ctx context.Context, id int64) (*SetTaskAcceptedResponse, error) {
	resp, err := t.client.SetTaskAcceptedWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (t *agentTasksClient) SetTaskExhausted(
	ctx context.Context,
	id int64,
) (*SetTaskExhaustedResponse, error) {
	resp, err := t.client.SetTaskExhaustedWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (t *agentTasksClient) SetTaskAbandoned(
	ctx context.Context,
	id int64,
) (*SetTaskAbandonedResponse, error) {
	resp, err := t.client.SetTaskAbandonedWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}

	// Handle 422 with structured error body
	if resp.JSON422 != nil {
		abandoned := &SetTaskAbandonedError{
			Error_: resp.JSON422.Error,
		}
		if resp.JSON422.Details != nil {
			abandoned.Details = *resp.JSON422.Details
		}
		return resp, abandoned
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (t *agentTasksClient) SendStatus(
	ctx context.Context,
	id int64,
	status TaskStatus,
) (*SendStatusResponse, error) {
	resp, err := t.client.SendStatusWithResponse(ctx, id, status)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (t *agentTasksClient) SendCrack(
	ctx context.Context,
	id int64,
	hashcatResult HashcatResult,
) (*SendCrackResponse, error) {
	resp, err := t.client.SendCrackWithResponse(ctx, id, hashcatResult)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (t *agentTasksClient) GetTaskZaps(ctx context.Context, id int64) (*GetTaskZapsResponse, error) {
	resp, err := t.client.GetTaskZapsWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

// ---------------------------------------------------------------------------
// Attacks sub-client
// ---------------------------------------------------------------------------

type agentAttacksClient struct {
	client *ClientWithResponses
}

func (a *agentAttacksClient) GetAttack(ctx context.Context, id int64) (*GetAttackResponse, error) {
	resp, err := a.client.GetAttackWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (a *agentAttacksClient) GetHashList(ctx context.Context, id int64) (*GetHashListResponse, error) {
	resp, err := a.client.GetHashListWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

// ---------------------------------------------------------------------------
// Agents sub-client
// ---------------------------------------------------------------------------

type agentAgentsClient struct {
	client *ClientWithResponses
}

func (a *agentAgentsClient) SendHeartbeat(
	ctx context.Context,
	id int64,
	activity string,
) (*SendHeartbeatResponse, error) {
	body := SendHeartbeatJSONRequestBody{Activity: &activity}
	resp, err := a.client.SendHeartbeatWithResponse(ctx, id, body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (a *agentAgentsClient) UpdateAgent(
	ctx context.Context,
	id int64,
	body UpdateAgentJSONRequestBody,
) (*UpdateAgentResponse, error) {
	resp, err := a.client.UpdateAgentWithResponse(ctx, id, body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (a *agentAgentsClient) SubmitBenchmark(
	ctx context.Context,
	id int64,
	body SubmitBenchmarkJSONRequestBody,
) (*SubmitBenchmarkResponse, error) {
	resp, err := a.client.SubmitBenchmarkWithResponse(ctx, id, body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (a *agentAgentsClient) SubmitErrorAgent(
	ctx context.Context,
	id int64,
	body SubmitErrorAgentJSONRequestBody,
) (*SubmitErrorAgentResponse, error) {
	resp, err := a.client.SubmitErrorAgentWithResponse(ctx, id, body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (a *agentAgentsClient) SetAgentShutdown(
	ctx context.Context,
	id int64,
) (*SetAgentShutdownResponse, error) {
	resp, err := a.client.SetAgentShutdownWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

// ---------------------------------------------------------------------------
// Auth sub-client
// ---------------------------------------------------------------------------

type agentAuthClient struct {
	client *ClientWithResponses
}

func (a *agentAuthClient) Authenticate(ctx context.Context) (*AuthenticateResponse, error) {
	resp, err := a.client.AuthenticateWithResponse(ctx)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

func (a *agentAuthClient) GetConfiguration(ctx context.Context) (*GetConfigurationResponse, error) {
	resp, err := a.client.GetConfigurationWithResponse(ctx)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() >= http.StatusBadRequest {
		return resp, newAPIError(resp.StatusCode(), resp.Status(), resp.Body)
	}

	return resp, nil
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// newAPIError creates an APIError from HTTP response details.
func newAPIError(statusCode int, status string, body []byte) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    status,
		Body:       string(body),
	}
}

// ResponseStream extracts the response body as an io.ReadCloser from a GetTaskZapsResponse.
// It uses the parsed Body bytes because the generated oapi-codegen parser reads and closes
// HTTPResponse.Body during parsing, making the original body stream unavailable.
// Returns io.ReadCloser (vs io.Reader) because callers in zap.go defer-close the stream.
func ResponseStream(resp *GetTaskZapsResponse) io.ReadCloser {
	if resp == nil {
		return nil
	}
	if len(resp.Body) > 0 {
		return io.NopCloser(bytes.NewReader(resp.Body))
	}
	return nil
}

// HashListResponseStream extracts the response body as an io.Reader from a GetHashListResponse.
// It uses the parsed Body bytes because the generated oapi-codegen parser reads and closes
// HTTPResponse.Body during parsing, making the original body stream unavailable.
// Returns io.Reader (vs io.ReadCloser) because callers in downloader.go don't need Close semantics.
func HashListResponseStream(resp *GetHashListResponse) io.Reader {
	if resp == nil {
		return nil
	}
	if len(resp.Body) > 0 {
		return bytes.NewReader(resp.Body)
	}
	return nil
}

// ConvertInt64SliceToInt converts []int64 to []int with bounds checking
// to prevent silent overflow on 32-bit platforms.
// Returns the converted slice and the number of values that were clamped to zero.
// Callers should log a warning when clamped > 0.
//
//nolint:gocritic // unnamedResult - two returns are clear from doc comment
func ConvertInt64SliceToInt(s []int64) ([]int, int) {
	result := make([]int, len(s))
	clamped := 0
	for i, v := range s {
		if v > math.MaxInt || v < math.MinInt {
			result[i] = 0
			clamped++

			continue
		}
		result[i] = int(v)
	}
	return result, clamped
}
