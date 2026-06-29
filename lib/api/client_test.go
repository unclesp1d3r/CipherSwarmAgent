package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testServerURL = "http://test-server"

// newTestClient creates an AgentClient backed by the provided mock transport.
// MaxAttempts is 1 (no retries) and CircuitBreakerFailureThreshold is high so
// that 4xx responses in tests do not trigger circuit breaker state changes.
func newTestClient(t *testing.T, mt *httpmock.MockTransport) *AgentClient {
	t.Helper()
	cfg := TransportConfig{
		BaseTransport:                  mt,
		MaxAttempts:                    1,
		ConnectTimeout:                 1 * time.Second,
		ReadTimeout:                    1 * time.Second,
		RequestTimeout:                 5 * time.Second,
		RetryInitialDelay:              1 * time.Millisecond,
		RetryMaxDelay:                  1 * time.Millisecond,
		CircuitBreakerFailureThreshold: 10,
		CircuitBreakerTimeout:          1 * time.Second,
	}
	client, err := NewAgentClient(testServerURL, "test-token", cfg)
	require.NoError(t, err)
	return client
}

// TestAgentClient_SubClient_200 verifies that a 200 response is forwarded as-is
// with a nil error. GetNewTask is used as a representative method.
func TestAgentClient_SubClient_200(t *testing.T) {
	t.Parallel()

	mt := httpmock.NewMockTransport()
	client := newTestClient(t, mt)

	mt.RegisterResponder(
		"GET",
		testServerURL+"/api/v1/client/tasks/new",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, map[string]any{
			"id": 42, "attack_id": 7,
		}),
	)

	resp, err := client.Tasks().GetNewTask(context.Background())

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	require.NotNil(t, resp.JSON200, "expected parsed body in JSON200")
	assert.Equal(t, int64(42), resp.JSON200.Id)
	assert.Equal(t, int64(7), resp.JSON200.AttackId)
}

// TestAgentClient_SubClient_4xx verifies that a >=400 response is wrapped as
// *APIError and returned alongside the response. GetNewTask is used as a
// representative method covering the checkResponse generic path.
func TestAgentClient_SubClient_4xx(t *testing.T) {
	t.Parallel()

	mt := httpmock.NewMockTransport()
	client := newTestClient(t, mt)

	mt.RegisterResponder(
		"GET",
		testServerURL+"/api/v1/client/tasks/new",
		httpmock.NewJsonResponderOrPanic(http.StatusNotFound, map[string]any{
			"error": "task not found",
		}),
	)

	resp, err := client.Tasks().GetNewTask(context.Background())

	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode())

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr, "expected *APIError, got: %T", err)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
}

// TestAgentClient_SetTaskAbandoned_422 verifies the explicit 422 handling in
// SetTaskAbandoned: the returned error is *SetTaskAbandonedError with the Error_
// and Details fields populated from the structured response body.
func TestAgentClient_SetTaskAbandoned_422(t *testing.T) {
	t.Parallel()

	mt := httpmock.NewMockTransport()
	client := newTestClient(t, mt)

	mt.RegisterResponder(
		"POST",
		testServerURL+"/api/v1/client/tasks/1/abandon",
		httpmock.NewJsonResponderOrPanic(http.StatusUnprocessableEntity, map[string]any{
			"error":   "cannot abandon task in current state",
			"details": []string{"task is already completed"},
		}),
	)

	resp, err := client.Tasks().SetTaskAbandoned(context.Background(), 1)

	require.Error(t, err)
	require.NotNil(t, resp)

	var abandonErr *SetTaskAbandonedError
	require.ErrorAs(t, err, &abandonErr, "expected *SetTaskAbandonedError, got: %T", err)
	require.NotNil(t, abandonErr.Error_)
	assert.Equal(t, "cannot abandon task in current state", *abandonErr.Error_)
	assert.Equal(t, []string{"task is already completed"}, abandonErr.Details)
}

// TestAgentClient_SetTaskAbandoned_4xx verifies that a non-422 4xx response from
// SetTaskAbandoned falls through to the generic APIError path below the 422 check.
func TestAgentClient_SetTaskAbandoned_4xx(t *testing.T) {
	t.Parallel()

	mt := httpmock.NewMockTransport()
	client := newTestClient(t, mt)

	mt.RegisterResponder(
		"POST",
		testServerURL+"/api/v1/client/tasks/2/abandon",
		httpmock.NewJsonResponderOrPanic(http.StatusNotFound, map[string]any{
			"error": "task not found",
		}),
	)

	resp, err := client.Tasks().SetTaskAbandoned(context.Background(), 2)

	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode())

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr, "expected *APIError, got: %T", err)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
}
