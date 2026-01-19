package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
)

func TestMockTasksClient_GetNewTask(t *testing.T) {
	t.Parallel()

	expectedTask := &components.Task{ID: 123, AttackID: 456}

	mock := &MockTasksClient{
		GetNewTaskFunc: func(_ context.Context) (*operations.GetNewTaskResponse, error) {
			return &operations.GetNewTaskResponse{
				StatusCode: http.StatusOK,
				Task:       expectedTask,
			}, nil
		},
	}

	resp, err := mock.GetNewTask(context.Background())

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, expectedTask.ID, resp.Task.ID)
}

func TestMockTasksClient_NoContent(t *testing.T) {
	t.Parallel()

	mock := &MockTasksClient{
		GetNewTaskFunc: func(_ context.Context) (*operations.GetNewTaskResponse, error) {
			return &operations.GetNewTaskResponse{
				StatusCode: http.StatusNoContent,
				Task:       nil,
			}, nil
		},
	}

	resp, err := mock.GetNewTask(context.Background())

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Nil(t, resp.Task)
}

func TestMockClient_InterfaceCompliance(t *testing.T) {
	t.Parallel()

	// This test verifies that MockClient satisfies the Client interface
	// and that all subsystem mocks satisfy their respective interfaces.
	var client Client = &MockClient{
		TasksImpl:    &MockTasksClient{},
		AttacksImpl:  &MockAttacksClient{},
		AgentsImpl:   &MockAgentsClient{},
		AuthImpl:     &MockAuthClient{},
		CrackersImpl: &MockCrackersClient{},
	}

	// Verify all subsystems are accessible
	assert.NotNil(t, client.Tasks())
	assert.NotNil(t, client.Attacks())
	assert.NotNil(t, client.Agents())
	assert.NotNil(t, client.Auth())
	assert.NotNil(t, client.Crackers())
}

func TestMockTasksClient_DefaultBehavior(t *testing.T) {
	t.Parallel()

	// When no function is configured, mocks return nil, nil
	mock := &MockTasksClient{}

	resp, err := mock.GetNewTask(context.Background())

	assert.NoError(t, err)
	assert.Nil(t, resp)
}
