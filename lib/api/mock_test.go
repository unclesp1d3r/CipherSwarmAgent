package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockTasksClient_GetNewTask(t *testing.T) {
	t.Parallel()

	expectedTask := &Task{Id: 123, AttackId: 456}

	mock := &MockTasksClient{
		GetNewTaskFunc: func(_ context.Context) (*GetNewTaskResponse, error) {
			return &GetNewTaskResponse{
				HTTPResponse: &http.Response{StatusCode: http.StatusOK},
				JSON200:      expectedTask,
			}, nil
		},
	}

	resp, err := mock.GetNewTask(context.Background())

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	require.NotNil(t, resp.JSON200, "Task should not be nil for successful response")
	assert.Equal(t, expectedTask.Id, resp.JSON200.Id)
}

func TestMockTasksClient_NoContent(t *testing.T) {
	t.Parallel()

	mock := &MockTasksClient{
		GetNewTaskFunc: func(_ context.Context) (*GetNewTaskResponse, error) {
			return &GetNewTaskResponse{
				HTTPResponse: &http.Response{StatusCode: http.StatusNoContent},
				JSON200:      nil,
			}, nil
		},
	}

	resp, err := mock.GetNewTask(context.Background())

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode())
	assert.Nil(t, resp.JSON200)
}

func TestMockClient_InterfaceCompliance(t *testing.T) {
	t.Parallel()

	// This test verifies that MockClient satisfies the APIClient interface
	// and that all subsystem mocks satisfy their respective interfaces.
	var client APIClient = &MockClient{
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

	require.NoError(t, err)
	assert.Nil(t, resp)
}
