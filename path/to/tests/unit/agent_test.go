// agent_test.go
package tests

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"cipherSwarmAgent"
)

func TestAgentStart(t *testing.T) {
	// Arrange
	mockServer := &cipherSwarmAgent.MockServer{}
	mockServer.On("AuthenticateAgent").Return(true)
	agent := cipherSwarmAgent.NewAgent(mockServer)

	// Act
	err := agent.Start()

	// Assert
	assert.NoError(t, err)
	mockServer.AssertExpectations(t)
}

func TestAgentAuthenticate(t *testing.T) {
	// Arrange
	mockServer := &cipherSwarmAgent.MockServer{}
	mockServer.On("AuthenticateAgent").Return(true)
	agent := cipherSwarmAgent.NewAgent(mockServer)

	// Act
	err := agent.AuthenticateAgent()

	// Assert
	assert.NoError(t, err)
	mockServer.AssertExpectations(t)
}

func TestAgentHandleNonExhaustedError(t *testing.T) {
	// Arrange
	agent := cipherSwarmAgent.NewAgent(nil)

	// Act
	err := agent.HandleNonExhaustedError()

	// Assert
	assert.NoError(t: err)
}

func TestAgentRunTestTask(t *testing.T) {
	// Arrange
	mockServer := &cipherSwarmAgent.MockServer{}
	mockServer.On("GetTestTask").Return("test_task")
	agent := cipherSwarmAgent.NewAgent(mockServer)

	// Act
	task, err := agent.RunTestTask()

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "test_task", task)
	mockServer.AssertExpectations(t)
}