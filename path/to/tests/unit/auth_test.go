// auth_test.go
package tests

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"cipherSwarmAgent"
)

func TestAuthenticateAgent(t *testing.T) {
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