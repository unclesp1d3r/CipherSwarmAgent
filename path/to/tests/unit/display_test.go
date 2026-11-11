// display_test.go
package tests

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"cipherSwarmAgent"
)

func TestDisplayStartup(t *testing.T) {
	// Arrange
	display := cipherSwarmAgent.NewDisplay()

	// Act
	output := display.DisplayStartup()

	// Assert
	assert.Equal(t, "Startup message", output)
}

func TestDisplayAuthenticated(t *testing.T) {
	// Arrange
	display := cipherSwarmAgent.NewDisplay()

	// Act
	output := display.DisplayAuthenticated()

	// Assert
	assert.Equal(t, "Authentication successful", output)
}

func TestDisplayNewTask(t *testing.T) {
	// Arrange
	display := cipherSwarmAgent.NewDisplay()

	// Act
	output := display.DisplayNewTask()

	// Assert
	assert.Equal(t, "New task notification", output)
}

func TestDisplayNewAttack(t *testing.T) {
	// Arrange
	display := cipherSwarmAgent.NewDisplay()

	// Act
	output := display.DisplayNewAttack()

	// Assert
	assert.Equal(t, "New attack notification", output)
}

func TestDisplayInactive(t *testing.T) {
	// Arrange
	display := cipherSwarmAgent.NewDisplay()

	// Act
	output := display.DisplayInactive()

	// Assert
	assert.Equal(t, "Inactive state", output)
}

func TestDisplayShuttingDown(t *testing.T) {
	// Arrange
	display := cipherSwarmAgent.NewDisplay()

	// Act
	output := display.DisplayShuttingDown()

	// Assert
	assert.Equal(t, "Shutdown process", output)
}