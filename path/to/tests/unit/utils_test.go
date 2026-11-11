// utils_test.go
package tests

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"cipherSwarmAgent"
)

func TestReadConfigFile(t *testing.T) {
	// Arrange
	utils := cipherSwarmAgent.NewUtils()

	// Act
	config, err := utils.ReadConfigFile("test_config.json")

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, config)
}

func TestWriteConfigFile(t *testing.T) {
	// Arrange
	utils := cipherSwarmAgent.NewUtils()

	// Act
	err := utils.WriteConfigFile("test_config.json", "test_config")

	// Assert
	assert.NoError(t, err)
}