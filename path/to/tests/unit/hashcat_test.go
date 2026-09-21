// hashcat_test.go
package tests

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"cipherSwarmAgent"
)

func TestFindHashcatBinary(t *testing.T) {
	// Arrange
	hashcat := cipherSwarmAgent.NewHashcat()

	// Act
	binaryPath := hashcat.FindHashcatBinary()

	// Assert
	assert.NotEmpty(t, binaryPath)
}

func TestGetHashcatVersion(t *testing.T) {
	// Arrange
	hashcat := cipherSwarmAgent.NewHashcat()

	// Act
	version := hashcat.GetHashcatVersion()

	// Assert
	assert.NotEmpty(t, version)
}