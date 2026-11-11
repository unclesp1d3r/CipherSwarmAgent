// file_system_mock.go
package tests

import (
	"os"
	"github.com/stretchr/testify/mock"
)

type MockFileSystem struct {
	mock.Mock
}

func (m *MockFileSystem) ReadFile(filename string) ([]byte, error) {
	args := m.Called(filename)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockFileSystem) WriteFile(filename string, data []byte) error {
	args := m.Called(filename, data)
	return args.Error(0)
}