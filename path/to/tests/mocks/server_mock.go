// server_mock.go
package tests

import (
	"net/http"
	"github.com/stretchr/testify/mock"
)

type MockServer struct {
	mock.Mock
}

func (m *MockServer) AuthenticateAgent() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockServer) GetTestTask() string {
	args := m.Called()
	return args.String(0)
}