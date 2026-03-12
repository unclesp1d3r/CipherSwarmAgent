package task

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// Package-level compiled URL patterns for test mocks.
var (
	taskNewPattern     = regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/new$`)
	attackPattern      = regexp.MustCompile(`^https?://[^/]+/api/v1/client/attacks/\d+$`)
	acceptTaskPattern  = regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/\d+/accept_task$`)
	abandonTaskPattern = regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/\d+/set_abandoned$`)
)

// newTestManager creates a Manager using the current agentstate API client.
func newTestManager() *Manager {
	return NewManager(
		agentstate.State.GetAPIClient().Tasks(),
		agentstate.State.GetAPIClient().Attacks(),
	)
}

// TestGetNewTask tests the Manager.GetNewTask method with various scenarios.
func TestGetNewTask(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		expectedTask *api.Task
		wantErr      bool
		wantErrIs    error // if non-nil, assert errors.Is(err, wantErrIs)
	}{
		{
			name: "successful task retrieval",
			setupMock: func() {
				task := testhelpers.NewTestTask(123, 456)
				jsonResponse, err := json.Marshal(task)
				if err != nil {
					panic(err)
				}
				responder := httpmock.ResponderFromResponse(&http.Response{
					Status:     http.StatusText(http.StatusOK),
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
				})
				httpmock.RegisterRegexpResponder("GET", taskNewPattern, responder)
			},
			expectedTask: &api.Task{Id: 123, AttackId: 456},
		},
		{
			name: "no task available - HTTP 204",
			setupMock: func() {
				responder := httpmock.NewStringResponder(http.StatusNoContent, "")
				httpmock.RegisterRegexpResponder("GET", taskNewPattern, responder)
			},
			wantErr:   true,
			wantErrIs: ErrNoTaskAvailable,
		},
		{
			name: "bad response - unexpected status",
			setupMock: func() {
				responder := httpmock.NewStringResponder(http.StatusBadRequest, "Bad Request")
				httpmock.RegisterRegexpResponder("GET", taskNewPattern, responder)
			},
			wantErr: true, // API client wraps 4xx as *api.APIError
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			t.Cleanup(cleanupHTTP)

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			t.Cleanup(cleanupState)

			tt.setupMock()

			mgr := newTestManager()
			task, err := mgr.GetNewTask(context.Background())

			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrIs != nil {
					require.ErrorIs(t, err, tt.wantErrIs)
				}
			} else {
				require.NoError(t, err)
				if tt.expectedTask != nil {
					require.NotNil(t, task)
					assert.Equal(t, tt.expectedTask.Id, task.Id)
					assert.Equal(t, tt.expectedTask.AttackId, task.AttackId)
				}
			}
		})
	}
}

// TestGetAttackParameters tests the Manager.GetAttackParameters method.
func TestGetAttackParameters(t *testing.T) {
	tests := []struct {
		name           string
		attackID       int64
		setupMock      func(attackID int64)
		expectedAttack *api.Attack
		wantErr        bool
		wantErrIs      error // if non-nil, assert errors.Is(err, wantErrIs)
	}{
		{
			name:     "successful attack retrieval",
			attackID: 456,
			setupMock: func(attackID int64) {
				attack := testhelpers.NewTestAttack(attackID, 0)
				jsonResponse, err := json.Marshal(attack)
				if err != nil {
					panic(err)
				}
				responder := httpmock.ResponderFromResponse(&http.Response{
					Status:     http.StatusText(http.StatusOK),
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
				})
				httpmock.RegisterRegexpResponder("GET", attackPattern, responder)
			},
			expectedAttack: &api.Attack{Id: 456},
		},
		{
			name:     "attack not found - HTTP 404",
			attackID: 999,
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusNotFound, "Not Found")
				httpmock.RegisterRegexpResponder("GET", attackPattern, responder)
			},
			wantErr: true, // API client wraps 4xx as *api.APIError
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			t.Cleanup(cleanupHTTP)

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			t.Cleanup(cleanupState)

			tt.setupMock(tt.attackID)

			mgr := newTestManager()
			attack, err := mgr.GetAttackParameters(context.Background(), tt.attackID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrIs != nil {
					require.ErrorIs(t, err, tt.wantErrIs)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, attack)
				assert.Equal(t, tt.expectedAttack.Id, attack.Id)
			}
		})
	}
}

// TestAcceptTask tests the Manager.AcceptTask method.
func TestAcceptTask(t *testing.T) {
	tests := []struct {
		name          string
		task          *api.Task
		setupMock     func(taskID int64)
		expectedError bool
		wantErrIs     error
	}{
		{
			name: "successful task acceptance",
			task: testhelpers.NewTestTask(123, 456),
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusNoContent, "")
				httpmock.RegisterRegexpResponder("POST", acceptTaskPattern, responder)
			},
			expectedError: false,
		},
		{
			name: "nil task",
			task: nil,
			setupMock: func(_ int64) {
				// No mock needed for nil task
			},
			expectedError: true,
			wantErrIs:     ErrTaskIsNil,
		},
		{
			name: "API error during acceptance",
			task: testhelpers.NewTestTask(123, 456),
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusBadRequest, "Bad Request")
				httpmock.RegisterRegexpResponder("POST", acceptTaskPattern, responder)
			},
			expectedError: true,
			wantErrIs:     ErrTaskAcceptFailed,
		},
		{
			name: "task not found - HTTP 404",
			task: testhelpers.NewTestTask(123, 456),
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusNotFound, "Not Found")
				httpmock.RegisterRegexpResponder("POST", acceptTaskPattern, responder)
			},
			expectedError: true,
			wantErrIs:     ErrTaskAcceptNotFound,
		},
		{
			name: "server error - HTTP 500",
			task: testhelpers.NewTestTask(123, 456),
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusInternalServerError, "Internal Server Error")
				httpmock.RegisterRegexpResponder("POST", acceptTaskPattern, responder)
			},
			expectedError: true,
			wantErrIs:     ErrTaskAcceptFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			t.Cleanup(cleanupHTTP)

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			t.Cleanup(cleanupState)

			// Mock SubmitErrorAgent endpoint to handle error reporting
			testhelpers.MockSubmitErrorSuccess(789)

			tt.setupMock(0) // All mocks ignore the task ID argument

			mgr := newTestManager()
			err := mgr.AcceptTask(context.Background(), tt.task)

			if tt.expectedError {
				require.Error(t, err)
				if tt.wantErrIs != nil {
					require.ErrorIs(t, err, tt.wantErrIs)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestAbandonTask tests the Manager.AbandonTask method.
func TestAbandonTask(t *testing.T) {
	tests := []struct {
		name      string
		task      *api.Task
		setupMock func(taskID int64)
	}{
		{
			name: "successful task abandonment",
			task: testhelpers.NewTestTask(123, 456),
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusNoContent, "")
				httpmock.RegisterRegexpResponder("POST", abandonTaskPattern, responder)
			},
		},
		{
			name: "nil task - should not panic",
			task: nil,
			setupMock: func(_ int64) {
				// No mock needed for nil task
			},
		},
		{
			name: "API error during abandonment - should log but not return error",
			task: testhelpers.NewTestTask(123, 456),
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusBadRequest, "Bad Request")
				httpmock.RegisterRegexpResponder("POST", abandonTaskPattern, responder)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanupHTTP := testhelpers.SetupHTTPMock()
			t.Cleanup(cleanupHTTP)

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			t.Cleanup(cleanupState)

			// Mock SubmitErrorAgent endpoint to handle error reporting
			testhelpers.MockSubmitErrorSuccess(789)

			tt.setupMock(0) // All mocks ignore the task ID argument

			mgr := newTestManager()
			// AbandonTask doesn't return an error, it just logs
			mgr.AbandonTask(context.Background(), tt.task)
		})
	}
}
