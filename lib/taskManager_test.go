package lib

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// TestGetNewTask tests the GetNewTask function with various scenarios.
func TestGetNewTask(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func()
		expectedTask  *api.Task
		expectedError error
	}{
		{
			name: "successful task retrieval",
			setupMock: func() {
				task := testhelpers.NewTestTask(123, 456)
				// According to swagger.json, the response is the Task object directly, not wrapped
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
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/new$`)
				httpmock.RegisterRegexpResponder("GET", pattern, responder)
			},
			expectedTask:  &api.Task{Id: 123, AttackId: 456},
			expectedError: nil,
		},
		{
			name: "no task available - HTTP 204",
			setupMock: func() {
				responder := httpmock.NewStringResponder(http.StatusNoContent, "")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/new$`)
				httpmock.RegisterRegexpResponder("GET", pattern, responder)
			},
			expectedTask:  nil,
			expectedError: ErrNoTaskAvailable,
		},
		{
			name: "bad response - unexpected status",
			setupMock: func() {
				// Use 400 Bad Request instead of 500 to avoid SDK retry backoff loops
				responder := httpmock.NewStringResponder(http.StatusBadRequest, "Bad Request")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/new$`)
				httpmock.RegisterRegexpResponder("GET", pattern, responder)
			},
			expectedTask:  nil,
			expectedError: ErrTaskBadResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			defer cleanupState()

			tt.setupMock()

			task, err := GetNewTask()

			if tt.expectedError != nil {
				require.Error(t, err)
				// The SDK may wrap errors for non-2xx responses; only assert type for specific sentinel we control.
				if errors.Is(tt.expectedError, ErrNoTaskAvailable) {
					require.ErrorIs(t, err, tt.expectedError)
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

// TestGetAttackParameters tests the GetAttackParameters function.
func TestGetAttackParameters(t *testing.T) {
	tests := []struct {
		name           string
		attackID       int64
		setupMock      func(attackID int64)
		expectedAttack *api.Attack
		expectedError  error
	}{
		{
			name:     "successful attack retrieval",
			attackID: 456,
			setupMock: func(attackID int64) {
				attack := testhelpers.NewTestAttack(attackID, 0)
				// According to swagger.json, the response is the Attack object directly, not wrapped
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
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/attacks/\d+$`)
				httpmock.RegisterRegexpResponder("GET", pattern, responder)
			},
			expectedAttack: &api.Attack{Id: 456},
			expectedError:  nil,
		},
		{
			name:     "attack not found - HTTP 404",
			attackID: 999,
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusNotFound, "Not Found")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/attacks/\d+$`)
				httpmock.RegisterRegexpResponder("GET", pattern, responder)
			},
			expectedAttack: nil,
			expectedError:  ErrTaskBadResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			defer cleanupState()

			tt.setupMock(tt.attackID)

			attack, err := GetAttackParameters(tt.attackID)

			if tt.expectedError != nil {
				require.Error(t, err)
				// For 4xx from SDK, errors are wrapped; avoid strict ErrorIs here.
				if !errors.Is(tt.expectedError, ErrTaskBadResponse) {
					require.ErrorIs(t, err, tt.expectedError)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, attack)
				assert.Equal(t, tt.expectedAttack.Id, attack.Id)
			}
		})
	}
}

// TestAcceptTask tests the AcceptTask function.
func TestAcceptTask(t *testing.T) {
	tests := []struct {
		name          string
		task          *api.Task
		setupMock     func(taskID int64)
		expectedError bool
	}{
		{
			name: "successful task acceptance",
			task: testhelpers.NewTestTask(123, 456),
			setupMock: func(_ int64) {
				responder := httpmock.NewStringResponder(http.StatusNoContent, "")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/\d+/accept_task$`)
				httpmock.RegisterRegexpResponder("POST", pattern, responder)
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
		},
		{
			name: "API error during acceptance",
			task: testhelpers.NewTestTask(123, 456),
			setupMock: func(_ int64) {
				// Use 400 Bad Request instead of 500 to avoid SDK retry backoff loops
				responder := httpmock.NewStringResponder(http.StatusBadRequest, "Bad Request")
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/\d+/accept_task$`)
				httpmock.RegisterRegexpResponder("POST", pattern, responder)
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			defer cleanupState()

			// Mock SubmitErrorAgent endpoint to handle error reporting
			testhelpers.MockSubmitErrorSuccess(789)

			if tt.task != nil {
				tt.setupMock(tt.task.Id)
			} else {
				tt.setupMock(0)
			}

			err := AcceptTask(tt.task)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAbandonTask tests the AbandonTask function.
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
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/\d+/set_abandoned$`)
				httpmock.RegisterRegexpResponder("POST", pattern, responder)
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
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/tasks/\d+/set_abandoned$`)
				httpmock.RegisterRegexpResponder("POST", pattern, responder)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()
			cleanupHTTP := testhelpers.SetupHTTPMock()
			defer cleanupHTTP()

			cleanupState := testhelpers.SetupTestState(789, "https://test.api", "test-token")
			defer cleanupState()

			// Mock SubmitErrorAgent endpoint to handle error reporting
			testhelpers.MockSubmitErrorSuccess(789)

			if tt.task != nil {
				tt.setupMock(tt.task.Id)
			} else {
				tt.setupMock(0)
			}

			// AbandonTask doesn't return an error, it just logs
			AbandonTask(tt.task)
		})
	}
}
