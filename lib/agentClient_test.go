package lib

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

// stubGetDevicesList replaces getDevicesListFn with a stub that returns mock devices.
// Returns a cleanup function to restore the original function.
func stubGetDevicesList() func() {
	original := getDevicesListFn
	getDevicesListFn = func(_ context.Context) ([]string, error) {
		return []string{"CPU", "GPU0"}, nil
	}
	return func() {
		getDevicesListFn = original
	}
}

// TestAuthenticateAgent tests the AuthenticateAgent function with various scenarios.
func TestAuthenticateAgent(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(agentID int64)
		expectedError error
		expectedID    int64
	}{
		{
			name: "successful authentication",
			setupMock: func(agentID int64) {
				testhelpers.MockAuthenticationSuccess(agentID)
			},
			expectedError: nil,
			expectedID:    123,
		},
		{
			name: "authentication failure - not authenticated",
			setupMock: func(_ int64) {
				authResponse := map[string]any{
					"authenticated": false,
				}
				jsonResponse, err := json.Marshal(authResponse)
				if err != nil {
					panic(err)
				}
				responder := httpmock.ResponderFromResponse(&http.Response{
					Status:     http.StatusText(http.StatusOK),
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
				})
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/authenticate$`)
				httpmock.RegisterRegexpResponder("GET", pattern, responder)
				httpmock.RegisterRegexpResponder("POST", pattern, responder) // Register both for compatibility
			},
			expectedError: ErrAuthenticationFailed,
			expectedID:    0,
		},
		{
			name: "ErrorObject handling",
			setupMock: func(_ int64) {
				testhelpers.MockAuthenticationFailure(http.StatusUnauthorized, "authentication failed")
			},
			expectedError: &api.APIError{},
			expectedID:    0,
		},
		{
			name: "APIError handling",
			setupMock: func(_ int64) {
				// Using 400 Bad Request to test client error handling.
				apiErr := testhelpers.NewAPIError(http.StatusBadRequest, "bad request")
				testhelpers.MockAPIError(`^https?://[^/]+/api/v1/client/authenticate$`, http.StatusBadRequest, *apiErr)
			},
			expectedError: &api.APIError{},
			expectedID:    0,
		},
		{
			name: "nil response handling",
			setupMock: func(_ int64) {
				// Mock a response that returns nil object
				responder := httpmock.ResponderFromResponse(&http.Response{
					Status:     http.StatusText(http.StatusOK),
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       httpmock.NewRespBodyFromString(`{}`),
				})
				pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/authenticate$`)
				httpmock.RegisterRegexpResponder("GET", pattern, responder)
				httpmock.RegisterRegexpResponder("POST", pattern, responder) // Register both for compatibility
			},
			expectedError: ErrAuthenticationFailed,
			expectedID:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(testhelpers.SetupHTTPMock())
			t.Cleanup(testhelpers.SetupTestState(0, "https://test.api", "test-token"))

			tt.setupMock(123)

			err := AuthenticateAgent(context.Background())

			if tt.expectedError == nil {
				require.NoError(t, err)
				require.Equal(t, int64(123), agentstate.State.AgentID)
			} else {
				require.Error(t, err)
				// Check error type if it's an API error type, otherwise just verify error was returned
				var ae *api.APIError
				if errors.As(tt.expectedError, &ae) {
					testhelpers.AssertErrorType(t, err, tt.expectedError)
				}
			}
		})
	}
}

// TestGetAgentConfiguration tests the GetAgentConfiguration function.
func TestGetAgentConfiguration(t *testing.T) {
	// Stub setNativeHashcatPath to avoid actual file system operations
	originalFn := setNativeHashcatPathFn
	t.Cleanup(func() {
		setNativeHashcatPathFn = originalFn
	})
	setNativeHashcatPathFn = func(_ context.Context) error {
		return nil // No-op for tests
	}

	tests := []struct {
		name             string
		setupMock        func()
		useNativeHashcat bool
		expectedError    error
	}{
		{
			name: "successful configuration retrieval with native hashcat disabled",
			setupMock: func() {
				config := testhelpers.NewTestAgentConfiguration(false)
				testhelpers.MockConfigurationResponse(config)
			},
			useNativeHashcat: false,
			expectedError:    nil,
		},
		{
			name: "successful configuration with native hashcat enabled",
			setupMock: func() {
				config := testhelpers.NewTestAgentConfiguration(true)
				testhelpers.MockConfigurationResponse(config)
			},
			useNativeHashcat: true,
			expectedError:    nil,
		},
		{
			name: "configuration error with ErrorObject",
			setupMock: func() {
				testhelpers.MockConfigurationError(http.StatusBadRequest, "bad request")
				testhelpers.MockSubmitErrorSuccess(123) // Mock submit_error endpoint
			},
			expectedError: &api.APIError{}, // API returns APIError for error responses
		},
		{
			name: "configuration error with APIError",
			setupMock: func() {
				// Use 400 Bad Request to test client error handling.
				apiErr := testhelpers.NewAPIError(http.StatusBadRequest, "bad request")
				testhelpers.MockAPIError(`^https?://[^/]+/api/v1/client/configuration$`, http.StatusBadRequest, *apiErr)
				testhelpers.MockSubmitErrorSuccess(123) // Mock submit_error endpoint
			},
			expectedError: &api.APIError{},
		},
		{
			name: "empty response handling",
			setupMock: func() {
				// Mock a response that returns empty config object
				// When the client parses {} successfully, it creates an empty struct (not nil)
				// So this test verifies that empty config is handled gracefully
				emptyConfig := testhelpers.TestAgentConfiguration{
					APIVersion: 0,
					Config:     api.AdvancedAgentConfiguration{},
				}
				testhelpers.MockConfigurationResponse(emptyConfig)
			},
			expectedError:    nil, // Empty config is valid, just uses defaults
			useNativeHashcat: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(testhelpers.SetupHTTPMock())
			t.Cleanup(testhelpers.SetupTestState(123, "https://test.api", "test-token"))

			tt.setupMock()

			err := GetAgentConfiguration(context.Background())

			if tt.expectedError == nil {
				require.NoError(t, err)
				require.Equal(t, tt.useNativeHashcat, Configuration.Config.UseNativeHashcat)
			} else {
				require.Error(t, err)
				testhelpers.AssertErrorType(t, err, tt.expectedError)
			}
		})
	}
}

// TestUpdateAgentMetadata tests the UpdateAgentMetadata function.
func TestUpdateAgentMetadata(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(agentID int64)
		expectedError bool
		expectBadResp bool
	}{
		{
			name: "successful metadata update",
			setupMock: func(agentID int64) {
				agent := testhelpers.NewTestAgent(agentID, "test-host")
				testhelpers.MockUpdateAgentSuccess(agentID, agent)
			},
			expectedError: false,
			expectBadResp: false,
		},
		{
			name: "API error with ErrorObject",
			setupMock: func(_ int64) {
				apiErr := testhelpers.NewAPIError(http.StatusBadRequest, "bad request")
				// According to swagger.json, the endpoint is /api/v1/client/agents/{id}
				testhelpers.MockAPIError(`^https?://[^/]+/api/v1/client/agents/\d+$`, http.StatusBadRequest, *apiErr)
			},
			expectedError: true,
			expectBadResp: false,
		},
		{
			name: "bad response - nil agent",
			setupMock: func(agentID int64) {
				agent := api.Agent{
					Id:              agentID,
					HostName:        "",
					ClientSignature: "",
					OperatingSystem: "",
					Devices:         []string{},
				}
				testhelpers.MockUpdateAgentSuccess(agentID, agent)
			},
			expectedError: false, // Empty agent is valid, not an error
			expectBadResp: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(testhelpers.SetupHTTPMock())
			t.Cleanup(testhelpers.SetupTestState(123, "https://test.api", "test-token"))

			// Stub getDevicesList to avoid requiring hashcat binary
			t.Cleanup(stubGetDevicesList())

			tt.setupMock(123)

			err := UpdateAgentMetadata(context.Background())

			if tt.expectedError {
				require.Error(t, err, "Expected an error but got nil")
				if tt.expectBadResp {
					require.Contains(t, err.Error(), ErrBadResponse.Error())
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestSendHeartBeat tests the SendHeartBeat function.
func TestSendHeartBeat(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(agentID int64)
		expectedState *api.SendHeartbeat200State
		expectedError bool
	}{
		{
			name: "heartbeat with no content response",
			setupMock: func(agentID int64) {
				testhelpers.MockHeartbeatNoContent(agentID)
			},
			expectedState: nil,
			expectedError: false,
		},
		{
			name: "heartbeat with state response",
			setupMock: func(agentID int64) {
				testhelpers.MockHeartbeatResponse(agentID, api.StatePending)
			},
			expectedState: func() *api.SendHeartbeat200State {
				s := api.StatePending
				return &s
			}(),
			expectedError: false,
		},
		{
			name: "heartbeat with StateStopped",
			setupMock: func(agentID int64) {
				testhelpers.MockHeartbeatResponse(agentID, api.StateStopped)
			},
			expectedState: func() *api.SendHeartbeat200State {
				s := api.StateStopped
				return &s
			}(),
			expectedError: false,
		},
		{
			name: "heartbeat with StateError",
			setupMock: func(agentID int64) {
				testhelpers.MockHeartbeatResponse(agentID, api.StateError)
			},
			expectedState: func() *api.SendHeartbeat200State {
				s := api.StateError
				return &s
			}(),
			expectedError: false,
		},
		{
			name: "heartbeat error with ErrorObject",
			setupMock: func(_ int64) {
				apiErr := testhelpers.NewAPIError(http.StatusBadRequest, "bad request")
				testhelpers.MockAPIError(`^https?://[^/]+/api/v1/agents/\d+/heartbeat$`, http.StatusBadRequest, *apiErr)
			},
			expectedState: nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(testhelpers.SetupHTTPMock())
			t.Cleanup(testhelpers.SetupTestState(123, "https://test.api", "test-token"))

			tt.setupMock(123)

			state, err := SendHeartBeat(context.Background())
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.expectedState == nil {
				require.Nil(t, state)
			} else {
				require.NotNil(t, state)
				require.Equal(t, *tt.expectedState, *state)
			}
		})
	}
}

// TestHandleStateResponse tests the handleStateResponse function.
func TestHandleStateResponse(t *testing.T) {
	tests := []struct {
		name     string
		response *struct {
			State api.SendHeartbeat200State `json:"state"`
		}
		expectedState *api.SendHeartbeat200State
	}{
		{
			name:          "nil response",
			response:      nil,
			expectedState: nil,
		},
		{
			name: "StatePending",
			response: &struct {
				State api.SendHeartbeat200State `json:"state"`
			}{
				State: api.StatePending,
			},
			expectedState: func() *api.SendHeartbeat200State {
				s := api.StatePending
				return &s
			}(),
		},
		{
			name: "StateStopped",
			response: &struct {
				State api.SendHeartbeat200State `json:"state"`
			}{
				State: api.StateStopped,
			},
			expectedState: func() *api.SendHeartbeat200State {
				s := api.StateStopped
				return &s
			}(),
		},
		{
			name: "StateError",
			response: &struct {
				State api.SendHeartbeat200State `json:"state"`
			}{
				State: api.StateError,
			},
			expectedState: func() *api.SendHeartbeat200State {
				s := api.StateError
				return &s
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(testhelpers.SetupTestState(123, "https://test.api", "test-token"))

			result := handleStateResponse(tt.response)

			if tt.expectedState == nil {
				require.Nil(t, result)
			} else {
				require.NotNil(t, result)
				require.Equal(t, *tt.expectedState, *result)
			}
		})
	}
}

// TestMapConfiguration tests the mapConfiguration function with various pointer combinations.
func TestMapConfiguration(t *testing.T) {
	tests := []struct {
		name             string
		apiVersion       int
		config           api.AdvancedAgentConfiguration
		benchmarksNeeded bool
		expected         agentConfiguration
	}{
		{
			name:             "all nil pointers",
			apiVersion:       1,
			benchmarksNeeded: false,
			config: api.AdvancedAgentConfiguration{
				UseNativeHashcat:    nil,
				AgentUpdateInterval: nil,
				BackendDevice:       nil,
				OpenclDevices:       nil,
			},
			expected: agentConfiguration{
				APIVersion:       1,
				BenchmarksNeeded: false,
				Config: agentConfig{
					UseNativeHashcat:    false,
					AgentUpdateInterval: defaultAgentUpdateInterval,
					BackendDevices:      "",
					OpenCLDevices:       "",
				},
			},
		},
		{
			name:             "all non-nil pointers",
			apiVersion:       1,
			benchmarksNeeded: true,
			config: api.AdvancedAgentConfiguration{
				UseNativeHashcat:    new(true),
				AgentUpdateInterval: new(600),
				BackendDevice:       new("OpenCL"),
				OpenclDevices:       new("1,2"),
			},
			expected: agentConfiguration{
				APIVersion:       1,
				BenchmarksNeeded: true,
				Config: agentConfig{
					UseNativeHashcat:    true,
					AgentUpdateInterval: 600,
					BackendDevices:      "OpenCL",
					OpenCLDevices:       "1,2",
				},
			},
		},
		{
			name:             "mixed nil and non-nil pointers",
			apiVersion:       1,
			benchmarksNeeded: false,
			config: api.AdvancedAgentConfiguration{
				UseNativeHashcat:    new(true),
				AgentUpdateInterval: nil,
				BackendDevice:       nil,
				OpenclDevices:       new("1"),
			},
			expected: agentConfiguration{
				APIVersion:       1,
				BenchmarksNeeded: false,
				Config: agentConfig{
					UseNativeHashcat:    true,
					AgentUpdateInterval: defaultAgentUpdateInterval,
					BackendDevices:      "",
					OpenCLDevices:       "1",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapConfiguration(tt.apiVersion, tt.config, tt.benchmarksNeeded, nil, nil, nil)
			require.Equal(t, tt.expected.APIVersion, result.APIVersion)
			require.Equal(t, tt.expected.BenchmarksNeeded, result.BenchmarksNeeded)
			require.Equal(t, tt.expected.Config.UseNativeHashcat, result.Config.UseNativeHashcat)
			require.Equal(t, tt.expected.Config.AgentUpdateInterval, result.Config.AgentUpdateInterval)
			require.Equal(t, tt.expected.Config.BackendDevices, result.Config.BackendDevices)
			require.Equal(t, tt.expected.Config.OpenCLDevices, result.Config.OpenCLDevices)
		})
	}
}

// TestMapConfiguration_RecommendedSettings tests that server-recommended values
// are correctly mapped into agentConfiguration.
func TestMapConfiguration_RecommendedSettings(t *testing.T) {
	config := api.AdvancedAgentConfiguration{}
	timeouts := &RecommendedTimeouts{
		ConnectTimeout: 15,
		ReadTimeout:    45,
		WriteTimeout:   15,
		RequestTimeout: 90,
	}
	retry := &RecommendedRetry{
		MaxAttempts:  5,
		InitialDelay: 2,
		MaxDelay:     60,
	}
	cb := &RecommendedCircuitBreaker{
		FailureThreshold: 10,
		Timeout:          60,
	}

	result := mapConfiguration(1, config, false, timeouts, retry, cb)

	require.NotNil(t, result.RecommendedTimeouts)
	require.Equal(t, 15, result.RecommendedTimeouts.ConnectTimeout)
	require.Equal(t, 45, result.RecommendedTimeouts.ReadTimeout)
	require.Equal(t, 15, result.RecommendedTimeouts.WriteTimeout)
	require.Equal(t, 90, result.RecommendedTimeouts.RequestTimeout)

	require.NotNil(t, result.RecommendedRetry)
	require.Equal(t, 5, result.RecommendedRetry.MaxAttempts)
	require.Equal(t, 2, result.RecommendedRetry.InitialDelay)
	require.Equal(t, 60, result.RecommendedRetry.MaxDelay)

	require.NotNil(t, result.RecommendedCircuitBreaker)
	require.Equal(t, 10, result.RecommendedCircuitBreaker.FailureThreshold)
	require.Equal(t, 60, result.RecommendedCircuitBreaker.Timeout)
}

// TestMapConfiguration_NilRecommendedSettings verifies nil pointers are preserved.
func TestMapConfiguration_NilRecommendedSettings(t *testing.T) {
	config := api.AdvancedAgentConfiguration{}
	result := mapConfiguration(1, config, false, nil, nil, nil)

	require.Nil(t, result.RecommendedTimeouts)
	require.Nil(t, result.RecommendedRetry)
	require.Nil(t, result.RecommendedCircuitBreaker)
}

// TestUnwrapOr tests the UnwrapOr generic utility function.
func TestUnwrapOr(t *testing.T) {
	t.Run("nil pointer returns default", func(t *testing.T) {
		var p *string
		require.Equal(t, "default", UnwrapOr(p, "default"))
	})

	t.Run("non-nil pointer returns value", func(t *testing.T) {
		s := "hello"
		require.Equal(t, "hello", UnwrapOr(&s, "default"))
	})

	t.Run("nil int pointer returns default", func(t *testing.T) {
		var p *int
		require.Equal(t, 42, UnwrapOr(p, 42))
	})

	t.Run("non-nil int pointer returns value", func(t *testing.T) {
		v := 7
		require.Equal(t, 7, UnwrapOr(&v, 42))
	})

	t.Run("nil bool pointer returns default", func(t *testing.T) {
		var p *bool
		require.True(t, UnwrapOr(p, true))
	})

	t.Run("non-nil bool pointer returns value", func(t *testing.T) {
		v := false
		require.False(t, UnwrapOr(&v, true))
	})

	t.Run("zero value pointer returns zero not default", func(t *testing.T) {
		v := 0
		require.Equal(t, 0, UnwrapOr(&v, 99))
	})
}

// TestLogHeartbeatSent tests the logHeartbeatSent function.
func TestLogHeartbeatSent(t *testing.T) {
	tests := []struct {
		name           string
		extraDebugging bool
	}{
		{
			name:           "ExtraDebugging enabled",
			extraDebugging: true,
		},
		{
			name:           "ExtraDebugging disabled",
			extraDebugging: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(testhelpers.SetupTestState(123, "https://test.api", "test-token"))

			// Set initial state
			agentstate.State.ExtraDebugging = tt.extraDebugging
			agentstate.State.SetJobCheckingStopped(true)

			// Call logHeartbeatSent - should not panic
			logHeartbeatSent()

			// Verify JobCheckingStopped is set to false
			require.False(t, agentstate.State.GetJobCheckingStopped(), "JobCheckingStopped should be set to false")
		})
	}
}
