// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/jarcoal/httpmock"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/operations"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
)

// mustMarshal marshals v to JSON or panics in tests if it fails.
func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// SetupHTTPMock initializes httpmock, activates it, and returns a cleanup function.
// This ensures consistent setup/teardown across tests.
func SetupHTTPMock() func() {
	httpmock.Activate()
	return func() {
		httpmock.DeactivateAndReset()
	}
}

// SetupHTTPMockForClient initializes httpmock for a custom http.Client and returns a cleanup function.
// This should be used when the SDK uses a custom http.Client. The client should be passed
// to the SDK via WithClient option after activating httpmock.
func SetupHTTPMockForClient(client *http.Client) func() {
	httpmock.ActivateNonDefault(client)
	return func() {
		httpmock.DeactivateAndReset()
	}
}

// MockAuthenticationSuccess registers a mock responder for the authentication endpoint
// that returns a successful authentication response with the provided agent ID.
// Uses a regex pattern to match any HTTP scheme and host.
// Note: The SDK uses GET for authentication, not POST.
func MockAuthenticationSuccess(agentID int64) {
	authResponse := operations.AuthenticateResponseBody{
		Authenticated: true,
		AgentID:       agentID,
	}
	jsonResponse := mustMarshal(authResponse)
	responder := httpmock.ResponderFromResponse(&http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
	})
	pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/authenticate$`)
	httpmock.RegisterRegexpResponder("GET", pattern, responder)
	httpmock.RegisterRegexpResponder("POST", pattern, responder) // Register both for compatibility
}

// MockAuthenticationFailure registers a mock responder for authentication
// that returns an error response with the specified status code and error message.
// Uses a regex pattern to match any HTTP scheme and host.
// Note: The SDK uses GET for authentication, not POST.
func MockAuthenticationFailure(statusCode int, errorMessage string) {
	errorResponse := map[string]any{
		"authenticated": false,
		"error":         errorMessage,
	}
	jsonResponse := mustMarshal(errorResponse)
	responder := httpmock.ResponderFromResponse(&http.Response{
		Status:     http.StatusText(statusCode),
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
	})
	pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/authenticate$`)
	httpmock.RegisterRegexpResponder("GET", pattern, responder)
	httpmock.RegisterRegexpResponder("POST", pattern, responder) // Register both for compatibility
}

// MockConfigurationResponse registers a mock responder for the configuration endpoint
// that returns the provided configuration.
// Uses a regex pattern to match any HTTP scheme and host.
func MockConfigurationResponse(config operations.GetConfigurationResponseBody) {
	jsonResponse := mustMarshal(config)
	responder := httpmock.ResponderFromResponse(&http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
	})
	pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/configuration$`)
	httpmock.RegisterRegexpResponder("GET", pattern, responder)
}

// MockHeartbeatResponse registers a mock responder for heartbeat endpoint
// that returns the specified agent state.
// Accepts agentID and uses a regex pattern to match the path with the numeric agent ID.
// According to swagger.json, the endpoint is /api/v1/client/agents/{id}/heartbeat.
func MockHeartbeatResponse(agentID int64, state operations.State) {
	stateResponse := operations.SendHeartbeatResponseBody{
		State: state,
	}
	jsonResponse := mustMarshal(stateResponse)
	responder := httpmock.ResponderFromResponse(&http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
	})
	// Use regex to match the numeric agent ID in the path
	// According to swagger.json, the path is /api/v1/client/agents/{id}/heartbeat
	pattern1 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/client/agents/%d/heartbeat$`, agentID))
	pattern2 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/agents/%d/heartbeat$`, agentID))
	httpmock.RegisterRegexpResponder("POST", pattern1, responder)
	httpmock.RegisterRegexpResponder("POST", pattern2, responder) // Register both for compatibility
}

// MockAPIError is a generic helper to mock API errors for any endpoint,
// useful for testing error handling across different API calls.
// The endpoint parameter should be a regex pattern string (will be compiled to *regexp.Regexp).
// Registers responders for multiple HTTP methods to handle different SDK implementations.
func MockAPIError(endpoint string, statusCode int, sdkError sdkerrors.SDKError) {
	errorResponse := map[string]any{
		"error":   sdkError.Message,
		"code":    sdkError.StatusCode,
		"details": nil,
	}
	jsonResponse := mustMarshal(errorResponse)
	responder := httpmock.ResponderFromResponse(&http.Response{
		Status:     http.StatusText(statusCode),
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
	})
	pattern := regexp.MustCompile(endpoint)
	httpmock.RegisterRegexpResponder("GET", pattern, responder)
	httpmock.RegisterRegexpResponder("POST", pattern, responder)
	httpmock.RegisterRegexpResponder("PUT", pattern, responder)
	httpmock.RegisterRegexpResponder("PATCH", pattern, responder)
}

// MockHeartbeatNoContent registers a mock responder for heartbeat endpoint
// that returns HTTP 204 No Content (indicating successful heartbeat with no state change).
// According to swagger.json, the endpoint is /api/v1/client/agents/{id}/heartbeat.
func MockHeartbeatNoContent(agentID int64) {
	responder := httpmock.NewStringResponder(http.StatusNoContent, "")
	// According to swagger.json, the path is /api/v1/client/agents/{id}/heartbeat
	pattern1 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/client/agents/%d/heartbeat$`, agentID))
	pattern2 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/agents/%d/heartbeat$`, agentID))
	httpmock.RegisterRegexpResponder("POST", pattern1, responder)
	httpmock.RegisterRegexpResponder("POST", pattern2, responder) // Register both for compatibility
}

// MockUpdateAgentSuccess registers a mock responder for POST /api/v1/client/agents/{id}
// that returns a successful UpdateAgentResponse with the provided agent data.
// According to swagger.json, the endpoint is /api/v1/client/agents/{id}.
func MockUpdateAgentSuccess(agentID int64, agent components.Agent) {
	responseBody := map[string]any{
		"agent": agent,
	}
	jsonResponse := mustMarshal(responseBody)
	responder := httpmock.ResponderFromResponse(&http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
	})
	pattern1 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/client/agents/%d$`, agentID))
	pattern2 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/agents/%d$`, agentID))
	httpmock.RegisterRegexpResponder("POST", pattern1, responder)
	httpmock.RegisterRegexpResponder("POST", pattern2, responder) // Register both for compatibility
	httpmock.RegisterRegexpResponder("PUT", pattern1, responder)
	httpmock.RegisterRegexpResponder("PUT", pattern2, responder)
	httpmock.RegisterRegexpResponder("PATCH", pattern1, responder)
	httpmock.RegisterRegexpResponder("PATCH", pattern2, responder)
}

// MockSendStatusSuccess registers a mock responder for POST /api/v1/client/tasks/{id}/submit_status
// that returns HTTP 204 No Content.
// According to swagger.json, the endpoint is /api/v1/client/tasks/{id}/submit_status.
func MockSendStatusSuccess(taskID int64) {
	responder := httpmock.NewStringResponder(http.StatusNoContent, "")
	pattern1 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/client/tasks/%d/submit_status$`, taskID))
	pattern2 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/tasks/%d/send_status$`, taskID))
	httpmock.RegisterRegexpResponder("POST", pattern1, responder)
	httpmock.RegisterRegexpResponder("POST", pattern2, responder) // Register both for compatibility
}

// MockSendStatusStale registers a mock responder for send status
// that returns HTTP 202 Accepted (indicating stale status).
// According to swagger.json, the endpoint is /api/v1/client/tasks/{id}/submit_status.
func MockSendStatusStale(taskID int64) {
	responder := httpmock.NewStringResponder(http.StatusAccepted, "")
	pattern1 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/client/tasks/%d/submit_status$`, taskID))
	pattern2 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/tasks/%d/send_status$`, taskID))
	httpmock.RegisterRegexpResponder("POST", pattern1, responder)
	httpmock.RegisterRegexpResponder("POST", pattern2, responder) // Register both for compatibility
}

// MockSendCrackSuccess registers a mock responder for POST /api/v1/client/tasks/{id}/submit_crack
// that returns HTTP 200 OK.
// According to swagger.json, the endpoint is /api/v1/client/tasks/{id}/submit_crack.
func MockSendCrackSuccess(taskID int64) {
	responder := httpmock.NewStringResponder(http.StatusOK, "")
	pattern1 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/client/tasks/%d/submit_crack$`, taskID))
	pattern2 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/tasks/%d/send_crack$`, taskID))
	httpmock.RegisterRegexpResponder("POST", pattern1, responder)
	httpmock.RegisterRegexpResponder("POST", pattern2, responder) // Register both for compatibility
}

// MockSendCrackComplete registers a mock responder for send crack
// that returns HTTP 204 No Content (indicating hashlist completed).
// According to swagger.json, the endpoint is /api/v1/client/tasks/{id}/submit_crack.
func MockSendCrackComplete(taskID int64) {
	responder := httpmock.NewStringResponder(http.StatusNoContent, "")
	pattern1 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/client/tasks/%d/submit_crack$`, taskID))
	pattern2 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/tasks/%d/send_crack$`, taskID))
	httpmock.RegisterRegexpResponder("POST", pattern1, responder)
	httpmock.RegisterRegexpResponder("POST", pattern2, responder) // Register both for compatibility
}

// MockSubmitErrorSuccess registers a mock responder for POST /api/v1/client/agents/{id}/submit_error
// that returns HTTP 200 OK with a proper JSON response body.
// Note: The SDK uses /api/v1/client/agents/{id}/submit_error path.
// Returns 204 No Content to avoid infinite recursion when handleSendError processes errors.
func MockSubmitErrorSuccess(agentID int64) {
	// Use 204 No Content to signal success without a body, which prevents the SDK from
	// treating it as an error and triggering infinite recursion in handleSendError.
	responder := httpmock.NewStringResponder(http.StatusNoContent, "")
	// Register both paths for compatibility
	pattern1 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/client/agents/%d/submit_error$`, agentID))
	pattern2 := regexp.MustCompile(fmt.Sprintf(`^https?://[^/]+/api/v1/agents/%d/submit_error$`, agentID))
	httpmock.RegisterRegexpResponder("POST", pattern1, responder)
	httpmock.RegisterRegexpResponder("POST", pattern2, responder)
}

// GetSubmitErrorCallCount returns the number of times the submit_error endpoint was called
// for the given agent ID. This handles the different key formats that httpmock uses.
func GetSubmitErrorCallCount(agentID int64, baseURL string) int {
	info := httpmock.GetCallCountInfo()
	var callCount int
	// Check both regex pattern format and actual URL format
	regexKey := fmt.Sprintf("POST =~^https?://[^/]+/api/v1/client/agents/%d/submit_error$", agentID)
	urlKey := fmt.Sprintf("POST %s/api/v1/client/agents/%d/submit_error", baseURL, agentID)
	callCount += info[regexKey]
	callCount += info[urlKey]
	return callCount
}

// MockConfigurationError registers a mock responder for configuration endpoint
// that returns an error response.
func MockConfigurationError(statusCode int, errorMsg string) {
	errorResponse := map[string]any{
		"error": errorMsg,
	}
	jsonResponse := mustMarshal(errorResponse)
	responder := httpmock.ResponderFromResponse(&http.Response{
		Status:     http.StatusText(statusCode),
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       httpmock.NewRespBodyFromString(string(jsonResponse)),
	})
	pattern := regexp.MustCompile(`^https?://[^/]+/api/v1/client/configuration$`)
	httpmock.RegisterRegexpResponder("GET", pattern, responder)
}
