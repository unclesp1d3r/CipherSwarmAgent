package api

import (
	"encoding/json"
	"fmt"
)

// ErrorObject represents an API error object with an "error" JSON field.
// It implements the error interface and maps to the OpenAPI ErrorObject schema.
// The generated ErrorObject schema is excluded from client.gen.go (via
// exclude-schemas in config.yaml) because a struct field named "Error"
// conflicts with the Error() method required by the error interface.
// The Err field is serialized as "error" in JSON to match the API contract.
type ErrorObject struct { //nolint:errname // Name matches the OpenAPI schema
	Err                  string         `json:"error"`
	AdditionalProperties map[string]any `json:"-"`
}

var _ error = (*ErrorObject)(nil) //nolint:errcheck // compile-time interface assertion

// Error implements the error interface, returning the error message.
func (e *ErrorObject) Error() string {
	return e.Err
}

// Get returns the specified additional property and whether it was found.
func (e *ErrorObject) Get(fieldName string) (any, bool) {
	if e.AdditionalProperties != nil {
		v, ok := e.AdditionalProperties[fieldName]
		return v, ok
	}
	return nil, false
}

// Set sets the specified additional property.
func (e *ErrorObject) Set(fieldName string, value any) {
	if e.AdditionalProperties == nil {
		e.AdditionalProperties = make(map[string]any)
	}
	e.AdditionalProperties[fieldName] = value
}

// UnmarshalJSON implements custom JSON unmarshaling to handle AdditionalProperties.
func (e *ErrorObject) UnmarshalJSON(b []byte) error {
	object := make(map[string]json.RawMessage)
	err := json.Unmarshal(b, &object)
	if err != nil {
		return err
	}

	if raw, found := object["error"]; found {
		err = json.Unmarshal(raw, &e.Err)
		if err != nil {
			return fmt.Errorf("error reading 'error': %w", err)
		}
		delete(object, "error")
	}

	if len(object) != 0 {
		e.AdditionalProperties = make(map[string]any)
		for fieldName, fieldBuf := range object {
			var fieldVal any
			err := json.Unmarshal(fieldBuf, &fieldVal)
			if err != nil {
				return fmt.Errorf("error unmarshaling field %s: %w", fieldName, err)
			}
			e.AdditionalProperties[fieldName] = fieldVal
		}
	}
	return nil
}

// MarshalJSON implements custom JSON marshaling to handle AdditionalProperties.
func (e *ErrorObject) MarshalJSON() ([]byte, error) {
	var err error
	object := make(map[string]json.RawMessage)

	object["error"], err = json.Marshal(e.Err)
	if err != nil {
		return nil, fmt.Errorf("error marshaling 'error': %w", err)
	}

	for fieldName, field := range e.AdditionalProperties {
		object[fieldName], err = json.Marshal(field)
		if err != nil {
			return nil, fmt.Errorf("error marshaling '%s': %w", fieldName, err)
		}
	}
	return json.Marshal(object)
}

// APIError represents an HTTP error returned by the CipherSwarm API.
// It serves as the unified internal error type for 4xx and 5xx API responses.
// For the API error object model (JSON "error" field), see ErrorObject.
type APIError struct { //nolint:revive // Name is intentional for clarity across packages
	StatusCode int
	Message    string
	Body       string
}

var _ error = (*APIError)(nil) //nolint:errcheck // compile-time interface assertion

// Error returns a formatted error string including the status code and body.
func (e *APIError) Error() string {
	body := ""
	if e.Body != "" {
		body = "\n" + e.Body
	}

	return fmt.Sprintf("%s: Status %d%s", e.Message, e.StatusCode, body)
}

// SetTaskAbandonedError represents a 422 error when abandoning a task.
// It maps to the 422 response schema for the SetTaskAbandoned endpoint.
type SetTaskAbandonedError struct {
	Details []string `json:"details"`
	Error_  *string  `json:"error"` //nolint:revive // Underscore avoids collision with Error() method
}

var _ error = (*SetTaskAbandonedError)(nil) //nolint:errcheck // compile-time interface assertion

// Error returns a JSON representation of the error.
// Falls back to a descriptive string if JSON marshaling fails.
func (e *SetTaskAbandonedError) Error() string {
	data, err := json.Marshal(e)
	if err != nil {
		errStr := "<nil>"
		if e.Error_ != nil {
			errStr = *e.Error_
		}

		return fmt.Sprintf("SetTaskAbandonedError{error: %s, details: %v}", errStr, e.Details)
	}

	return string(data)
}

// Severity is a type alias for the generated SubmitErrorAgentJSONBodySeverity.
// This provides named constants for error severity levels.
type Severity = SubmitErrorAgentJSONBodySeverity

// Severity levels for error reporting.
const (
	SeverityCritical Severity = Critical
	SeverityWarning  Severity = Warning
	SeverityInfo     Severity = Info
	SeverityMajor    Severity = Major
	SeverityMinor    Severity = Minor
	SeverityFatal    Severity = Fatal
)

// SendHeartbeat200State constants for heartbeat response state values.
// The generated code defines the type but not constants.
// Note: The swagger enum only includes "pending", "stopped", and "error".
// "active" is described in the API prose but is not part of the response enum;
// it may not be returned by current server versions.
const (
	StatePending SendHeartbeat200State = "pending"
	StateActive  SendHeartbeat200State = "active" // Not in swagger enum; see block comment above
	StateError   SendHeartbeat200State = "error"
	StateStopped SendHeartbeat200State = "stopped"
)
