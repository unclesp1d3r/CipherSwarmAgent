// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"fmt"
	"net/http"

	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

// NewAPIError creates a new APIError with the specified status code and message.
func NewAPIError(statusCode int, message string) *api.APIError {
	return &api.APIError{
		StatusCode: statusCode,
		Message:    message,
		Body:       fmt.Sprintf(`{"error":%q}`, message),
	}
}

// NewErrorObject creates a new APIError representing a client validation error.
// Uses 422 Unprocessable Entity as the default status code since the former
// ErrorObject type was typically used for validation errors.
func NewErrorObject(message string) *api.APIError {
	return NewAPIError(http.StatusUnprocessableEntity, message)
}

// NewSetTaskAbandonedError creates a SetTaskAbandonedError
// for testing task abandonment scenarios.
func NewSetTaskAbandonedError(state string) *api.SetTaskAbandonedError {
	return &api.SetTaskAbandonedError{
		Details: []string{state},
	}
}

// NewSetTaskAbandonedErrorWithErrorField creates a SetTaskAbandonedError
// with empty Details but a populated Error_ field for testing fallback extraction.
func NewSetTaskAbandonedErrorWithErrorField(errorMsg string) *api.SetTaskAbandonedError {
	return &api.SetTaskAbandonedError{
		Error_:  &errorMsg,
		Details: []string{},
	}
}

// NewSetTaskAbandonedErrorWithNilError creates a SetTaskAbandonedError
// with empty Details and nil Error_ for testing edge case handling.
func NewSetTaskAbandonedErrorWithNilError() *api.SetTaskAbandonedError {
	return &api.SetTaskAbandonedError{
		Error_:  nil,
		Details: []string{},
	}
}
