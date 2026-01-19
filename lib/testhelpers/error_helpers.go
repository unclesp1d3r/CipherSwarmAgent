// Package testhelpers provides reusable test utilities and helpers for testing the CipherSwarm agent.
package testhelpers

import (
	"fmt"

	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/sdkerrors"
)

// NewErrorObject creates a new ErrorObject with the specified message.
// Wraps the error construction to make tests more readable.
func NewErrorObject(message string) *sdkerrors.ErrorObject {
	return &sdkerrors.ErrorObject{
		Error_: message,
	}
}

// NewSDKError creates a new SDKError with the specified status code and message.
// Sets other fields (Body, RawResponse) to reasonable test values.
func NewSDKError(statusCode int, message string) *sdkerrors.SDKError {
	return &sdkerrors.SDKError{
		StatusCode: statusCode,
		Message:    message,
		Body:       fmt.Sprintf(`{"error":%q}`, message),
	}
}

// NewSetTaskAbandonedError creates a SetTaskAbandonedResponseBody error
// for testing task abandonment scenarios.
func NewSetTaskAbandonedError(state string) *sdkerrors.SetTaskAbandonedResponseBody {
	return &sdkerrors.SetTaskAbandonedResponseBody{
		Details: []string{state},
	}
}

// WrapAsErrorObject wraps a standard error as an ErrorObject for testing error type assertions.
func WrapAsErrorObject(err error) error {
	if err == nil {
		return nil
	}
	return NewErrorObject(err.Error())
}

// WrapAsSDKError wraps a standard error as an SDKError for testing error type assertions.
func WrapAsSDKError(err error, statusCode int) error {
	if err == nil {
		return nil
	}
	return NewSDKError(statusCode, err.Error())
}
