package lib

import (
	"context"
	stderrors "errors"

	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/apierrors"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
)

// Static errors to comply with err113 linter.
var (
	ErrCouldNotValidateCredentials = stderrors.New("could not validate credentials")
)

// handleAuthenticationError handles authentication errors from the CipherSwarm API.
// It logs detailed error information based on the type of error and returns the original error.
func handleAuthenticationError(ctx context.Context, err error) error {
	opts := apierrors.Options{
		Message:        "Error connecting to the CipherSwarm API",
		SendToServer:   false, // Auth errors don't send to server (agent not authenticated yet)
		LogAuthContext: true,
	}
	return cserrors.GetErrorHandlerNoSend().Handle(ctx, err, opts)
}

// handleConfigurationError processes configuration errors by logging them and sending critical error reports.
func handleConfigurationError(ctx context.Context, err error) error {
	opts := apierrors.Options{
		Message:      "Error getting agent configuration",
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}
	return cserrors.GetErrorHandler().Handle(ctx, err, opts)
}

// handleAPIError handles errors returned from the CipherSwarm API.
// It logs error messages and sends error reports based on the error type.
func handleAPIError(ctx context.Context, message string, err error) {
	opts := apierrors.Options{
		Message:        message,
		Severity:       api.SeverityCritical,
		SendToServer:   true,
		LogAuthContext: stderrors.Is(err, ErrCouldNotValidateCredentials),
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.GetErrorHandler().Handle(ctx, err, opts)
}

// handleHeartbeatError processes and logs errors occurring during the heartbeat operation.
func handleHeartbeatError(ctx context.Context, err error) {
	opts := apierrors.Options{
		Message:      "Error sending heartbeat",
		Severity:     api.SeverityCritical,
		SendToServer: true,
	}
	//nolint:errcheck,gosec // Error handler returns error for chaining; not needed here
	cserrors.GetErrorHandler().Handle(ctx, err, opts)
}
