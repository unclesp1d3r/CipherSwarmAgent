package lib

import (
	"context"
	"errors"
	"net/http"
	"testing"

	sdk "github.com/unclesp1d3r/cipherswarm-agent-sdk-go"
	"github.com/unclesp1d3r/cipherswarm-agent-sdk-go/models/components"

	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// errorHTTPClient is a stub HTTP client that always returns an error.
type errorHTTPClient struct{}

func (errorHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return nil, errors.New("http error")
}

// TestDownloadHashListError ensures downloadHashList does not panic when the
// API client returns an error.
func TestDownloadHashListError(t *testing.T) {
	// Prepare a temporary directory for hashlists.
	dir := t.TempDir()
	shared.State.HashlistPath = dir

	// Initialize the SDK client with the error HTTP client.
	SdkClient = sdk.New(sdk.WithClient(errorHTTPClient{}))
	Context = context.Background()

	attack := &components.Attack{ID: 1, HashListID: 1}

	if err := downloadHashList(attack); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestDummy(t *testing.T) {
	t.Log("Basic test structure for clientUtils.go")
}
