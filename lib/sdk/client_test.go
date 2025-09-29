package sdk

import (
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		token       string
		expectError bool
	}{
		{
			name:        "valid parameters",
			baseURL:     "https://api.example.com",
			token:       "test-token",
			expectError: false,
		},
		{
			name:        "empty baseURL",
			baseURL:     "",
			token:       "test-token",
			expectError: true,
		},
		{
			name:        "empty token",
			baseURL:     "https://api.example.com",
			token:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.baseURL, tt.token)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if client == nil {
				t.Errorf("expected client but got nil")
				return
			}

			if client.GetBaseURL() != tt.baseURL {
				t.Errorf("expected baseURL %s, got %s", tt.baseURL, client.GetBaseURL())
			}

			if client.GetToken() != tt.token {
				t.Errorf("expected token %s, got %s", tt.token, client.GetToken())
			}

			if client.GetHTTPClient() == nil {
				t.Errorf("expected HTTP client but got nil")
			}
		})
	}
}

func TestClientMethods(t *testing.T) {
	client, err := NewClient("https://api.example.com", "test-token")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Test SetTimeout
	newTimeout := 60 * time.Second
	client.SetTimeout(newTimeout)

	if client.httpClient.Timeout != newTimeout {
		t.Errorf("expected timeout %v, got %v", newTimeout, client.httpClient.Timeout)
	}

	// Test GetHTTPClient
	httpClient := client.GetHTTPClient()
	if httpClient == nil {
		t.Errorf("expected HTTP client but got nil")
	}

	if httpClient != client.httpClient {
		t.Errorf("GetHTTPClient returned different client instance")
	}
}
