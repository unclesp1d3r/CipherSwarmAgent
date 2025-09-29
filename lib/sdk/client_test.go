package sdk

import (
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name      string
		baseURL   string
		token     string
		wantError bool
	}{
		{
			name:      "valid parameters",
			baseURL:   "https://api.example.com",
			token:     "test-token",
			wantError: false,
		},
		{
			name:      "empty baseURL",
			baseURL:   "",
			token:     "test-token",
			wantError: true,
		},
		{
			name:      "empty token",
			baseURL:   "https://api.example.com",
			token:     "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.baseURL, tt.token)
			if tt.wantError {
				if err == nil {
					t.Errorf("NewClient() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("NewClient() unexpected error: %v", err)
				return
			}
			if client.GetBaseURL() != tt.baseURL {
				t.Errorf("NewClient() baseURL = %v, want %v", client.GetBaseURL(), tt.baseURL)
			}
			if client.GetToken() != tt.token {
				t.Errorf("NewClient() token = %v, want %v", client.GetToken(), tt.token)
			}
		})
	}
}

func TestNewClientWithDefaults(t *testing.T) {
	client, err := NewClient("https://api.example.com", "test-token")
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	// Check default timeout
	if client.httpClient.Timeout != DefaultTimeout {
		t.Errorf("NewClient() timeout = %v, want %v", client.httpClient.Timeout, DefaultTimeout)
	}

	// Check default retry config
	retryConfig := client.GetRetryConfig()
	if retryConfig.MaxRetries != DefaultMaxRetries {
		t.Errorf("NewClient() MaxRetries = %v, want %v", retryConfig.MaxRetries, DefaultMaxRetries)
	}
	if retryConfig.Backoff != DefaultRetryBackoff {
		t.Errorf("NewClient() Backoff = %v, want %v", retryConfig.Backoff, DefaultRetryBackoff)
	}
}

func TestWithTimeout(t *testing.T) {
	customTimeout := 60 * time.Second
	client, err := NewClient("https://api.example.com", "test-token", WithTimeout(customTimeout))
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	if client.httpClient.Timeout != customTimeout {
		t.Errorf("WithTimeout() timeout = %v, want %v", client.httpClient.Timeout, customTimeout)
	}
}

func TestWithRetryConfig(t *testing.T) {
	maxRetries := 5
	backoff := 2 * time.Second
	client, err := NewClient("https://api.example.com", "test-token", WithRetryConfig(maxRetries, backoff))
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	retryConfig := client.GetRetryConfig()
	if retryConfig.MaxRetries != maxRetries {
		t.Errorf("WithRetryConfig() MaxRetries = %v, want %v", retryConfig.MaxRetries, maxRetries)
	}
	if retryConfig.Backoff != backoff {
		t.Errorf("WithRetryConfig() Backoff = %v, want %v", retryConfig.Backoff, backoff)
	}
}

func TestMultipleOptions(t *testing.T) {
	customTimeout := 45 * time.Second
	maxRetries := 7
	backoff := 3 * time.Second

	client, err := NewClient("https://api.example.com", "test-token",
		WithTimeout(customTimeout),
		WithRetryConfig(maxRetries, backoff))
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	// Check timeout
	if client.httpClient.Timeout != customTimeout {
		t.Errorf("Multiple options timeout = %v, want %v", client.httpClient.Timeout, customTimeout)
	}

	// Check retry config
	retryConfig := client.GetRetryConfig()
	if retryConfig.MaxRetries != maxRetries {
		t.Errorf("Multiple options MaxRetries = %v, want %v", retryConfig.MaxRetries, maxRetries)
	}
	if retryConfig.Backoff != backoff {
		t.Errorf("Multiple options Backoff = %v, want %v", retryConfig.Backoff, backoff)
	}
}

func TestSetTimeout(t *testing.T) {
	client, err := NewClient("https://api.example.com", "test-token")
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	customTimeout := 90 * time.Second
	client.SetTimeout(customTimeout)

	if client.httpClient.Timeout != customTimeout {
		t.Errorf("SetTimeout() timeout = %v, want %v", client.httpClient.Timeout, customTimeout)
	}
}

func TestServiceInitialization(t *testing.T) {
	client, err := NewClient("https://api.example.com", "test-token")
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	// Verify Agent service is initialized
	if client.Agent == nil {
		t.Error("NewClient() Agent service is nil, expected initialized service")
	}
	if client.Agent != nil && client.Agent.client != client {
		t.Error("NewClient() Agent service client reference is incorrect")
	}

	// Verify Task service is initialized
	if client.Task == nil {
		t.Error("NewClient() Task service is nil, expected initialized service")
	}
	if client.Task != nil && client.Task.client != client {
		t.Error("NewClient() Task service client reference is incorrect")
	}

	// Verify Attack service is initialized
	if client.Attack == nil {
		t.Error("NewClient() Attack service is nil, expected initialized service")
	}
	if client.Attack != nil && client.Attack.client != client {
		t.Error("NewClient() Attack service client reference is incorrect")
	}
}
