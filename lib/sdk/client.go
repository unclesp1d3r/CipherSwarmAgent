// Package sdk provides the CipherSwarm API client implementation
package sdk

import (
	"errors"
	"net/http"
	"time"
)

const (
	// DefaultTimeout is the default HTTP client timeout.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxRetries is the default number of retry attempts.
	DefaultMaxRetries = 3
	// DefaultRetryBackoff is the default backoff duration between retries.
	DefaultRetryBackoff = 1 * time.Second
)

// RetryConfig holds configuration for HTTP request retries.
type RetryConfig struct {
	MaxRetries int
	Backoff    time.Duration
}

// ClientOption is a function type for configuring the Client.
type ClientOption func(*Client)

// Client represents the main SDK client for CipherSwarm API interactions.
type Client struct {
	baseURL     string
	token       string
	httpClient  *http.Client
	retryConfig RetryConfig

	// Service endpoints
	Agent  *AgentService
	Task   *TaskService
	Attack *AttackService
}

// NewClient creates a new CipherSwarm SDK client with the provided base URL and authentication token.
// Additional configuration can be applied using ClientOption functions.
func NewClient(baseURL, token string, opts ...ClientOption) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("baseURL cannot be empty")
	}
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}

	client := &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		retryConfig: RetryConfig{
			MaxRetries: DefaultMaxRetries,
			Backoff:    DefaultRetryBackoff,
		},
	}

	// Initialize services
	client.Agent = &AgentService{client: client}
	client.Task = &TaskService{client: client}
	client.Attack = &AttackService{client: client}

	// Apply all provided options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// GetBaseURL returns the base URL configured for this client.
func (c *Client) GetBaseURL() string {
	return c.baseURL
}

// GetToken returns the authentication token configured for this client.
func (c *Client) GetToken() string {
	return c.token
}

// SetTimeout sets the HTTP client timeout.
func (c *Client) SetTimeout(timeout time.Duration) {
	c.httpClient.Timeout = timeout
}

// GetHTTPClient returns the underlying HTTP client for advanced usage.
func (c *Client) GetHTTPClient() *http.Client {
	return c.httpClient
}

// GetRetryConfig returns the current retry configuration.
func (c *Client) GetRetryConfig() RetryConfig {
	return c.retryConfig
}

// WithTimeout returns a ClientOption that sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithRetryConfig returns a ClientOption that sets the retry configuration.
func WithRetryConfig(maxRetries int, backoff time.Duration) ClientOption {
	return func(c *Client) {
		c.retryConfig = RetryConfig{
			MaxRetries: maxRetries,
			Backoff:    backoff,
		}
	}
}

// AgentService provides agent-specific operations.
type AgentService struct {
	client *Client
}

// TaskService provides task-specific operations.
type TaskService struct {
	client *Client
}

// AttackService provides attack-specific operations.
type AttackService struct {
	client *Client
}
