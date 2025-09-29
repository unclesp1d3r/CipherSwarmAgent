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
)

// Client represents the main SDK client for CipherSwarm API interactions.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client

	// Service endpoints will be added in future tasks
	// Agent  *AgentService
	// Task   *TaskService
	// Attack *AttackService
}

// NewClient creates a new CipherSwarm SDK client with the provided base URL and authentication token.
func NewClient(baseURL, token string) (*Client, error) {
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
