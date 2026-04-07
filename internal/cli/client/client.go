// Package client provides a thin HTTP client for the JA4proxy Management API.
// It sets the Authorization header on every request and returns descriptive
// errors that include the HTTP status code and response body on non-2xx responses.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultTimeout = 30 * time.Second

// Client is a lightweight HTTP client scoped to a single Management API instance.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// New creates a Client for the given base URL and bearer token.
// The client uses a 30-second timeout for all requests.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// Get sends a GET request to baseURL+path and JSON-decodes the response into out.
// out may be nil if the response body is not needed.
func (c *Client) Get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("building GET request for %s: %w", path, err)
	}
	c.setAuth(req)
	return c.do(req, out)
}

// Post sends a POST request to baseURL+path with a JSON-encoded body and
// decodes the response into out. out may be nil.
func (c *Client) Post(ctx context.Context, path string, body interface{}, out interface{}) error {
	req, err := c.newJSONRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

// Patch sends a PATCH request to baseURL+path with a JSON-encoded body and
// decodes the response into out. out may be nil.
func (c *Client) Patch(ctx context.Context, path string, body interface{}, out interface{}) error {
	req, err := c.newJSONRequest(ctx, http.MethodPatch, path, body)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

// Delete sends a DELETE request to baseURL+path.
func (c *Client) Delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("building DELETE request for %s: %w", path, err)
	}
	c.setAuth(req)
	return c.do(req, nil)
}

// setAuth adds the Bearer token Authorization header to r.
func (c *Client) setAuth(r *http.Request) {
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// newJSONRequest builds a request with a JSON-encoded body and Content-Type header.
func (c *Client) newJSONRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, fmt.Errorf("encoding request body for %s %s: %w", method, path, err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, &buf)
	if err != nil {
		return nil, fmt.Errorf("building %s request for %s: %w", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)
	return req, nil
}

// do executes req, optionally decodes a JSON response into out, and returns
// a descriptive error for non-2xx status codes.
func (c *Client) do(req *http.Request, out interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(bodyBytes)
		if len(snippet) > 256 {
			snippet = snippet[:256] + "..."
		}
		return fmt.Errorf("HTTP %s %s: status %d: %s",
			req.Method, req.URL.Path, resp.StatusCode, snippet)
	}

	if out != nil && len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, out); err != nil {
			return fmt.Errorf("decoding response from %s %s: %w",
				req.Method, req.URL.Path, err)
		}
	}
	return nil
}
