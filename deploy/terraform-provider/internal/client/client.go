package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ── Response types ──────────────────────────────────────────────────────────

type HealthResponse struct {
	Status         string  `json:"status"`
	Redis          string  `json:"redis"`
	ProxyInstances int     `json:"proxy_instances"`
	GeoIP          string  `json:"geoip"`
	UptimeSeconds  float64 `json:"uptime_seconds"`
}

type BanResponse struct {
	Message string `json:"message"`
	IP      string `json:"ip"`
	TTL     int    `json:"ttl"`
	Reason  string `json:"reason"`
}

type Ban struct {
	IP           string `json:"ip"`
	Reason       string `json:"reason"`
	TTLRemaining *int   `json:"ttl_remaining"`
}

type BansListResponse struct {
	Bans  []Ban `json:"bans"`
	Count int   `json:"count"`
}

type ListEntry struct {
	ID        string  `json:"id"`
	Entry     string  `json:"entry"`
	ListType  string  `json:"list_type"`
	ManagedBy string  `json:"managed_by"`
	Note      string  `json:"note"`
	CreatedAt string  `json:"created_at"`
	CreatedBy string  `json:"created_by"`
	ExpiresAt *string `json:"expires_at"`
}

type ListEntriesResponse struct {
	Entries []ListEntry `json:"entries"`
	Count   int         `json:"count"`
}

type DialResponse struct {
	Value     int    `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

type Webhook struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Active    bool     `json:"active"`
	CreatedAt string   `json:"created_at"`
	ManagedBy string   `json:"managed_by"`
}

type WebhookResponse struct {
	Webhook
	Secret string `json:"secret"`
}

// ── Client ───────────────────────────────────────────────────────────────────

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// New creates a new API client. baseURL should not include a trailing slash.
func New(baseURL, token string) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("baseURL is required")
	}
	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// BaseURL returns the configured base URL (useful for singleton resource guards).
func (c *Client) BaseURL() string {
	return c.baseURL
}

// urlWithEncodedPath builds a URL with a properly percent-encoded path segment.
// It sets both Path (decoded) and RawPath (encoded) so that the encoded form
// is preserved on the wire even for characters like '/'.
func (c *Client) urlWithEncodedPath(basePath, rawSegment string) string {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return c.baseURL + basePath + rawSegment
	}
	decoded, _ := url.PathUnescape(rawSegment)
	base.Path = basePath + decoded
	base.RawPath = basePath + rawSegment
	return base.String()
}

// do executes an HTTP request and returns the body, status code, and any error.
// Non-2xx status codes are returned as errors.
func (c *Client) do(req *http.Request) ([]byte, int, error) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	if req.Header.Get("Content-Type") == "" && req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return body, resp.StatusCode, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, msg)
	}

	return body, resp.StatusCode, nil
}

// ── Health ───────────────────────────────────────────────────────────────────

func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/health", nil)
	if err != nil {
		return nil, err
	}
	body, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp HealthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse health response: %w", err)
	}
	return &resp, nil
}

// ── Bans ─────────────────────────────────────────────────────────────────────

func (c *Client) CreateBan(ctx context.Context, ip string, ttl int, reason string) (*BanResponse, error) {
	encodedIP := url.PathEscape(ip)
	payload := map[string]interface{}{
		"ttl":    ttl,
		"reason": reason,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	fullURL := c.urlWithEncodedPath("/api/v1/bans/", encodedIP)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp BanResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse ban response: %w", err)
	}
	return &resp, nil
}

func (c *Client) DeleteBan(ctx context.Context, ip string) (*BanResponse, error) {
	encodedIP := url.PathEscape(ip)
	fullURL := c.urlWithEncodedPath("/api/v1/bans/", encodedIP)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, fullURL, nil)
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp BanResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse delete ban response: %w", err)
	}
	return &resp, nil
}

func (c *Client) ListBans(ctx context.Context) (*BansListResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/bans", nil)
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp BansListResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse bans response: %w", err)
	}
	return &resp, nil
}

func (c *Client) GetBan(ctx context.Context, ip string) (*Ban, error) {
	encodedIP := url.PathEscape(ip)
	fullURL := c.urlWithEncodedPath("/api/v1/bans/", encodedIP)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	respBody, statusCode, err := c.do(req)
	if err != nil {
		if statusCode == http.StatusNotFound {
			detail := strings.TrimSpace(string(respBody))
			if detail == "" {
				detail = http.StatusText(statusCode)
			}
			return nil, fmt.Errorf("no active ban found for IP %s: %s", ip, detail)
		}
		return nil, err
	}
	var ban Ban
	if err := json.Unmarshal(respBody, &ban); err != nil {
		return nil, fmt.Errorf("failed to parse ban response: %w", err)
	}
	return &ban, nil
}

// ── List entries ─────────────────────────────────────────────────────────────

func (c *Client) CreateListEntry(ctx context.Context, listType, entry, managedBy, note string, expiresAt *string) (*ListEntry, error) {
	payload := map[string]interface{}{
		"entry":      entry,
		"managed_by": managedBy,
		"note":       note,
	}
	if expiresAt != nil {
		payload["expires_at"] = *expiresAt
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/"+listType, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp ListEntry
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse list entry response: %w", err)
	}
	return &resp, nil
}

func (c *Client) GetListEntryByID(ctx context.Context, listType, id string) (*ListEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/"+listType+"/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var entry ListEntry
	if err := json.Unmarshal(respBody, &entry); err != nil {
		return nil, fmt.Errorf("failed to parse list entry response: %w", err)
	}
	return &entry, nil
}

func (c *Client) ListEntries(ctx context.Context, listType string) (*ListEntriesResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/"+listType, nil)
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp ListEntriesResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse list entries response: %w", err)
	}
	return &resp, nil
}

func (c *Client) DeleteListEntry(ctx context.Context, listType, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/"+listType+"/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	_, _, err = c.do(req)
	return err
}

// ── Dial ─────────────────────────────────────────────────────────────────────

func (c *Client) GetDial(ctx context.Context) (*DialResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/dial", nil)
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp DialResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse dial response: %w", err)
	}
	return &resp, nil
}

func (c *Client) UpdateDial(ctx context.Context, value int) (*DialResponse, error) {
	payload := map[string]interface{}{"value": value}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+"/api/v1/dial", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	respBody, statusCode, err := c.do(req)
	if err != nil {
		if statusCode == http.StatusBadRequest {
			detail := strings.TrimSpace(string(respBody))
			if detail == "" {
				detail = http.StatusText(statusCode)
			}
			return nil, fmt.Errorf("dial update failed (HTTP 400): %s", detail)
		}
		return nil, err
	}

	// Try JSON first — value of 0 is valid, so don't check resp.Value
	var resp DialResponse
	if err := json.Unmarshal(respBody, &resp); err == nil {
		return &resp, nil
	}
	// Fallback: bare integer (legacy API format)
	if val, parseErr := strconv.Atoi(strings.TrimSpace(string(respBody))); parseErr == nil {
		return &DialResponse{Value: val}, nil
	}
	return nil, fmt.Errorf("failed to parse dial response: %s", respBody)
}

// ── Webhooks ─────────────────────────────────────────────────────────────────

func (c *Client) CreateWebhook(ctx context.Context, u string, events []string, active bool) (*WebhookResponse, error) {
	payload := map[string]interface{}{
		"url":    u,
		"events": events,
		"active": active,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/webhooks", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp WebhookResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse webhook response: %w", err)
	}
	return &resp, nil
}

func (c *Client) GetWebhook(ctx context.Context, id string) (*Webhook, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/webhooks/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var wh Webhook
	if err := json.Unmarshal(respBody, &wh); err != nil {
		return nil, fmt.Errorf("failed to parse webhook response: %w", err)
	}
	return &wh, nil
}

func (c *Client) UpdateWebhook(ctx context.Context, id, u string, events []string, active bool) (*Webhook, error) {
	payload := map[string]interface{}{
		"url":    u,
		"active": active,
	}
	if events != nil {
		payload["events"] = events
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/api/v1/webhooks/"+url.PathEscape(id), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	respBody, _, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var wh Webhook
	if err := json.Unmarshal(respBody, &wh); err != nil {
		return nil, fmt.Errorf("failed to parse webhook response: %w", err)
	}
	return &wh, nil
}

func (c *Client) DeleteWebhook(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/webhooks/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	_, _, err = c.do(req)
	return err
}
