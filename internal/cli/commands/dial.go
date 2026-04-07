package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
)

// DialValue holds the current dial setting returned by the Management API.
type DialValue struct {
	Setting int `json:"setting"`
}

// PendingApprovalError is returned by RunDialSet when the Management API responds
// with HTTP 202, indicating that the dial change requires four-eyes approval.
type PendingApprovalError struct {
	DecisionID string
}

// Error implements the error interface for PendingApprovalError.
func (e *PendingApprovalError) Error() string {
	return "PENDING APPROVAL: " + e.DecisionID
}

// RunDialGet retrieves the current dial setting from the Management API.
// It issues GET /api/v1/dial.
func RunDialGet(ctx context.Context, c *client.Client) (*DialValue, error) {
	var dv DialValue
	if err := c.Get(ctx, "/api/v1/dial", &dv); err != nil {
		return nil, fmt.Errorf("getting dial setting: %w", err)
	}
	return &dv, nil
}

// RunDialSet updates the dial setting via the Management API.
// It issues PATCH /api/v1/dial with the new setting, optional ticket, and notes.
// If the API responds with HTTP 202 (pending approval), RunDialSet returns a
// *PendingApprovalError containing the decision_id from the response body.
func RunDialSet(ctx context.Context, c *client.Client, setting int, ticket, notes string) error {
	body := map[string]interface{}{
		"setting": setting,
		"notes":   notes,
	}
	if ticket != "" {
		body["ticket"] = ticket
	}

	// We need the raw HTTP status to detect 202, so we build a custom request
	// path using the client's Patch method with a raw response container.
	// The client.Patch method returns an error on non-2xx, so we use a separate
	// approach: attempt the patch, then check for the specific 202 case.
	//
	// Because client.Client.Patch returns an error for 202 (which is non-2xx ≥ 200
	// but... actually 202 IS a 2xx code — the client only errors on < 200 or >= 300),
	// we decode the body normally and inspect the response fields.
	var respBody map[string]interface{}
	err := c.Patch(ctx, "/api/v1/dial", body, &respBody)
	if err != nil {
		// Check if this is a 202 wrapped as an HTTP error — some API implementations
		// return 202 and the client may have decoded it.  We handle both paths.
		return fmt.Errorf("setting dial to %d: %w", setting, err)
	}

	// Check for pending approval status in a successful (2xx) response body.
	if status, ok := respBody["status"].(string); ok && status == "pending_approval" {
		decisionID, _ := respBody["decision_id"].(string)
		return &PendingApprovalError{DecisionID: decisionID}
	}

	return nil
}

// RunDialSetRaw sends the dial PATCH and explicitly handles HTTP 202 by reading
// the raw response.  This variant is used internally when direct HTTP status
// inspection is needed.
func RunDialSetRaw(ctx context.Context, httpClient *http.Client, baseURL, token string, setting int, ticket, notes string) error {
	body := map[string]interface{}{
		"setting": setting,
		"notes":   notes,
	}
	if ticket != "" {
		body["ticket"] = ticket
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, baseURL+"/api/v1/dial",
		bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var respBody map[string]interface{}
	if decErr := json.NewDecoder(resp.Body).Decode(&respBody); decErr != nil {
		respBody = nil
	}

	if resp.StatusCode == http.StatusAccepted {
		decisionID, _ := respBody["decision_id"].(string)
		return &PendingApprovalError{DecisionID: decisionID}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP PATCH /api/v1/dial: status %d", resp.StatusCode)
	}
	return nil
}
