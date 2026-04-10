package commands

import (
	"context"
	"fmt"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
)

// ListEntry represents a single allowlist or blocklist entry from the Management API.
type ListEntry struct {
	ID        string `json:"id"`
	Entry     string `json:"entry"`
	Reason    string `json:"reason"`
	ManagedBy string `json:"managed_by"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Ticket    string `json:"ticket,omitempty"`
}

// RunAllowlistAdd adds a JA4 fingerprint to the allowlist.
// It issues POST /api/v1/allowlist with the given reason, expiry, and ticket fields.
func RunAllowlistAdd(ctx context.Context, c *client.Client, ja4, reason, expiresAt, ticket string) (*ListEntry, error) {
	body := map[string]interface{}{
		"entry":      ja4,
		"reason":     reason,
		"expires_at": expiresAt,
		"ticket":     ticket,
	}
	var entry ListEntry
	if err := c.Post(ctx, "/api/v1/allowlist", body, &entry); err != nil {
		return nil, fmt.Errorf("adding %s to allowlist: %w", ja4, err)
	}
	return &entry, nil
}

// RunAllowlistRemove removes a JA4 fingerprint from the allowlist.
// It first calls GET /api/v1/allowlist to locate the entry by its ja4 value,
// then calls DELETE /api/v1/allowlist/{id}.
// Returns an error if no matching entry is found.
func RunAllowlistRemove(ctx context.Context, c *client.Client, ja4 string) error {
	var items []ListEntry
	if err := c.Get(ctx, "/api/v1/allowlist", &items); err != nil {
		return fmt.Errorf("fetching allowlist: %w", err)
	}
	for _, item := range items {
		if item.Entry == ja4 {
			if err := c.Delete(ctx, "/api/v1/allowlist/"+item.ID); err != nil {
				return fmt.Errorf("removing allowlist entry %s: %w", item.ID, err)
			}
			return nil
		}
	}
	return fmt.Errorf("no entry found matching %s", ja4)
}

// RunAllowlistList returns all entries in the allowlist.
// It issues GET /api/v1/allowlist.
func RunAllowlistList(ctx context.Context, c *client.Client) ([]ListEntry, error) {
	var items []ListEntry
	if err := c.Get(ctx, "/api/v1/allowlist", &items); err != nil {
		return nil, fmt.Errorf("listing allowlist: %w", err)
	}
	return items, nil
}
