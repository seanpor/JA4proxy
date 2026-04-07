package commands

import (
	"context"
	"fmt"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
)

// RunBlocklistAdd adds a JA4 fingerprint to the blocklist.
// It issues POST /api/v1/blocklist with the given reason and ticket fields.
func RunBlocklistAdd(ctx context.Context, c *client.Client, ja4, reason, ticket string) (*ListEntry, error) {
	body := map[string]interface{}{
		"entry":  ja4,
		"reason": reason,
		"ticket": ticket,
	}
	var entry ListEntry
	if err := c.Post(ctx, "/api/v1/blocklist", body, &entry); err != nil {
		return nil, fmt.Errorf("adding %s to blocklist: %w", ja4, err)
	}
	return &entry, nil
}

// RunBlocklistRemove removes a JA4 fingerprint from the blocklist.
// It first calls GET /api/v1/blocklist to locate the entry by its ja4 value,
// then calls DELETE /api/v1/blocklist/{id}.
// Returns an error if no matching entry is found.
func RunBlocklistRemove(ctx context.Context, c *client.Client, ja4 string) error {
	var items []ListEntry
	if err := c.Get(ctx, "/api/v1/blocklist", &items); err != nil {
		return fmt.Errorf("fetching blocklist: %w", err)
	}
	for _, item := range items {
		if item.Entry == ja4 {
			if err := c.Delete(ctx, "/api/v1/blocklist/"+item.ID); err != nil {
				return fmt.Errorf("removing blocklist entry %s: %w", item.ID, err)
			}
			return nil
		}
	}
	return fmt.Errorf("no entry found matching %s", ja4)
}

// RunBlocklistList returns all entries in the blocklist.
// It issues GET /api/v1/blocklist.
func RunBlocklistList(ctx context.Context, c *client.Client) ([]ListEntry, error) {
	var items []ListEntry
	if err := c.Get(ctx, "/api/v1/blocklist", &items); err != nil {
		return nil, fmt.Errorf("listing blocklist: %w", err)
	}
	return items, nil
}
