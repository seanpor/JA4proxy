// Package commands contains the business logic for all ja4proxy-cli sub-commands.
// Each RunXxx function is independently testable and is called by the cobra command
// wiring in cmd/ja4proxy-cli/main.go.
package commands

import (
	"context"
	"fmt"
	"net/url"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
)

// BanResult represents an active IP ban entry returned by the Management API.
type BanResult struct {
	IP     string `json:"ip"`
	TTL    int    `json:"ttl"`
	Reason string `json:"reason"`
}

// LookupResult is the aggregated result of an IP lookup, combining active ban
// information with recent connection history.
type LookupResult struct {
	IP                string        `json:"ip"`
	ActiveBan         *BanResult    `json:"active_ban,omitempty"`
	RecentConnections []interface{} `json:"recent_connections"`
}

// RunIPBan bans an IP address or CIDR range via the Management API.
// It issues POST /api/v1/bans/{ip} with the given TTL (seconds) and reason.
func RunIPBan(ctx context.Context, c *client.Client, ip string, ttl int, reason string) (*BanResult, error) {
	body := map[string]interface{}{
		"ttl":    ttl,
		"reason": reason,
	}
	var result BanResult
	if err := c.Post(ctx, "/api/v1/bans/"+ip, body, &result); err != nil {
		return nil, fmt.Errorf("banning %s: %w", ip, err)
	}
	return &result, nil
}

// RunIPRelease removes an active ban for the given IP address or CIDR.
// It issues DELETE /api/v1/bans/{ip}.
func RunIPRelease(ctx context.Context, c *client.Client, ip string) error {
	if err := c.Delete(ctx, "/api/v1/bans/"+ip); err != nil {
		return fmt.Errorf("releasing ban for %s: %w", ip, err)
	}
	return nil
}

// RunWatchlistAdd adds an IP address to the watchlist.
// It issues POST /api/v1/watchlist with the given TTL and reason.
func RunWatchlistAdd(ctx context.Context, c *client.Client, ip string, ttl int, reason string) error {
	body := map[string]interface{}{
		"entry":  ip,
		"ttl":    ttl,
		"reason": reason,
	}
	if err := c.Post(ctx, "/api/v1/watchlist", body, nil); err != nil {
		return fmt.Errorf("adding %s to watchlist: %w", ip, err)
	}
	return nil
}

// RunWatchlistRemove removes an IP address from the watchlist.
// It first calls GET /api/v1/watchlist to find the entry ID, then calls
// DELETE /api/v1/watchlist/{id}.  Returns an error if no matching entry is found.
func RunWatchlistRemove(ctx context.Context, c *client.Client, ip string) error {
	var items []struct {
		ID    string `json:"id"`
		Entry string `json:"entry"`
	}
	if err := c.Get(ctx, "/api/v1/watchlist", &items); err != nil {
		return fmt.Errorf("fetching watchlist: %w", err)
	}
	for _, item := range items {
		if item.Entry == ip {
			if err := c.Delete(ctx, "/api/v1/watchlist/"+item.ID); err != nil {
				return fmt.Errorf("removing watchlist entry %s: %w", item.ID, err)
			}
			return nil
		}
	}
	return fmt.Errorf("no entry found matching %s", ip)
}

// RunIPLookup retrieves active ban information and recent connections for an IP.
// It calls /api/v1/bans/{ip} and /api/v1/connections concurrently and aggregates
// the results into a LookupResult.
func RunIPLookup(ctx context.Context, c *client.Client, ip string) (*LookupResult, error) {
	result := &LookupResult{IP: ip}

	// Fetch active ban — a 404 means no ban exists (not an error).
	var ban BanResult
	banErr := c.Get(ctx, "/api/v1/bans/"+ip, &ban)
	if banErr == nil {
		result.ActiveBan = &ban
	}
	// Non-nil banErr is treated as "no active ban" (e.g. 404) to keep the lookup
	// fail-open.  Transport errors would already be visible from the connections call.

	// Fetch recent connections.
	connPath := "/api/v1/connections?" + url.Values{
		"ip":    []string{ip},
		"limit": []string{"10"},
	}.Encode()
	var conns []interface{}
	if err := c.Get(ctx, connPath, &conns); err != nil {
		return nil, fmt.Errorf("fetching connections for %s: %w", ip, err)
	}
	result.RecentConnections = conns

	return result, nil
}
