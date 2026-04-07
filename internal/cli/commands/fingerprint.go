package commands

import (
	"context"
	"fmt"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
)

// RunFingerprintHistory retrieves historical connection data for a JA4 fingerprint.
// It calls GET /api/v1/fingerprints/{ja4}/history.
// The since parameter is an optional time-range filter (e.g. "30d") passed as a
// query parameter; if empty, no filter is applied.
func RunFingerprintHistory(ctx context.Context, c *client.Client, ja4, since string) ([]interface{}, error) {
	path := "/api/v1/fingerprints/" + ja4 + "/history"
	if since != "" {
		path += "?since=" + since
	}
	var items []interface{}
	if err := c.Get(ctx, path, &items); err != nil {
		return nil, fmt.Errorf("fetching fingerprint history for %s: %w", ja4, err)
	}
	return items, nil
}
