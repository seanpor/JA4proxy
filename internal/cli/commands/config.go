package commands

import (
	"context"
	"fmt"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
)

// nodeListResponse is used to decode the /api/v1/nodes response.
type nodeListResponse struct {
	Nodes []struct {
		Host string `json:"host"`
	} `json:"nodes"`
}

// RunConfigReload triggers a configuration reload on one or all proxy nodes.
// If node is empty, RunConfigReload first fetches all known nodes via
// GET /api/v1/nodes and then calls POST /api/v1/nodes/{host}/reload for each.
// If node is non-empty, it calls POST /api/v1/nodes/{node}/reload directly.
func RunConfigReload(ctx context.Context, c *client.Client, node string) error {
	if node != "" {
		return reloadNode(ctx, c, node)
	}

	// Fetch all nodes.
	var resp nodeListResponse
	if err := c.Get(ctx, "/api/v1/nodes", &resp); err != nil {
		return fmt.Errorf("fetching node list: %w", err)
	}
	if len(resp.Nodes) == 0 {
		return fmt.Errorf("no nodes returned by /api/v1/nodes")
	}
	for _, n := range resp.Nodes {
		if err := reloadNode(ctx, c, n.Host); err != nil {
			return err
		}
	}
	return nil
}

// reloadNode sends a reload request to a single proxy node.
func reloadNode(ctx context.Context, c *client.Client, host string) error {
	if err := c.Post(ctx, "/api/v1/nodes/"+host+"/reload", nil, nil); err != nil {
		return fmt.Errorf("reloading node %s: %w", host, err)
	}
	return nil
}
