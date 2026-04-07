package commands

import (
	"context"
	"fmt"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
)

// NodeHealth represents the health state of a single proxy node.
type NodeHealth struct {
	Host    string `json:"host"`
	Status  string `json:"status"`
	Version string `json:"version"`
	Dial    int    `json:"dial"`
}

// deepHealthResponse decodes the /api/v1/health/deep payload.
type deepHealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Dial    int    `json:"dial"`
	Host    string `json:"host"`
}

// nodesResponse decodes the /api/v1/nodes list.
type nodesResponse struct {
	Nodes []NodeHealth `json:"nodes"`
}

// RunHealth retrieves health information for proxy nodes.
// When allNodes is true, it calls GET /api/v1/nodes to get the full cluster list.
// In both cases, it also calls GET /api/v1/health/deep for the local node and
// includes that in the returned slice.
func RunHealth(ctx context.Context, c *client.Client, allNodes bool) ([]NodeHealth, error) {
	var results []NodeHealth

	if allNodes {
		var resp nodesResponse
		if err := c.Get(ctx, "/api/v1/nodes", &resp); err != nil {
			return nil, fmt.Errorf("fetching nodes: %w", err)
		}
		results = append(results, resp.Nodes...)
	}

	// Always include the deep health of the directly-connected node.
	var deep deepHealthResponse
	if err := c.Get(ctx, "/api/v1/health/deep", &deep); err != nil {
		return nil, fmt.Errorf("fetching deep health: %w", err)
	}

	localNode := NodeHealth{
		Host:    deep.Host,
		Status:  deep.Status,
		Version: deep.Version,
		Dial:    deep.Dial,
	}

	// Avoid duplicate if the deep-health host is already in the nodes list.
	found := false
	for _, n := range results {
		if n.Host == localNode.Host {
			found = true
			break
		}
	}
	if !found {
		results = append(results, localNode)
	}

	return results, nil
}
