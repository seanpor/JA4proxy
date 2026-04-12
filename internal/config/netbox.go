package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// netboxPrefix represents a single prefix entry in the NetBox API response.
type netboxPrefix struct {
	Prefix string `json:"prefix"`
}

// netboxPrefixResponse represents the paginated response from NetBox IPAM.
type netboxPrefixResponse struct {
	Results []netboxPrefix `json:"results"`
}

// LoadTrustedCIDRsFromNetBox fetches trusted upstream CIDRs from
// NetBox IPAM. Fails open: returns an empty slice (not an error) on
// any HTTP, transport, timeout, or decode failure. The caller merges
// the result with static CIDRs from config/proxy.yml.
func LoadTrustedCIDRsFromNetBox(ctx context.Context, url, token, tag string) ([]string, error) {
	// Build the request URL with query parameters
	reqURL := fmt.Sprintf("%s/api/ipam/prefixes/?tag=%s&limit=1000", url, tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		logrus.WithError(err).Warn("netbox: failed to build request")
		return []string{}, nil
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))
	req.Header.Set("Accept", "application/json")

	// 5-second total timeout (applied on top of caller's context)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		logrus.WithError(err).Warn("netbox: request failed — failing open")
		return []string{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logrus.WithField("status", resp.StatusCode).Warn("netbox: non-2xx response — failing open")
		return []string{}, nil
	}

	var nbResp netboxPrefixResponse
	if err := json.NewDecoder(resp.Body).Decode(&nbResp); err != nil {
		logrus.WithError(err).Warn("netbox: JSON decode failed — failing open")
		return []string{}, nil
	}

	cidrs := make([]string, 0, len(nbResp.Results))
	for _, p := range nbResp.Results {
		if p.Prefix != "" {
			cidrs = append(cidrs, p.Prefix)
		}
	}

	return cidrs, nil
}
