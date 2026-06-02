package config

import (
	"os"
	"strings"
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	Next    *string        `json:"next"`
}

// LoadTrustedCIDRsFromNetBox fetches trusted upstream CIDRs from
// NetBox IPAM. Follows pagination via the "next" pointer. Each CIDR is
// validated with net.ParseCIDR and dangerous ranges (0.0.0.0/0, ::/0)
// are rejected with a WARN log.
//
// Fails open: returns an empty slice (not an error) on
// any HTTP, transport, timeout, or decode failure. The caller merges
// the result with static CIDRs from config/proxy.yml.
func LoadTrustedCIDRsFromNetBox(ctx context.Context, baseURL, token, tag string) ([]string, error) {
	// JA4PROXY-2026-0044: Enforce HTTPS for NetBox integration
	if !strings.HasPrefix(strings.ToLower(baseURL), "https://") && os.Getenv("JA4PROXY_TEST_ALLOW_INSECURE_NETBOX") != "true" {
		return nil, fmt.Errorf("netbox: insecure URL blocked (HTTPS required): %s", baseURL)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Default transport already does strict validation.
	}

	var allCIDRs []string
	reqURL := fmt.Sprintf("%s/api/ipam/prefixes/?tag=%s&limit=1000", baseURL, tag)

	for reqURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			logrus.WithError(err).Warn("netbox: failed to build request")
			return []string{}, nil
		}
		req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			logrus.WithError(err).Warn("netbox: request failed — failing open")
			return []string{}, nil
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			logrus.WithField("status", resp.StatusCode).Warn("netbox: non-2xx response — failing open")
			_ = resp.Body.Close() // #nosec G104
			return []string{}, nil
		}

		var nbResp netboxPrefixResponse
		if err := json.NewDecoder(resp.Body).Decode(&nbResp); err != nil {
			logrus.WithError(err).Warn("netbox: JSON decode failed — failing open")
			_ = resp.Body.Close() // #nosec G104
			return []string{}, nil
		}
		_ = resp.Body.Close() // #nosec G104

		for _, p := range nbResp.Results {
			if p.Prefix == "" {
				continue
			}
			// B3: Validate CIDR — skip malformed entries
			_, ipNet, err := net.ParseCIDR(p.Prefix)
			if err != nil {
				logrus.WithField("prefix", p.Prefix).Warn("netbox: invalid CIDR, skipping")
				continue
			}
			// B3: Reject overly-broad CIDRs that would trust the entire internet
			if isDefaultRoute(ipNet) {
				logrus.WithField("prefix", p.Prefix).Warn("netbox: rejecting default-route CIDR (would trust all IPs)")
				continue
			}
			allCIDRs = append(allCIDRs, p.Prefix)
		}

		// B2: Follow pagination link if present
		if nbResp.Next != nil && *nbResp.Next != "" {
			reqURL = *nbResp.Next
		} else {
			reqURL = ""
		}
	}

	return allCIDRs, nil
}

// isDefaultRoute returns true if the CIDR covers all IPv4 or all IPv6 space.
func isDefaultRoute(ipNet *net.IPNet) bool {
	ones, bits := ipNet.Mask.Size()
	return ones == 0 && (bits == 32 || bits == 128)
}
