// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package security

import (
	"sync"
	"time"
)

// DecisionCache is the in-process per-connection decision cache. Per ADR-003
// ("Asymmetric Decision-Cache TTLs — ALLOW Long, BLOCK Short") it caches
// per-client allow/block decisions so the full signal pipeline is not re-run on
// every connection from a recently-seen client, with asymmetric TTLs:
//
//   - ALLOW decisions are cached with a long TTL (a client judged legitimate
//     stays fast and unblocked without re-scoring).
//   - Every other action (block/ban/tarpit/rate_limit/flag) is cached with a
//     short TTL so a mistaken or stale block self-heals fast and a lifted ban
//     takes effect almost immediately.
//
// JA4PROXY-2026-0087 (phase-515): the key MUST identify the client, not just
// the TLS fingerprint. A JA4 is shared by every client running the same TLS
// stack (all Chrome-N users, all curl, all Go net/http clients); keying on JA4
// alone caused an IP-derived block to be served to every other client sharing
// that JA4 (false positive: real browsers blocked) and an allow warmed by one
// client to let an attacker with the same ClientHello bypass all per-IP
// controls (false negative). Callers MUST build the key with decisionCacheKey.
type DecisionCache struct {
	mu       sync.RWMutex
	data     map[string]cacheEntry
	limit    int
	allowTTL time.Duration
	blockTTL time.Duration
	// now is injectable for deterministic tests; defaults to time.Now.
	now func() time.Time
}

type cacheEntry struct {
	res       *PipelineResult
	expiresAt time.Time
}

// Default TTLs per ADR-003 when config supplies none.
const (
	defaultAllowTTL = 30 * time.Minute
	defaultBlockTTL = 30 * time.Second
)

// NewDecisionCache creates a decision cache. A non-positive limit falls back to
// 10000; non-positive TTLs fall back to the ADR-003 defaults (ALLOW 30m,
// BLOCK 30s) so a misconfiguration can never disable expiry entirely.
func NewDecisionCache(limit int, allowTTL, blockTTL time.Duration) *DecisionCache {
	if limit <= 0 {
		limit = 10000
	}
	if allowTTL <= 0 {
		allowTTL = defaultAllowTTL
	}
	if blockTTL <= 0 {
		blockTTL = defaultBlockTTL
	}
	return &DecisionCache{
		data:     make(map[string]cacheEntry),
		limit:    limit,
		allowTTL: allowTTL,
		blockTTL: blockTTL,
		now:      time.Now,
	}
}

// Get returns the cached decision for key, or (nil, false) on a miss. An entry
// whose TTL has elapsed is treated as a miss and removed (expiry-on-read).
func (c *DecisionCache) Get(key string) (*PipelineResult, bool) {
	if key == "" {
		return nil, false
	}
	now := c.now()
	c.mu.RLock()
	e, ok := c.data[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !now.Before(e.expiresAt) {
		// Expired — drop under the write lock and report a miss.
		c.mu.Lock()
		if cur, still := c.data[key]; still && cur.expiresAt.Equal(e.expiresAt) {
			delete(c.data, key)
		}
		c.mu.Unlock()
		return nil, false
	}
	return e.res, true
}

// Set stores a decision under key. The TTL is chosen from res.Action: "allow"
// uses the long ALLOW TTL; every other action uses the short BLOCK TTL
// (ADR-003). Empty keys and nil results are ignored.
func (c *DecisionCache) Set(key string, res *PipelineResult) {
	if key == "" || res == nil {
		return
	}
	ttl := c.blockTTL
	if res.Action == "allow" {
		ttl = c.allowTTL
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) >= c.limit {
		c.evictLocked(now)
	}
	c.data[key] = cacheEntry{res: res, expiresAt: now.Add(ttl)}
}

// evictLocked bounds the map. It first drops any already-expired entries (free
// wins that also protect against unbounded growth of short-lived block
// entries), and if that did not free enough it trims a fraction of the
// remaining entries. Caller must hold the write lock.
func (c *DecisionCache) evictLocked(now time.Time) {
	freed := 0
	for k, e := range c.data {
		if !now.Before(e.expiresAt) {
			delete(c.data, k)
			freed++
		}
	}
	if len(c.data) < c.limit {
		return
	}
	// Still at/over the limit after expiry sweep — trim ~10% of live entries.
	trim := c.limit / 10
	if trim <= 0 {
		trim = 1
	}
	for k := range c.data {
		if trim <= 0 {
			break
		}
		delete(c.data, k)
		trim--
	}
}

// SetTTLs updates the ALLOW/BLOCK TTLs in place (used on hot config reload).
// Non-positive values are ignored so a partial config never disables expiry.
func (c *DecisionCache) SetTTLs(allowTTL, blockTTL time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if allowTTL > 0 {
		c.allowTTL = allowTTL
	}
	if blockTTL > 0 {
		c.blockTTL = blockTTL
	}
}

// decisionCacheKey builds the composite per-client cache key. It combines the
// client IP and the JA4 so that neither a shared JA4 (many clients, one
// fingerprint) nor a shared NAT egress IP (one address, many fingerprints)
// causes one client's decision to be served to another. JA4PROXY-2026-0087.
func decisionCacheKey(clientIP, ja4 string) string {
	return clientIP + "|" + ja4
}
