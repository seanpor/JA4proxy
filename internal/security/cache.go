// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package security

import (
	"sync"
)

// DecisionCache provides nanosecond-speed lookups for recently seen fingerprints.
// This is critical for breaking the 350 CPS bottleneck by bypassing Redis
// for repeat traffic.
type DecisionCache struct {
	mu    sync.RWMutex
	data  map[string]*PipelineResult
	limit int
}

// NewDecisionCache initializes a thread-safe cache for security decisions.
func NewDecisionCache(limit int) *DecisionCache {
	return &DecisionCache{
		data:  make(map[string]*PipelineResult),
		limit: limit,
	}
}

// Get retrieves a cached decision for a fingerprint.
func (c *DecisionCache) Get(ja4 string) (*PipelineResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res, ok := c.data[ja4]
	return res, ok
}

// Set stores a decision in the local cache.
// Note: This is a simple map-based cache for Phase 160.
// Future improvements can add eviction logic.
func (c *DecisionCache) Set(ja4 string, res *PipelineResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Simple eviction: clear if full
	if len(c.data) >= c.limit {
		c.data = make(map[string]*PipelineResult)
	}
	c.data[ja4] = res
}
