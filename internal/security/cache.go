// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package security

import (
	"math/rand"
	"sync"
)

type DecisionCache struct {
	mu    sync.RWMutex
	data  map[string]*PipelineResult
	limit int
}

func NewDecisionCache(limit int) *DecisionCache {
	return &DecisionCache{data: make(map[string]*PipelineResult), limit: limit}
}

func (c *DecisionCache) Get(ja4 string) (*PipelineResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res, ok := c.data[ja4]
	return res, ok
}

func (c *DecisionCache) Set(ja4 string, res *PipelineResult) {
	if ja4 == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) >= c.limit {
		evictCount := c.limit / 10
		remaining := len(c.data)
		for k := range c.data {
			if evictCount <= 0 {
				break
			}
			if rand.Intn(remaining) < evictCount {
				delete(c.data, k)
				evictCount--
			}
			remaining--
		}
	}
	c.data[ja4] = res
}
