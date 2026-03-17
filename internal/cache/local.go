// Package cache provides a simple in-process LRU cache for connection decisions.
package cache

import (
	"container/list"
	"sync"
	"time"
)

// entry holds a cached value and its expiry.
type entry struct {
	key     string
	value   interface{}
	expires time.Time
}

// LRU is a bounded, TTL-aware in-process LRU cache.
// Thread-safe.
type LRU struct {
	mu       sync.Mutex
	cap      int
	items    map[string]*list.Element
	order    *list.List
}

// New creates an LRU cache with the given capacity.
func New(cap int) *LRU {
	if cap <= 0 {
		cap = 1024
	}
	return &LRU{
		cap:   cap,
		items: make(map[string]*list.Element, cap),
		order: list.New(),
	}
}

// Set stores a value with a TTL. TTL=0 means no expiry.
func (c *LRU) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expires time.Time
	if ttl > 0 {
		expires = time.Now().Add(ttl)
	}

	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)
		el.Value.(*entry).value = value
		el.Value.(*entry).expires = expires
		return
	}

	if c.order.Len() >= c.cap {
		c.evict()
	}

	e := &entry{key: key, value: value, expires: expires}
	el := c.order.PushFront(e)
	c.items[key] = el
}

// Get retrieves a value. Returns (nil, false) if absent or expired.
func (c *LRU) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*entry)
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		c.order.Remove(el)
		delete(c.items, key)
		return nil, false
	}
	c.order.MoveToFront(el)
	return e.value, true
}

// Delete removes a key. No-op if absent.
func (c *LRU) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

// Len returns the number of items currently in the cache.
func (c *LRU) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// evict removes the least-recently-used item. Caller must hold the lock.
func (c *LRU) evict() {
	back := c.order.Back()
	if back == nil {
		return
	}
	c.order.Remove(back)
	delete(c.items, back.Value.(*entry).key)
}
