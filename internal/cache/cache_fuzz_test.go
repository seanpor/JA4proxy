// Package cache provides in-process LRU cache implementations.
package cache

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// ---------------------------------------------------------------------------
// Native Go Fuzz Targets
// ---------------------------------------------------------------------------

// FuzzLRUOperations fuzzes arbitrary sequences of Set, Get, Delete, and Len operations,
// checking that the internal map and doubly-linked list always maintain exact parity.
func FuzzLRUOperations(f *testing.F) {
	// Seed with typical operation byte streams:
	// Op byte: 0 = Set, 1 = Get, 2 = Delete, 3 = Len
	f.Add([]byte{
		0, 'k', '1', 0, 'v', '1', // Set(k1, v1)
		1, 'k', '1',             // Get(k1)
		2, 'k', '1',             // Delete(k1)
		3,                       // Len()
	})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0, 'a', 0, 'b'}, 10))

	f.Fuzz(func(t *testing.T, ops []byte) {
		c := New(8)
		idx := 0

		for idx < len(ops) {
			op := ops[idx] % 4
			idx++

			switch op {
			case 0: // Set
				if idx >= len(ops) {
					break
				}
				keyLen := int(ops[idx]%16) + 1
				idx++
				if idx+keyLen > len(ops) {
					break
				}
				key := string(ops[idx : idx+keyLen])
				idx += keyLen

				c.Set(key, "fuzz_val", 0)

			case 1: // Get
				if idx >= len(ops) {
					break
				}
				keyLen := int(ops[idx]%16) + 1
				idx++
				if idx+keyLen > len(ops) {
					break
				}
				key := string(ops[idx : idx+keyLen])
				idx += keyLen

				_, _ = c.Get(key)

			case 2: // Delete
				if idx >= len(ops) {
					break
				}
				keyLen := int(ops[idx]%16) + 1
				idx++
				if idx+keyLen > len(ops) {
					break
				}
				key := string(ops[idx : idx+keyLen])
				idx += keyLen

				c.Delete(key)

			case 3: // Len
				_ = c.Len()
			}

			// Invariant check: map and list must have identical length
			c.mu.Lock()
			mapLen := len(c.items)
			listLen := c.order.Len()
			capVal := c.cap
			c.mu.Unlock()

			if mapLen != listLen {
				t.Fatalf("parity mismatch: map has %d items, list has %d items", mapLen, listLen)
			}
			if mapLen > capVal {
				t.Fatalf("capacity exceeded: map has %d items, cap is %d", mapLen, capVal)
			}
		}
	})
}

// FuzzLRUKeyFormatting fuzzes key storage across binary, null byte, unicode, and extreme length strings.
func FuzzLRUKeyFormatting(f *testing.F) {
	f.Add("")
	f.Add("\x00\x00\x00")
	f.Add("normal_key")
	f.Add("key_with\x00null_byte")
	f.Add("日本語_unicode_key_🌟")
	f.Add(string(bytes.Repeat([]byte("A"), 1024)))

	f.Fuzz(func(t *testing.T, key string) {
		c := New(4)
		c.Set(key, 42, 0)
		val, ok := c.Get(key)
		if !ok || val != 42 {
			t.Fatalf("failed to retrieve key %q: got (%v, %v), want (42, true)", key, val, ok)
		}
		c.Delete(key)
		_, okAfter := c.Get(key)
		if okAfter {
			t.Fatalf("key %q still exists after Delete", key)
		}
	})
}

// ---------------------------------------------------------------------------
// Rapid Property-Based Invariant Tests
// ---------------------------------------------------------------------------

// TestProperty_LRUCapacityBound proves that for any capacity C in [1, 100] and
// any number of unique keys inserted, Len() never exceeds C.
func TestProperty_LRUCapacityBound(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		capVal := rapid.IntRange(1, 50).Draw(rt, "capacity")
		c := New(capVal)

		numInserts := rapid.IntRange(1, capVal*3).Draw(rt, "num_inserts")
		for i := 0; i < numInserts; i++ {
			key := fmt.Sprintf("key_%d", i)
			c.Set(key, i, 0)

			length := c.Len()
			if length > capVal {
				rt.Fatalf("cache length %d exceeded capacity %d after inserting %s", length, capVal, key)
			}
		}
	})
}

// TestProperty_LRUEvictionOrder proves that accessing an element updates its recency,
// and that inserting past capacity evicts the true least-recently-used item.
func TestProperty_LRUEvictionOrder(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		capVal := rapid.IntRange(2, 20).Draw(rt, "capacity")
		c := New(capVal)

		// Fill to exact capacity
		for i := 0; i < capVal; i++ {
			c.Set(fmt.Sprintf("item_%d", i), i, 0)
		}

		// Pick an arbitrary element other than the least-recent (item_0) to touch
		touchIndex := rapid.IntRange(0, capVal-1).Draw(rt, "touch_index")
		touchedKey := fmt.Sprintf("item_%d", touchIndex)
		val, ok := c.Get(touchedKey)
		if !ok || val != touchIndex {
			rt.Fatalf("failed to get touched key %s: got (%v, %v)", touchedKey, val, ok)
		}

		// Insert a brand new key, triggering one eviction
		newKey := "item_brand_new"
		c.Set(newKey, 999, 0)

		// The touched key MUST still be present
		_, okTouched := c.Get(touchedKey)
		if !okTouched {
			rt.Fatalf("recently touched key %s was incorrectly evicted after new insertion", touchedKey)
		}

		// If touched key was NOT item_0, then item_0 must have been the one evicted
		if touchIndex != 0 {
			_, okEvicted := c.Get("item_0")
			if okEvicted {
				rt.Fatalf("least-recently-used item_0 should have been evicted, but was still present")
			}
		}
	})
}

// TestProperty_TTLExpiration proves that entries with TTLs are retrievable immediately,
// and after TTL expires, Get() returns (nil, false) and purges the expired node.
func TestProperty_TTLExpiration(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		c := New(10)
		key := rapid.StringMatching(`^[a-z0-9]{3,8}$`).Draw(rt, "key")
		val := rapid.Int().Draw(rt, "val")

		// Insert with 5ms TTL
		ttl := 5 * time.Millisecond
		c.Set(key, val, ttl)

		// Immediate get must hit
		v, ok := c.Get(key)
		if !ok || v != val {
			rt.Fatalf("immediate Get(%s) failed: got (%v, %v), want (%v, true)", key, v, ok, val)
		}

		// Sleep past TTL
		time.Sleep(10 * time.Millisecond)

		// Expired get must miss
		vExpired, okExpired := c.Get(key)
		if okExpired || vExpired != nil {
			rt.Fatalf("expired Get(%s) should return (nil, false), got (%v, %v)", key, vExpired, okExpired)
		}

		// Verify it was purged from cache
		c.mu.Lock()
		_, inMap := c.items[key]
		c.mu.Unlock()
		if inMap {
			rt.Fatalf("expired key %s was not purged from internal map after Get", key)
		}
	})
}

// TestProperty_ConcurrentSafetyAndParity drives high-concurrency read/write/delete operations
// across multiple goroutines, asserting zero panics and complete map/list parity.
func TestProperty_ConcurrentSafetyAndParity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		c := New(25)
		workers := 8
		opsPerWorker := 200

		var wg sync.WaitGroup
		wg.Add(workers)

		for w := 0; w < workers; w++ {
			workerID := w
			go func() {
				defer wg.Done()
				for i := 0; i < opsPerWorker; i++ {
					key := fmt.Sprintf("k_%d_%d", workerID, i%10)
					switch i % 3 {
					case 0:
						c.Set(key, i, 0)
					case 1:
						_, _ = c.Get(key)
					case 2:
						c.Delete(key)
					}
				}
			}()
		}

		wg.Wait()

		// Final state check: map length == list length <= cap
		c.mu.Lock()
		defer c.mu.Unlock()
		if len(c.items) != c.order.Len() {
			rt.Fatalf("concurrent parity violation: map=%d list=%d", len(c.items), c.order.Len())
		}
		if len(c.items) > c.cap {
			rt.Fatalf("concurrent capacity violation: map=%d cap=%d", len(c.items), c.cap)
		}
	})
}

// ---------------------------------------------------------------------------
// Micro-Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkLRUSet(b *testing.B) {
	c := New(b.N + 1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set("bench_key", i, 0)
	}
}

func BenchmarkLRUSetWithEviction(b *testing.B) {
	c := New(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("k_%d", i)
		c.Set(key, i, 0)
	}
}

func BenchmarkLRUGetHit(b *testing.B) {
	c := New(100)
	c.Set("hit_key", 42, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Get("hit_key")
	}
}

func BenchmarkLRUGetMiss(b *testing.B) {
	c := New(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Get("miss_key")
	}
}

func BenchmarkLRUConcurrent(b *testing.B) {
	c := New(1000)
	for i := 0; i < 500; i++ {
		c.Set(fmt.Sprintf("init_%d", i), i, 0)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("k_%d", i%200)
			if i%4 == 0 {
				c.Set(key, i, 0)
			} else {
				_, _ = c.Get(key)
			}
			i++
		}
	})
}
