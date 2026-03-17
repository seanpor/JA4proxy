package cache

import (
	"testing"
	"time"
)

func TestLRU_SetGet(t *testing.T) {
	c := New(10)
	c.Set("k1", "v1", 0)
	val, ok := c.Get("k1")
	if !ok || val != "v1" {
		t.Errorf("Get: got (%v, %v), want (v1, true)", val, ok)
	}
}

func TestLRU_Missing(t *testing.T) {
	c := New(10)
	_, ok := c.Get("absent")
	if ok {
		t.Error("Get absent key: should return false")
	}
}

func TestLRU_TTLExpiry(t *testing.T) {
	c := New(10)
	c.Set("k1", "v1", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	_, ok := c.Get("k1")
	if ok {
		t.Error("expired entry should not be returned")
	}
}

func TestLRU_TTLNotExpired(t *testing.T) {
	c := New(10)
	c.Set("k1", "v1", 1*time.Hour)
	_, ok := c.Get("k1")
	if !ok {
		t.Error("non-expired entry should be returned")
	}
}

func TestLRU_EvictsLRU(t *testing.T) {
	c := New(3)
	c.Set("a", 1, 0)
	c.Set("b", 2, 0)
	c.Set("c", 3, 0)
	// Access "a" to make "b" the LRU
	c.Get("a")
	c.Get("c")
	// Adding "d" should evict "b"
	c.Set("d", 4, 0)

	_, okB := c.Get("b")
	if okB {
		t.Error("'b' should have been evicted as LRU")
	}
	_, okA := c.Get("a")
	if !okA {
		t.Error("'a' should still be present")
	}
}

func TestLRU_Delete(t *testing.T) {
	c := New(10)
	c.Set("k1", "v1", 0)
	c.Delete("k1")
	_, ok := c.Get("k1")
	if ok {
		t.Error("deleted key should not be retrievable")
	}
}

func TestLRU_Overwrite(t *testing.T) {
	c := New(10)
	c.Set("k1", "v1", 0)
	c.Set("k1", "v2", 0)
	val, ok := c.Get("k1")
	if !ok || val != "v2" {
		t.Errorf("overwrite: got (%v, %v), want (v2, true)", val, ok)
	}
}

func TestLRU_Len(t *testing.T) {
	c := New(10)
	if c.Len() != 0 {
		t.Errorf("empty cache: Len=%d, want 0", c.Len())
	}
	c.Set("a", 1, 0)
	c.Set("b", 2, 0)
	if c.Len() != 2 {
		t.Errorf("after 2 inserts: Len=%d, want 2", c.Len())
	}
}

func TestLRU_ZeroCapFallback(t *testing.T) {
	// cap=0 should not panic; defaults to 1024
	c := New(0)
	c.Set("k", "v", 0)
	_, ok := c.Get("k")
	if !ok {
		t.Error("zero-cap LRU: Get after Set failed")
	}
}
