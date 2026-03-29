package ainarration_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/ainarration"
)

var noTenant = uuid.Nil

func output(text string) *ainarration.NarrationOutput {
	return &ainarration.NarrationOutput{Narrative: text}
}

func TestNarrationCache_GetPut(t *testing.T) {
	c := ainarration.NewNarrationCache(ainarration.CacheConfig{MaxSize: 10, TTL: time.Minute})
	c.Put(noTenant, "key1", output("hello"))

	got, ok := c.Get(noTenant, "key1")
	if !ok || got.Narrative != "hello" {
		t.Errorf("expected cached value 'hello', got ok=%v val=%+v", ok, got)
	}
}

func TestNarrationCache_Miss(t *testing.T) {
	c := ainarration.NewNarrationCache(ainarration.DefaultCacheConfig())
	_, ok := c.Get(noTenant, "not-there")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestNarrationCache_TTLExpiry(t *testing.T) {
	c := ainarration.NewNarrationCache(ainarration.CacheConfig{MaxSize: 10, TTL: 1 * time.Millisecond})
	c.Put(noTenant, "k", output("short-lived"))
	time.Sleep(10 * time.Millisecond)
	_, ok := c.Get(noTenant, "k")
	if ok {
		t.Error("expected expired entry to be a miss")
	}
}

func TestNarrationCache_LRUEviction(t *testing.T) {
	c := ainarration.NewNarrationCache(ainarration.CacheConfig{MaxSize: 2, TTL: time.Minute})
	c.Put(noTenant, "a", output("a"))
	c.Put(noTenant, "b", output("b"))
	// Access "a" to make "b" LRU.
	c.Get(noTenant, "a")
	// Adding "c" should evict "b" (LRU).
	c.Put(noTenant, "c", output("c"))

	if _, ok := c.Get(noTenant, "b"); ok {
		t.Error("'b' should have been evicted")
	}
	if _, ok := c.Get(noTenant, "a"); !ok {
		t.Error("'a' should still be in cache")
	}
}

func TestNarrationCache_Size(t *testing.T) {
	c := ainarration.NewNarrationCache(ainarration.CacheConfig{MaxSize: 5, TTL: time.Minute})
	for i := 0; i < 3; i++ {
		c.Put(noTenant, fmt.Sprintf("k%d", i), output("v"))
	}
	if c.Size() != 3 {
		t.Errorf("Size = %d, want 3", c.Size())
	}
}

func TestNarrationCache_Flush(t *testing.T) {
	c := ainarration.NewNarrationCache(ainarration.DefaultCacheConfig())
	c.Put(noTenant, "x", output("x"))
	c.Flush()
	if c.Size() != 0 {
		t.Error("cache should be empty after Flush")
	}
}

func TestCacheKey_Deterministic(t *testing.T) {
	type ctx struct{ Field string }
	k1 := ainarration.CacheKey("narration", "editor", ctx{Field: "abc"})
	k2 := ainarration.CacheKey("narration", "editor", ctx{Field: "abc"})
	if k1 != k2 {
		t.Errorf("CacheKey is not deterministic: %q != %q", k1, k2)
	}
}

func TestCacheKey_DifferentContexts(t *testing.T) {
	type ctx struct{ Field string }
	k1 := ainarration.CacheKey("narration", "editor", ctx{Field: "abc"})
	k2 := ainarration.CacheKey("narration", "editor", ctx{Field: "xyz"})
	if k1 == k2 {
		t.Error("different contexts should produce different keys")
	}
}

func TestCacheKey_Format(t *testing.T) {
	key := ainarration.CacheKey("plan_narration", "owner", map[string]int{"x": 1})
	if len(key) == 0 {
		t.Error("expected non-empty key")
	}
	// Key should start with featureType prefix.
	if key[:len("plan_narration")] != "plan_narration" {
		t.Errorf("key does not start with featureType: %s", key)
	}
}
