package ainarration_test

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/ainarration"
)

// ExampleNarrationCache demonstrates the basic get/put cycle and how the cache
// reports a miss before any entry is stored.
func ExampleNarrationCache() {
	cache := ainarration.NewNarrationCache(ainarration.DefaultCacheConfig())

	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	key := "plan_narration:admin:abc123def456"

	// Cache miss on a fresh cache.
	if _, ok := cache.Get(tenantID, key); !ok {
		fmt.Println("miss")
	}

	// Store a narration result.
	cache.Put(tenantID, key, &ainarration.NarrationOutput{
		Narrative: "Your plan is performing well.",
		Metadata:  map[string]any{"model": "claude-sonnet-4-6", "tokens": 142},
	})

	// Cache hit.
	if out, ok := cache.Get(tenantID, key); ok {
		fmt.Println("hit:", out.Narrative)
	}

	// Output:
	// miss
	// hit: Your plan is performing well.
}

// ExampleCacheKey demonstrates the deterministic content-addressed key
// format: featureType:role:hexprefix.
func ExampleCacheKey() {
	type myCtx struct {
		UserID string
		Metric string
	}

	ctx := myCtx{UserID: "u-1", Metric: "revenue"}

	key1 := ainarration.CacheKey("plan_narration", "admin", ctx)
	key2 := ainarration.CacheKey("plan_narration", "admin", ctx)

	// Same inputs → same key every time.
	fmt.Println(key1 == key2)

	// Different role → different key.
	key3 := ainarration.CacheKey("plan_narration", "viewer", ctx)
	fmt.Println(key1 == key3)

	// Output:
	// true
	// false
}

// ExampleNarrationCache_Size demonstrates the Size method returning the total
// number of entries currently held in the cache.
func ExampleNarrationCache_Size() {
	cache := ainarration.NewNarrationCache(ainarration.DefaultCacheConfig())

	t1 := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	t2 := uuid.MustParse("00000000-0000-0000-0000-000000000002")

	cache.Put(t1, "key-a", &ainarration.NarrationOutput{Narrative: "A"})
	cache.Put(t2, "key-b", &ainarration.NarrationOutput{Narrative: "B"})
	fmt.Println(cache.Size())

	cache.Flush()
	fmt.Println(cache.Size())

	// Output:
	// 2
	// 0
}
