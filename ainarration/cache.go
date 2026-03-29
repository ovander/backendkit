package ainarration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ────────────────────────────────────────────────────────────────────────────
// NarrationCacher — interface
// ────────────────────────────────────────────────────────────────────────────

// NarrationCacher is the interface satisfied by all cache implementations.
// tenantID is accepted so DB-backed implementations can scope storage per
// tenant. The in-memory implementation ignores it (the content hash in the
// key already provides effective tenant isolation).
type NarrationCacher interface {
	Get(tenantID uuid.UUID, key string) (*NarrationOutput, bool)
	Put(tenantID uuid.UUID, key string, output *NarrationOutput)
	Flush()
	Size() int
}

// ────────────────────────────────────────────────────────────────────────────
// Configuration
// ────────────────────────────────────────────────────────────────────────────

const (
	// DefaultCacheSize is the maximum number of cached entries.
	// Each NarrationOutput is ~1–4 KB, so 200 entries ≈ < 1 MB.
	DefaultCacheSize = 200
	// DefaultCacheTTL is the time after which a cached entry is expired.
	DefaultCacheTTL = 2 * time.Hour
)

// CacheConfig holds tunable parameters for the narration cache.
type CacheConfig struct {
	MaxSize int
	TTL     time.Duration
}

// DefaultCacheConfig returns the recommended production defaults.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{MaxSize: DefaultCacheSize, TTL: DefaultCacheTTL}
}

// ────────────────────────────────────────────────────────────────────────────
// NarrationCache — in-memory LRU + TTL
// ────────────────────────────────────────────────────────────────────────────

// NarrationCache is an in-memory LRU+TTL cache of AI narration results.
// It is safe for concurrent use.
type NarrationCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	order   []string // oldest first
	cfg     CacheConfig
}

type cacheEntry struct {
	output    *NarrationOutput
	createdAt time.Time
}

// NewNarrationCache creates a cache with the given configuration.
func NewNarrationCache(cfg CacheConfig) *NarrationCache {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = DefaultCacheSize
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultCacheTTL
	}
	return &NarrationCache{
		entries: make(map[string]*cacheEntry, cfg.MaxSize),
		order:   make([]string, 0, cfg.MaxSize),
		cfg:     cfg,
	}
}

// Get retrieves a cached entry. Returns (nil, false) on miss or expiry.
func (c *NarrationCache) Get(_ uuid.UUID, key string) (*NarrationOutput, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if time.Since(e.createdAt) > c.cfg.TTL {
		c.mu.Lock()
		delete(c.entries, key)
		c.removeFromOrder(key)
		c.mu.Unlock()
		return nil, false
	}

	// Promote to MRU.
	c.mu.Lock()
	c.moveToEnd(key)
	c.mu.Unlock()
	return e.output, true
}

// Put stores output under key. Evicts the LRU entry when at capacity.
func (c *NarrationCache) Put(_ uuid.UUID, key string, output *NarrationOutput) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; exists {
		c.entries[key] = &cacheEntry{output: output, createdAt: time.Now()}
		c.moveToEnd(key)
		return
	}

	for len(c.entries) >= c.cfg.MaxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}

	c.entries[key] = &cacheEntry{output: output, createdAt: time.Now()}
	c.order = append(c.order, key)
}

// Size returns the current number of cached entries.
func (c *NarrationCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Flush empties the cache. Useful in tests.
func (c *NarrationCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry, c.cfg.MaxSize)
	c.order = c.order[:0]
}

func (c *NarrationCache) moveToEnd(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append(c.order, key)
			return
		}
	}
}

func (c *NarrationCache) removeFromOrder(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Cache key computation
// ────────────────────────────────────────────────────────────────────────────

// CacheKey computes a deterministic cache key from a narration context value.
//
// Key format: "<featureType>:<role>:<sha256-prefix-16-chars>"
//
// The SHA-256 is computed over the canonical JSON serialisation of ctx (which
// must be JSON-serialisable). The first 16 hex characters (64 bits of entropy)
// are used; the collision probability within a 200-entry cache is negligible.
//
// Both featureType and role are surfaced in the prefix so keys are readable in
// logs and traces.
//
// Example:
//
//	key := ainarration.CacheKey("plan_narration", "editor", myContext)
func CacheKey(featureType, role string, ctx any) string {
	b, err := json.Marshal(ctx)
	if err != nil {
		// Fallback: uncacheable key (unreachable in practice with well-formed structs).
		return fmt.Sprintf("err:uncacheable:%d", time.Now().UnixNano())
	}

	sum := sha256.Sum256(b)
	prefix := hex.EncodeToString(sum[:])[:16]

	if role == "" {
		role = "unknown"
	}
	if featureType == "" {
		featureType = "unknown"
	}
	return fmt.Sprintf("%s:%s:%s", featureType, role, prefix)
}
