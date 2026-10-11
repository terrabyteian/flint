package upstream

import (
	"cmp"
	"slices"
	"strings"
	"sync"
	"time"
)

// CacheTracker tracks the content a size-limited proxy repository caches,
// so the least recently pulled content can be evicted when the
// repository exceeds its limit. It holds every cached item in memory: its
// metadata key, its size, and the time it was last pulled. The format
// package that owns the keys loads the items at startup, persists the
// pull times it takes from TakeDirty in periodic batches rather than one
// metadata write per pull, and deletes the records Victims names. An item
// with no recorded pull time counts as never pulled.
type CacheTracker struct {
	repo  string
	limit int64

	mu    sync.Mutex
	items map[string]*cacheItem // by metadata key
	total int64
	dirty map[string]bool // items whose pull time is not persisted yet
}

// cacheItem is a cached item.
type cacheItem struct {
	size   int64
	pulled int64 // Unix seconds of the last pull; 0 if never recorded
}

// NewCacheTracker returns a tracker for repository repo, limited to
// limit bytes.
func NewCacheTracker(repo string, limit int64) *CacheTracker {
	return &CacheTracker{repo: repo, limit: limit, items: map[string]*cacheItem{}, dirty: map[string]bool{}}
}

// Repo returns the repository's name.
func (c *CacheTracker) Repo() string { return c.repo }

// Limit returns the repository's size limit in bytes.
func (c *CacheTracker) Limit() int64 { return c.limit }

// Load records an item found in the metadata store at startup.
func (c *CacheTracker) Load(key string, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if it := c.items[key]; it != nil {
		c.total -= it.size
	}
	c.items[key] = &cacheItem{size: size}
	c.total += size
}

// LoadPulled records the persisted last-pull time, in Unix seconds, of an
// item loaded before.
func (c *CacheTracker) LoadPulled(key string, pulled int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if it := c.items[key]; it != nil {
		it.pulled = pulled
	}
}

// Add records a newly cached item. It reports whether the repository is
// now over its limit.
func (c *CacheTracker) Add(key []byte, size int64, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := string(key)
	if it := c.items[k]; it != nil {
		c.total += size - it.size
		it.size = size
	} else {
		c.items[k] = &cacheItem{size: size}
		c.total += size
	}
	c.items[k].pulled = now.Unix()
	c.dirty[k] = true
	return c.total > c.limit
}

// Touch records a pull of a cached item.
func (c *CacheTracker) Touch(key []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := string(key)
	if it := c.items[k]; it != nil && it.pulled != now.Unix() {
		it.pulled = now.Unix()
		c.dirty[k] = true
	}
}

// Size returns the bytes cached.
func (c *CacheTracker) Size() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// TakeDirty returns the pull times not yet persisted, in Unix seconds by
// key, and forgets that they are dirty.
func (c *CacheTracker) TakeDirty() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.dirty))
	for k := range c.dirty {
		if it := c.items[k]; it != nil {
			out[k] = it.pulled
		}
	}
	clear(c.dirty)
	return out
}

// MarkDirty marks pull times dirty again after a failed flush.
func (c *CacheTracker) MarkDirty(keys []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		if c.items[k] != nil {
			c.dirty[k] = true
		}
	}
}

// Victims returns the least recently pulled items whose removal brings
// the repository within its limit, oldest first.
func (c *CacheTracker) Victims() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total <= c.limit {
		return nil
	}
	keys := make([]string, 0, len(c.items))
	for k := range c.items {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		return cmp.Or(cmp.Compare(c.items[a].pulled, c.items[b].pulled), strings.Compare(a, b))
	})
	var out []string
	over := c.total - c.limit
	for _, k := range keys {
		if over <= 0 {
			break
		}
		out = append(out, k)
		over -= c.items[k].size
	}
	return out
}

// Remove forgets evicted items.
func (c *CacheTracker) Remove(keys []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		if it := c.items[k]; it != nil {
			c.total -= it.size
			delete(c.items, k)
			delete(c.dirty, k)
		}
	}
}
