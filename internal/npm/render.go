package npm

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// DefaultRenderBudget is the default bound on the bytes of rendered
// packuments kept in memory.
const DefaultRenderBudget = 64 << 20

// renderCache keeps rendered packuments in memory, least recently used
// first out, within a byte budget. A key names the package's state and
// everything the rendering depends on, so an entry never goes stale; an
// entry larger than a quarter of the budget is not kept.
type renderCache struct {
	mu     sync.Mutex
	budget int64
	size   int64
	lru    *list.List // of *rendered, most recently used first
	byKey  map[string]*list.Element
}

type rendered struct {
	key  string
	body []byte
	etag string
}

func newRenderCache(budget int64) *renderCache {
	if budget <= 0 {
		budget = DefaultRenderBudget
	}
	return &renderCache{budget: budget, lru: list.New(), byKey: map[string]*list.Element{}}
}

// get returns the rendering cached under key, if any. The empty key is
// never cached.
func (c *renderCache) get(key string) (body []byte, etag string, ok bool) {
	if key == "" {
		return nil, "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byKey[key]
	if !ok {
		return nil, "", false
	}
	c.lru.MoveToFront(e)
	r := e.Value.(*rendered)
	return r.body, r.etag, true
}

// put caches body under key, unless key is empty or body too large, and
// returns its ETag.
func (c *renderCache) put(key string, body []byte) string {
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	n := int64(len(body)) + int64(len(key))
	if key == "" || n > c.budget/4 {
		return etag
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.byKey[key]; ok {
		return etag
	}
	c.byKey[key] = c.lru.PushFront(&rendered{key: key, body: body, etag: etag})
	c.size += n
	for c.size > c.budget {
		e := c.lru.Back()
		r := e.Value.(*rendered)
		c.lru.Remove(e)
		delete(c.byKey, r.key)
		c.size -= int64(len(r.body)) + int64(len(r.key))
	}
	return etag
}
