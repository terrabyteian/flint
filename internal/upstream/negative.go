package upstream

import (
	"sync"
	"time"
)

// DefaultNotFoundTTL is how long a path-addressed proxy repository
// remembers that its upstream does not have something.
const DefaultNotFoundTTL = time.Minute

// maxNegative bounds a NegativeCache; when it is full, expired entries
// are dropped, and if none are, every entry is.
const maxNegative = 100000

// NegativeCache remembers upstream not-found answers in memory for a
// short time, so a burst of requests for content that does not exist,
// such as a build tool probing every repository for sources and
// documentation it never finds, costs one upstream request per window
// rather than one each. Keys are chosen by the caller and should name
// the repository.
type NegativeCache struct {
	now func() time.Time

	mu sync.Mutex
	m  map[string]time.Time // expiry by key
}

// NewNegativeCache returns an empty NegativeCache; now is the clock, nil
// meaning time.Now.
func NewNegativeCache(now func() time.Time) *NegativeCache {
	if now == nil {
		now = time.Now
	}
	return &NegativeCache{now: now, m: map[string]time.Time{}}
}

// Remember records that the upstream does not have key, for ttl.
func (n *NegativeCache) Remember(key string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if len(n.m) >= maxNegative {
		n.prune(now)
		if len(n.m) >= maxNegative {
			clear(n.m)
		}
	}
	n.m[key] = now.Add(ttl)
}

// Known reports whether the upstream answered that it does not have key
// within the time Remember was given.
func (n *NegativeCache) Known(key string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	exp, ok := n.m[key]
	if ok && !n.now().Before(exp) {
		delete(n.m, key)
		return false
	}
	return ok
}

// Forget drops key, such as once the content is cached after all.
func (n *NegativeCache) Forget(key string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.m, key)
}

// Prune drops expired entries.
func (n *NegativeCache) Prune() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.prune(n.now())
}

func (n *NegativeCache) prune(now time.Time) {
	for k, exp := range n.m {
		if !now.Before(exp) {
			delete(n.m, k)
		}
	}
}

// Len returns the number of entries, expired ones included until pruned.
func (n *NegativeCache) Len() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.m)
}
