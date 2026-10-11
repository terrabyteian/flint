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
	m  map[string]negEntry
}

type negEntry struct {
	exp  time.Time
	gone bool // the upstream answered 410
}

// NewNegativeCache returns an empty NegativeCache; now is the clock, nil
// meaning time.Now.
func NewNegativeCache(now func() time.Time) *NegativeCache {
	if now == nil {
		now = time.Now
	}
	return &NegativeCache{now: now, m: map[string]negEntry{}}
}

// Remember records that the upstream does not have key, for ttl; gone
// records that it answered 410 rather than 404.
func (n *NegativeCache) Remember(key string, gone bool, ttl time.Duration) {
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
	n.m[key] = negEntry{exp: now.Add(ttl), gone: gone}
}

// Known reports whether the upstream answered that it does not have key
// within the time Remember was given, and whether that answer was 410.
func (n *NegativeCache) Known(key string) (known, gone bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	e, ok := n.m[key]
	if ok && !n.now().Before(e.exp) {
		delete(n.m, key)
		return false, false
	}
	return ok, e.gone
}

// Prune drops expired entries.
func (n *NegativeCache) Prune() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.prune(n.now())
}

func (n *NegativeCache) prune(now time.Time) {
	for k, e := range n.m {
		if !now.Before(e.exp) {
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
