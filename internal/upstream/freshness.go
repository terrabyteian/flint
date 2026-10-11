package upstream

import (
	"errors"
	"sync"
	"time"
)

// Freshness remembers when upstreams last confirmed mutable content, such
// as a tag or a package listing, so a proxy serves its cached copy
// without asking again within its revalidation window. Confirmations are
// kept in memory only: after a restart, each item is revalidated on its
// first use. Keys are chosen by the caller and should name the
// repository.
type Freshness struct {
	now func() time.Time

	mu sync.Mutex
	m  map[string]time.Time
}

// NewFreshness returns an empty Freshness; now is the clock, nil meaning
// time.Now.
func NewFreshness(now func() time.Time) *Freshness {
	if now == nil {
		now = time.Now
	}
	return &Freshness{now: now, m: map[string]time.Time{}}
}

// Fresh reports whether the upstream confirmed key within window.
func (f *Freshness) Fresh(key string, window time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.m[key]
	return ok && f.now().Sub(t) < window
}

// Confirm records that the upstream confirmed key now.
func (f *Freshness) Confirm(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[key] = f.now()
}

// Forget drops the confirmation of key.
func (f *Freshness) Forget(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, key)
}

// Prune forgets confirmations older than window, the longest window any
// caller trusts, so the map stays as small as the set of recently used
// items.
func (f *Freshness) Prune(window time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	for k, t := range f.m {
		if now.Sub(t) >= window {
			delete(f.m, k)
		}
	}
}

// Answered reports whether a failed upstream request is the upstream's
// answer about the content, that it is not found or denied, rather than a
// failure to reach the upstream or to authenticate to it. A proxy answers
// not found for content the upstream answered for, even if it has a
// cached copy, and serves its cached copy otherwise.
func Answered(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, ErrDenied)
}
