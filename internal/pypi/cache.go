package pypi

import (
	"context"
	"fmt"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository with a size limit evicts its least recently pulled
// files and core-metadata files when what it caches exceeds the limit, as
// OCI proxy repositories do (see upstream.Limits). Pull times are
// persisted under pypi\0pulled\0... in periodic batches. Eviction deletes
// the cached record; the bytes stay in the blob store until garbage
// collection reclaims what nothing links any more. Project pages are not
// counted: they are small, and needed to serve anything at all.

// PullFlushInterval is how often last-pull times are persisted.
const PullFlushInterval = upstream.PullFlushInterval

// loadTrackers loads what the size-limited proxy repositories cache, and
// asks for an eviction if one is over its limit.
func (h *Handler) loadTrackers() error {
	v := h.view()
	defer v.Release()
	for _, rp := range h.repos {
		if rp.proxy == nil || rp.proxy.cache == nil {
			continue
		}
		c := rp.proxy.cache
		if err := h.loadTracker(c, v); err != nil {
			return fmt.Errorf("pypi: loading the cache of proxy repository %s: %w", c.Repo(), err)
		}
		h.limits.Add(c)
	}
	return nil
}

// loadTracker loads the cached items of c's repository, and their pull
// times, from v.
func (h *Handler) loadTracker(c *upstream.CacheTracker, v meta.View) error {
	for _, ns := range []string{nsFile, nsMetadata} {
		var failure error
		pfx := key(ns, c.Repo(), "")
		v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
			f, err := decodeFile(rec.Value)
			if err != nil {
				failure = err
				return false
			}
			c.Load(string(k), f.Size)
			return true
		})
		if failure == nil {
			failure = h.limits.LoadPulled(c, v, pfx)
		}
		if failure != nil {
			return failure
		}
	}
	return nil
}

// track records content cached in rp, and asks for an eviction if rp is
// now over its size limit.
func (h *Handler) track(rp *repository, k []byte, size int64) {
	h.limits.Track(rp.proxy.cache, k, size)
}

// touch records a pull of content cached in rp.
func (h *Handler) touch(rp *repository, k []byte) {
	h.limits.Touch(rp.proxy.cache, k)
}

// FlushPullTimes persists the last-pull times recorded since the last
// flush.
func (h *Handler) FlushPullTimes(ctx context.Context) error { return h.limits.Flush(ctx) }

// Evict evicts the least recently pulled content of every size-limited
// proxy repository that exceeds its limit.
func (h *Handler) Evict(ctx context.Context) error { return h.limits.Evict(ctx) }

// RunProxy runs the proxy repositories' background work until ctx is
// done: it persists last-pull times, evicts content over size limits, and,
// if the handler has its own document cache, forgets stale page
// confirmations. Before returning, it persists the pull times once more.
func (h *Handler) RunProxy(ctx context.Context) {
	if !h.hasProxy {
		return
	}
	var window time.Duration
	for _, rp := range h.repos {
		if rp.proxy != nil {
			window = max(window, rp.proxy.revalidate)
		}
	}
	h.limits.Run(ctx, func(msg string, err error) { h.log.Warn(msg, "err", err) }, func() {
		if h.ownDocs {
			h.docs.Prune(window)
		}
	})
}

// dropPageRecords deletes the project page records that proxy
// repositories wrote before pages moved to the shared document cache
// (cache\0doc\0...). They were only a cache: a page is fetched again on
// its next request, and garbage collection reclaims the old page blobs.
func (h *Handler) dropPageRecords(ctx context.Context) error {
	for {
		var b meta.Batch
		n := 0
		v := h.view()
		v.Scan([]byte(nsPage), nil, func(k []byte, rec meta.Record) bool {
			b.Require(k, rec.Version)
			b.Delete(k)
			n++
			return n < 1000
		})
		v.Release()
		if n == 0 {
			return nil
		}
		b.SetOrigin(meta.Origin{Actor: meta.ActorSystem, Action: "pypi.proxy.migrate",
			Target: "project pages moved to the shared document cache"})
		if _, err := h.meta.Commit(ctx, &b); err != nil {
			return fmt.Errorf("pypi: dropping old project page records: %w", err)
		}
	}
}
