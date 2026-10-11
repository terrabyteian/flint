package pypi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository with a size limit evicts its least recently pulled
// files and core-metadata files when what it caches exceeds the limit, as
// OCI proxy repositories do (see upstream.CacheTracker). Pull times are
// persisted under pypi\0pulled\0... in periodic batches. Eviction deletes
// the cached record; the bytes stay in the blob store until garbage
// collection reclaims what nothing links any more. Project pages are not
// counted: they are small, and needed to serve anything at all.

// Size-limit intervals and batch sizes.
const (
	// PullFlushInterval is how often last-pull times are persisted.
	PullFlushInterval = time.Minute
	pullBatch         = 1000
	evictBatch        = 100
)

// trackers returns the size-limited proxy repositories' trackers.
func (h *Handler) trackers() []*upstream.CacheTracker {
	var out []*upstream.CacheTracker
	for _, rp := range h.repos {
		if rp.proxy != nil && rp.proxy.cache != nil {
			out = append(out, rp.proxy.cache)
		}
	}
	slices.SortFunc(out, func(a, b *upstream.CacheTracker) int { return strings.Compare(a.Repo(), b.Repo()) })
	return out
}

// loadTrackers loads what the size-limited proxy repositories cache, and
// asks for an eviction if one is over its limit.
func (h *Handler) loadTrackers() error {
	v := h.view()
	defer v.Release()
	for _, c := range h.trackers() {
		if err := loadTracker(c, v); err != nil {
			return fmt.Errorf("pypi: loading the cache of proxy repository %s: %w", c.Repo(), err)
		}
		h.pm.CachedBytes.With(c.Repo()).Set(float64(c.Size()))
		if c.Size() > c.Limit() {
			h.kickEviction()
		}
	}
	return nil
}

// loadTracker loads the cached items of c's repository, and their pull
// times, from v.
func loadTracker(c *upstream.CacheTracker, v meta.View) error {
	var failure error
	for _, ns := range []string{nsFile, nsMetadata} {
		pfx := key(ns, c.Repo(), "")
		v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
			if ns == nsFile {
				f, err := decodeFile(rec.Value)
				if err != nil {
					failure = err
					return false
				}
				c.Load(string(k), f.Size)
				return true
			}
			b, err := decodeBlobRecord(rec.Value)
			if err != nil {
				failure = err
				return false
			}
			c.Load(string(k), b.Size)
			return true
		})
		if failure != nil {
			return failure
		}
		v.Scan(pulledKey(pfx), nil, func(k []byte, rec meta.Record) bool {
			d := newDec(rec.Value)
			t := d.varint()
			if failure = d.done(); failure != nil {
				return false
			}
			c.LoadPulled("pypi\x00"+string(k[len(nsPulled):]), t)
			return true
		})
		if failure != nil {
			return failure
		}
	}
	return nil
}

func (h *Handler) kickEviction() {
	select {
	case h.evictKick <- struct{}{}:
	default:
	}
}

// track records content cached in rp, and asks for an eviction if rp is
// now over its size limit.
func (h *Handler) track(rp *repository, k []byte, size int64) {
	c := rp.proxy.cache
	if c == nil {
		return
	}
	over := c.Add(k, size, h.now())
	h.pm.CachedBytes.With(c.Repo()).Set(float64(c.Size()))
	if over {
		h.kickEviction()
	}
}

// touch records a pull of content cached in rp.
func (h *Handler) touch(rp *repository, k []byte) {
	if c := rp.proxy.cache; c != nil {
		c.Touch(k, h.now())
	}
}

// FlushPullTimes persists the last-pull times recorded since the last
// flush.
func (h *Handler) FlushPullTimes(ctx context.Context) error {
	for _, c := range h.trackers() {
		dirty := c.TakeDirty()
		keys := make([]string, 0, len(dirty))
		for k := range dirty {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for len(keys) > 0 {
			chunk := keys[:min(len(keys), pullBatch)]
			keys = keys[len(chunk):]
			var b meta.Batch
			for _, k := range chunk {
				b.Put(pulledKey([]byte(k)), newEnc().varint(dirty[k]))
			}
			b.SetOrigin(meta.Origin{Actor: "system", Action: "pypi.proxy.pulled", Target: c.Repo()})
			if _, err := h.meta.Commit(ctx, &b); err != nil {
				c.MarkDirty(chunk)
				c.MarkDirty(keys)
				return err
			}
		}
	}
	return nil
}

// Evict evicts the least recently pulled content of every size-limited
// proxy repository that exceeds its limit.
func (h *Handler) Evict(ctx context.Context) error {
	for _, c := range h.trackers() {
		victims := c.Victims()
		for len(victims) > 0 {
			chunk := victims[:min(len(victims), evictBatch)]
			victims = victims[len(chunk):]
			if err := h.evict(ctx, c, chunk); err != nil {
				return err
			}
		}
		h.pm.CachedBytes.With(c.Repo()).Set(float64(c.Size()))
	}
	return nil
}

// evict removes cached items of c's repository in one batch, each
// required unchanged, so an item cached again meanwhile is not removed
// behind the tracker's back; such a conflict fails the batch, and the next
// eviction decides again.
func (h *Handler) evict(ctx context.Context, c *upstream.CacheTracker, keys []string) error {
	var b meta.Batch
	var gone []string
	v := h.view()
	for _, k := range keys {
		rec, ok := v.Get([]byte(k))
		if !ok {
			gone = append(gone, k)
			continue
		}
		b.Require([]byte(k), rec.Version)
		b.Delete([]byte(k))
		b.Delete(pulledKey([]byte(k)))
	}
	v.Release()
	c.Remove(gone)
	if len(gone) == len(keys) {
		return nil
	}
	b.SetOrigin(meta.Origin{Actor: "system", Action: "pypi.proxy.evict",
		Target: c.Repo() + ": least recently pulled content over the size limit"})
	if _, err := h.meta.Commit(ctx, &b); err != nil {
		if errors.Is(err, meta.ErrConflict) {
			return nil
		}
		return err
	}
	c.Remove(keys)
	h.pm.Evictions.With(c.Repo()).Add(float64(len(keys) - len(gone)))
	return nil
}

// RunProxy runs the proxy repositories' background work until ctx is
// done: it persists last-pull times, evicts content over size limits, and
// forgets stale page confirmations. Before returning, it persists the
// pull times once more.
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
	t := time.NewTicker(PullFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := h.FlushPullTimes(fctx); err != nil {
				h.log.Warn("persisting proxy pull times", "err", err)
			}
			cancel()
			return
		case <-t.C:
			if err := h.FlushPullTimes(ctx); err != nil && ctx.Err() == nil {
				h.log.Warn("persisting proxy pull times", "err", err)
			}
			h.fresh.Prune(window)
		case <-h.evictKick:
			if err := h.Evict(ctx); err != nil && ctx.Err() == nil {
				h.log.Warn("evicting proxy content over its size limit", "err", err)
			}
		}
	}
}
