package oci

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository with a size limit evicts its least recently pulled
// content when the content it caches exceeds the limit. Without a limit,
// nothing is tracked and nothing is evicted.
//
// The tracker holds every cached item of the repository in memory: each
// blob link and manifest record, with its size and the time it was last
// pulled. Pull times are persisted under
//
//	oci\0pulled\0blob\0<repo>\0<name>\0<digest>       last pull of a blob link
//	oci\0pulled\0manifest\0<repo>\0<name>\0<digest>   last pull of a manifest
//
// in periodic batches rather than one metadata write per pull, so a
// restart loses at most one flush interval of pull times. An item with
// no persisted time counts as never pulled.
//
// Eviction removes the item's metadata: the blob link, or the manifest
// record with the tags that point to it and its referrers entry. The
// bytes stay in the blob store, as for any delete, until garbage
// collection reclaims what nothing links any more.

// Size-limit intervals and batch sizes.
const (
	// PullFlushInterval is how often last-pull times are persisted.
	PullFlushInterval = time.Minute
	// pullBatch bounds the pull times persisted in one batch.
	pullBatch = 1000
	// evictBatch bounds the items evicted in one batch.
	evictBatch = 100
)

const nsPulled = "oci\x00pulled\x00"

// pulledKey returns the pull-time key of an item's metadata key, which
// starts with "oci\0".
func pulledKey(key []byte) []byte {
	return append([]byte(nsPulled), key[len("oci\x00"):]...)
}

// cacheItem is a cached blob link or manifest record.
type cacheItem struct {
	size   int64
	pulled int64 // Unix seconds of the last pull; 0 if never recorded
}

// cacheTracker tracks the content cached in a size-limited proxy
// repository.
type cacheTracker struct {
	repo  string
	limit int64

	mu    sync.Mutex
	items map[string]*cacheItem // by metadata key
	total int64
	dirty map[string]bool // items whose pull time is not persisted yet
}

func newCacheTracker(repo string, limit int64) *cacheTracker {
	return &cacheTracker{repo: repo, limit: limit, items: map[string]*cacheItem{}, dirty: map[string]bool{}}
}

// load reads the repository's cached items and their pull times from v.
func (c *cacheTracker) load(v meta.View) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var failure error
	for _, ns := range []string{nsBlob, nsManifest} {
		v.Scan([]byte(ns+c.repo+"\x00"), nil, func(key []byte, rec meta.Record) bool {
			var size int64
			if ns == nsBlob {
				size, failure = decodeBlobLink(rec.Value)
			} else {
				var m *manifestRecord
				if m, failure = decodeManifest(rec.Value); failure == nil {
					size = m.Size
				}
			}
			if failure != nil {
				return false
			}
			c.items[string(key)] = &cacheItem{size: size}
			c.total += size
			return true
		})
		if failure != nil {
			return failure
		}
		pfx := pulledKey([]byte(ns + c.repo + "\x00"))
		v.Scan(pfx, nil, func(key []byte, rec meta.Record) bool {
			d := newDec(rec.Value)
			t := d.varint()
			if failure = d.done(); failure != nil {
				return false
			}
			if it := c.items["oci\x00"+string(key[len(nsPulled):])]; it != nil {
				it.pulled = t
			}
			return true
		})
		if failure != nil {
			return failure
		}
	}
	return nil
}

// add records a newly cached item. It reports whether the repository is
// now over its limit.
func (c *cacheTracker) add(key []byte, size int64, now time.Time) bool {
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

// touch records a pull of a cached item.
func (c *cacheTracker) touch(key []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := string(key)
	if it := c.items[k]; it != nil && it.pulled != now.Unix() {
		it.pulled = now.Unix()
		c.dirty[k] = true
	}
}

// size returns the bytes cached.
func (c *cacheTracker) size() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// takeDirty returns the pull times not yet persisted, and forgets that
// they are dirty.
func (c *cacheTracker) takeDirty() map[string]int64 {
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

// markDirty marks pull times dirty again after a failed flush.
func (c *cacheTracker) markDirty(keys []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		if c.items[k] != nil {
			c.dirty[k] = true
		}
	}
}

// victims returns the least recently pulled items whose removal brings
// the repository within its limit, oldest first.
func (c *cacheTracker) victims() []string {
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

// remove forgets evicted items.
func (c *cacheTracker) remove(keys []string) {
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

// track records content cached in rn's repository, and asks for an
// eviction if it is now over its size limit.
func (h *Handler) track(rn *repoName, key []byte, size int64) {
	c := rn.cfg.proxy.cache
	if c == nil {
		return
	}
	over := c.add(key, size, h.now())
	h.cachedBytes.With(c.repo).Set(float64(c.size()))
	if over {
		select {
		case h.evictKick <- struct{}{}:
		default:
		}
	}
}

// touch records a pull of cached content in rn's repository.
func (h *Handler) touch(rn *repoName, key []byte) {
	if c := rn.cfg.proxy.cache; c != nil {
		c.touch(key, h.now())
	}
}

// trackers returns the size-limited proxy repositories' trackers.
func (h *Handler) trackers() []*cacheTracker {
	var out []*cacheTracker
	for _, rc := range h.repos {
		if rc.proxy != nil && rc.proxy.cache != nil {
			out = append(out, rc.proxy.cache)
		}
	}
	slices.SortFunc(out, func(a, b *cacheTracker) int { return strings.Compare(a.repo, b.repo) })
	return out
}

// FlushPullTimes persists the last-pull times recorded since the last
// flush.
func (h *Handler) FlushPullTimes(ctx context.Context) error {
	for _, c := range h.trackers() {
		dirty := c.takeDirty()
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
			b.SetOrigin(meta.Origin{Actor: "system", Action: "oci.proxy.pulled", Target: c.repo})
			if err := h.commit(ctx, &b); err != nil {
				c.markDirty(chunk)
				c.markDirty(keys)
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
		victims := c.victims()
		for len(victims) > 0 {
			chunk := victims[:min(len(victims), evictBatch)]
			victims = victims[len(chunk):]
			if err := h.evict(ctx, c, chunk); err != nil {
				return err
			}
		}
		h.cachedBytes.With(c.repo).Set(float64(c.size()))
	}
	return nil
}

// evict removes cached items of c's repository in one batch. Each item
// must still be at the version read, so an item cached again meanwhile
// is not removed behind the tracker's back; such a conflict fails the
// batch, and the next eviction run decides again.
func (h *Handler) evict(ctx context.Context, c *cacheTracker, keys []string) error {
	var b meta.Batch
	var gone []string
	v := h.view()
	for _, k := range keys {
		key := []byte(k)
		rec, ok := v.Get(key)
		if !ok {
			gone = append(gone, k)
			continue
		}
		b.Require(key, rec.Version)
		b.Delete(key)
		b.Delete(pulledKey(key))
		if strings.HasPrefix(k, nsManifest) {
			evictManifestRefs(v, &b, h.repos[c.repo], k, rec)
		}
	}
	v.Release()
	c.remove(gone)
	if len(gone) == len(keys) {
		return nil
	}
	b.SetOrigin(meta.Origin{Actor: "system", Action: "oci.proxy.evict",
		Target: c.repo + ": least recently pulled content over the size limit"})
	if err := h.commit(ctx, &b); err != nil {
		if errors.Is(err, meta.ErrConflict) {
			return nil
		}
		return err
	}
	c.remove(keys)
	h.evictions.With(c.repo).Add(float64(len(keys) - len(gone)))
	return nil
}

// evictManifestRefs adds to b the deletion of the tags that point to the
// manifest record at key, and of its referrers entry.
func evictManifestRefs(v meta.View, b *meta.Batch, cfg *repository, key string, rec meta.Record) {
	parts := strings.SplitN(key[len(nsManifest):], "\x00", 3)
	if len(parts) != 3 {
		return
	}
	rn := &repoName{full: parts[0] + "/" + parts[1], repo: parts[0], name: parts[1], cfg: cfg}
	d, err := blob.ParseDigest(parts[2])
	if err != nil {
		return
	}
	if m, err := decodeManifest(rec.Value); err == nil && !m.Subject.IsZero() {
		b.Delete(referrerKey(rn, m.Subject, d))
	}
	pfx := prefix(nsTag, rn)
	want := encodeTag(d)
	v.Scan(pfx, nil, func(k []byte, tr meta.Record) bool {
		if bytes.Equal(tr.Value, want) {
			b.Require(k, tr.Version)
			b.Delete(k)
		}
		return true
	})
}

// RunProxy runs the proxy repositories' background work until ctx is
// done: it watches the free space of the data directory, persists
// last-pull times, evicts content over size limits, and forgets stale
// tag confirmations. Before returning, it persists the pull times once
// more.
func (h *Handler) RunProxy(ctx context.Context) {
	if !h.hasProxy {
		return
	}
	var wg sync.WaitGroup
	if h.space != nil {
		wg.Go(func() { h.space.Run(ctx, upstream.SpaceCheckInterval) })
	}
	defer wg.Wait()
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
			h.pruneValidated()
		case <-h.evictKick:
			if err := h.Evict(ctx); err != nil && ctx.Err() == nil {
				h.log.Warn("evicting proxy content over its size limit", "err", err)
			}
		}
	}
}
