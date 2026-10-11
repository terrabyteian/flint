package oci

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository with a size limit evicts its least recently pulled
// content when the content it caches exceeds the limit. Without a limit,
// nothing is tracked and nothing is evicted.
//
// The tracker (upstream.CacheTracker) holds every cached item of the
// repository in memory: each blob link and manifest record, with its size
// and the time it was last pulled. Pull times are persisted under
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

// loadTracker loads the cached items of c's repository, and their pull
// times, from v.
func loadTracker(c *upstream.CacheTracker, v meta.View) error {
	var failure error
	for _, ns := range []string{nsBlob, nsManifest} {
		v.Scan([]byte(ns+c.Repo()+"\x00"), nil, func(key []byte, rec meta.Record) bool {
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
			c.Load(string(key), size)
			return true
		})
		if failure != nil {
			return failure
		}
		pfx := pulledKey([]byte(ns + c.Repo() + "\x00"))
		v.Scan(pfx, nil, func(key []byte, rec meta.Record) bool {
			d := newDec(rec.Value)
			t := d.varint()
			if failure = d.done(); failure != nil {
				return false
			}
			c.LoadPulled("oci\x00"+string(key[len(nsPulled):]), t)
			return true
		})
		if failure != nil {
			return failure
		}
	}
	return nil
}

// track records content cached in rn's repository, and asks for an
// eviction if it is now over its size limit.
func (h *Handler) track(rn *repoName, key []byte, size int64) {
	c := rn.cfg.proxy.cache
	if c == nil {
		return
	}
	over := c.Add(key, size, h.now())
	h.cachedBytes.With(c.Repo()).Set(float64(c.Size()))
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
		c.Touch(key, h.now())
	}
}

// trackers returns the size-limited proxy repositories' trackers.
func (h *Handler) trackers() []*upstream.CacheTracker {
	var out []*upstream.CacheTracker
	for _, rc := range h.repos {
		if rc.proxy != nil && rc.proxy.cache != nil {
			out = append(out, rc.proxy.cache)
		}
	}
	slices.SortFunc(out, func(a, b *upstream.CacheTracker) int { return strings.Compare(a.Repo(), b.Repo()) })
	return out
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
			b.SetOrigin(meta.Origin{Actor: "system", Action: "oci.proxy.pulled", Target: c.Repo()})
			if err := h.commit(ctx, &b); err != nil {
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
		h.cachedBytes.With(c.Repo()).Set(float64(c.Size()))
	}
	return nil
}

// evict removes cached items of c's repository in one batch. Each item
// must still be at the version read, so an item cached again meanwhile
// is not removed behind the tracker's back; such a conflict fails the
// batch, and the next eviction run decides again.
func (h *Handler) evict(ctx context.Context, c *upstream.CacheTracker, keys []string) error {
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
			evictManifestRefs(v, &b, h.repos[c.Repo()], k, rec)
		}
	}
	v.Release()
	c.Remove(gone)
	if len(gone) == len(keys) {
		return nil
	}
	b.SetOrigin(meta.Origin{Actor: "system", Action: "oci.proxy.evict",
		Target: c.Repo() + ": least recently pulled content over the size limit"})
	if err := h.commit(ctx, &b); err != nil {
		if errors.Is(err, meta.ErrConflict) {
			return nil
		}
		return err
	}
	c.Remove(keys)
	h.evictions.With(c.Repo()).Add(float64(len(keys) - len(gone)))
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
// done: it persists last-pull times, evicts content over size limits,
// and forgets stale tag confirmations. Before returning, it persists the
// pull times once more. The free-space watcher, which proxy repositories
// of every format share, runs separately (upstream.Space.Run).
func (h *Handler) RunProxy(ctx context.Context) {
	if !h.hasProxy {
		return
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
			h.pruneValidated()
		case <-h.evictKick:
			if err := h.Evict(ctx); err != nil && ctx.Err() == nil {
				h.log.Warn("evicting proxy content over its size limit", "err", err)
			}
		}
	}
}
