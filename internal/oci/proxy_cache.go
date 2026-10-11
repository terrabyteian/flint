package oci

import (
	"bytes"
	"context"
	"strings"

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

// PullFlushInterval is how often last-pull times are persisted.
const PullFlushInterval = upstream.PullFlushInterval

const nsPulled = "oci\x00pulled\x00"

// pulledKey returns the pull-time key of an item's metadata key, which
// starts with "oci\0".
func pulledKey(key []byte) []byte {
	return append([]byte(nsPulled), key[len("oci\x00"):]...)
}

// loadTracker loads the cached items of c's repository, and their pull
// times, from v.
func (h *Handler) loadTracker(c *upstream.CacheTracker, v meta.View) error {
	var failure error
	for _, ns := range []string{nsBlob, nsManifest} {
		pfx := []byte(ns + c.Repo() + "\x00")
		v.Scan(pfx, nil, func(key []byte, rec meta.Record) bool {
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
		if failure == nil {
			failure = h.limits.LoadPulled(c, v, pfx)
		}
		if failure != nil {
			return failure
		}
	}
	return nil
}

// track records content cached in rn's repository, and asks for an
// eviction if it is now over its size limit.
func (h *Handler) track(rn *repoName, key []byte, size int64) {
	h.limits.Track(rn.cfg.proxy.cache, key, size)
}

// touch records a pull of cached content in rn's repository.
func (h *Handler) touch(rn *repoName, key []byte) {
	h.limits.Touch(rn.cfg.proxy.cache, key)
}

// FlushPullTimes persists the last-pull times recorded since the last
// flush.
func (h *Handler) FlushPullTimes(ctx context.Context) error { return h.limits.Flush(ctx) }

// Evict evicts the least recently pulled content of every size-limited
// proxy repository that exceeds its limit: a blob link, or a manifest
// record with the tags that point to it and its referrers entry.
func (h *Handler) Evict(ctx context.Context) error { return h.limits.Evict(ctx) }

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
	h.limits.Run(ctx, func(msg string, err error) { h.log.Warn(msg, "err", err) }, h.pruneValidated)
}
