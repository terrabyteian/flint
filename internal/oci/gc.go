package oci

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
)

// GCMarker returns the OCI marker for the garbage collector, which says
// what each record of hosted and proxy repositories references:
//
//   - a blob link references its blob, until GCPruner's pruner removes
//     it;
//   - a manifest record references the manifest's own bytes and every
//     blob and child manifest it lists;
//   - a tag references the manifest it points to;
//   - a referrers entry references the referring manifest, but not its
//     subject, which need not exist;
//   - upload sessions, manifest generation keys, and proxy repositories'
//     last-pull times reference nothing.
func GCMarker() gc.Marker {
	return gc.Marker{
		nsBlob:     keyDigestRefs,
		nsManifest: manifestRefs,
		nsTag:      tagRefs,
		nsReferrer: keyDigestRefs,
		nsUpload:   nil,
		nsGen:      nil,
		nsPulled:   nil,
	}
}

// keyDigest parses the digest that ends key, after its last separator.
func keyDigest(key []byte) (blob.Digest, error) {
	i := bytes.LastIndexByte(key, 0)
	d, err := blob.ParseDigest(string(key[i+1:]))
	if err != nil {
		return d, fmt.Errorf("the key does not end with a digest: %w", err)
	}
	return d, nil
}

// keyDigestRefs returns the digest that ends the key.
func keyDigestRefs(key, _ []byte) ([]blob.Digest, error) {
	d, err := keyDigest(key)
	if err != nil {
		return nil, err
	}
	return []blob.Digest{d}, nil
}

// manifestRefs returns a manifest's own digest and everything it
// references.
func manifestRefs(key, value []byte) ([]blob.Digest, error) {
	d, err := keyDigest(key)
	if err != nil {
		return nil, err
	}
	m, err := decodeManifest(value)
	if err != nil {
		return nil, err
	}
	out := make([]blob.Digest, 0, 1+len(m.Refs))
	out = append(out, d)
	for _, r := range m.Refs {
		out = append(out, r.Digest)
	}
	return out, nil
}

// tagRefs returns the manifest a tag points to.
func tagRefs(_, value []byte) ([]blob.Digest, error) {
	d, err := decodeTag(value)
	if err != nil {
		return nil, err
	}
	return []blob.Digest{d}, nil
}

// GCPruner returns the OCI pruner for the garbage collector. A blob link,
// in a hosted or proxy repository, keeps its blob alive while it is
// within the grace period, or while a manifest stored in its repository
// name is that blob or references it, directly or as an index's child; a
// run removes every other link. A link is within the grace period if it
// was written, or a blob HEAD or GET read it, within the grace period, or
// the handler started within it, since reads are known only since the
// start. So deleting an image with any client makes the blobs only it used
// unreferenced, while a push whose manifest has not arrived yet keeps the
// links it wrote or found. A manifest push writes its repository name's
// generation key, which the removal requires unchanged, so a run cannot
// remove a link that a manifest pushed meanwhile references.
func (h *Handler) GCPruner() gc.Pruner { return linkPruner{h} }

type linkPruner struct{ h *Handler }

// Expired finds the blob links written and read before cutoff that no
// manifest in their repository name references.
func (p linkPruner) Expired(v meta.View, cutoff time.Time, fn func(gc.Expired) bool) {
	if !p.h.started.Before(cutoff) {
		return
	}
	reads := p.h.linkReadsSince(cutoff)
	var group []byte              // repo\0name\0 of the links scanned
	var gen gc.Required           // the group's manifest generation key
	var refs map[blob.Digest]bool // what the group's manifests are and reference; nil if one is unreadable
	v.Scan([]byte(nsBlob), nil, func(key []byte, rec meta.Record) bool {
		_, linked, err := decodeBlobLink(rec.Value)
		if err != nil || !linked.Before(cutoff) || reads[string(key)] {
			return true
		}
		rest := key[len(nsBlob):]
		i := bytes.LastIndexByte(rest, 0)
		if i < 0 {
			return true
		}
		d, err := blob.ParseDigest(string(rest[i+1:]))
		if err != nil {
			return true
		}
		if !bytes.Equal(rest[:i+1], group) {
			group = bytes.Clone(rest[:i+1])
			gen.Key = append([]byte(nsGen), group...)
			g, _ := v.Get(gen.Key)
			gen.Version = g.Version
			refs = manifestRefsIn(v, group)
		}
		if refs == nil || refs[d] {
			return true
		}
		e := gc.Expired{Key: bytes.Clone(key), Version: rec.Version, Requires: []gc.Required{gen},
			Desc: "blob link " + strings.Replace(string(rest[:i]), "\x00", "/", 1) + "@" + d.String()}
		if pk := pulledKey(key); hasKey(v, pk) {
			e.Also = [][]byte{pk}
		}
		return fn(e)
	})
}

// Remove removes the links not read since Expired found them, holding off
// reads meanwhile, and forgets the removed links in their size-limited
// proxy repositories.
func (p linkPruner) Remove(cutoff time.Time, es []gc.Expired, remove func([]gc.Expired) ([]gc.Expired, error)) error {
	h := p.h
	h.linkMu.Lock()
	defer h.linkMu.Unlock()
	es = slices.DeleteFunc(es, func(e gc.Expired) bool {
		t, ok := h.linkReads[string(e.Key)]
		return ok && !t.Before(cutoff)
	})
	removed, err := remove(es)
	for _, e := range removed {
		delete(h.linkReads, string(e.Key))
		repo, _, _ := strings.Cut(string(e.Key[len(nsBlob):]), "\x00")
		if rc := h.repos[repo]; rc != nil && rc.proxy != nil && rc.proxy.cache != nil {
			h.limits.Remove(rc.proxy.cache, []string{string(e.Key)})
		}
	}
	return err
}

// linkReadsSince returns the keys of the blob links read since cutoff,
// and forgets the reads before it, which no run needs any more.
func (h *Handler) linkReadsSince(cutoff time.Time) map[string]bool {
	h.linkMu.Lock()
	defer h.linkMu.Unlock()
	out := map[string]bool{}
	for k, t := range h.linkReads {
		if t.Before(cutoff) {
			delete(h.linkReads, k)
		} else {
			out[k] = true
		}
	}
	return out
}

// manifestRefsIn returns the digests of the manifests stored in v under
// group, repo\0name\0, and of everything they reference, or nil if one
// of them cannot be read.
func manifestRefsIn(v meta.View, group []byte) map[blob.Digest]bool {
	refs := map[blob.Digest]bool{}
	ok := true
	v.Scan(append([]byte(nsManifest), group...), nil, func(key []byte, rec meta.Record) bool {
		ds, err := manifestRefs(key, rec.Value)
		for _, d := range ds {
			refs[d] = true
		}
		ok = err == nil
		return ok
	})
	if !ok {
		return nil
	}
	return refs
}

func hasKey(v meta.View, key []byte) bool {
	_, ok := v.Get(key)
	return ok
}
