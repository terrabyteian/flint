package npm

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
)

// change is a change to a hosted package, which a plan computes from a
// metadata view.
type change struct {
	action, target string                    // the batch's origin
	pkg            *pkgRecord                // the package record to write
	versions       map[string]*versionRecord // the version records to write
	digests        []blob.Digest             // the blobs the change links
}

// plan computes a change to a hosted package from view v: p is the
// package's record, nil if the repository never had the package, and vrs
// its version records, live and tombstones. A nil change changes nothing.
type plan func(v meta.View, p *pkgRecord, vrs map[string]*versionRecord) (*change, error)

// maxAttempts bounds how often a batch is retried after a metadata
// precondition fails.
const maxAttempts = 4

// errRetry means a batch lost a race with garbage collection or other
// writers and the client should retry.
var errRetry = errorf(http.StatusServiceUnavailable, "the registry is busy with this package; retry the request")

// update applies the change plan computes to a hosted package, in one
// batch that requires the package record and every version record it
// writes unchanged since the view the plan read, and carries the
// garbage-collection precondition on the blobs it links. When another
// change got there first, it plans again on what the store then holds.
// Every change rewrites the package record, so its version, the
// package's _rev, moves. With rev not zero, the package record must be
// at that version, or the change is refused with 409, as CouchDB refuses
// an edit of a stale revision. It returns the package's _rev after the
// change, and whether anything changed.
func (h *Handler) update(r *http.Request, rp *repository, name string, rev meta.Seq, plan plan) (string, bool, error) {
	ctx := r.Context()
	for attempt := 0; ; attempt++ {
		v := h.meta.View()
		p, rec, err := hostedPackage(v, rp, name)
		if err == nil && rev != 0 && rec.Version != rev {
			err = errorf(http.StatusConflict, "package %s changed since the revision being edited was read; read it again and retry", name)
		}
		var vrs map[string]*versionRecord
		if err == nil {
			vrs, err = hostedVersions(v, rp, name)
		}
		var c *change
		if err == nil {
			c, err = plan(v, p, vrs)
		}
		var b meta.Batch
		var value []byte
		if err == nil && c != nil && len(c.digests) > 0 {
			err = gc.Guard(v, &b, c.digests...)
		}
		if err == nil && c != nil {
			pk := pkgKey(rp.name, name)
			value = c.pkg.encode()
			b.Require(pk, rec.Version)
			b.Put(pk, value)
			for _, ver := range sortedKeys(c.versions) {
				k := versionKey(rp.name, name, ver)
				cur, _ := v.Get(k)
				b.Require(k, cur.Version)
				b.Put(k, c.versions[ver].encode())
			}
			b.SetOrigin(h.origin(r, c.action, c.target))
		}
		v.Release()
		if err != nil {
			return "", false, err
		}
		if c == nil {
			return formatRev(rec.Version, rec.Value), false, nil
		}
		if err = h.statBlobs(ctx, c.digests...); err != nil {
			return "", false, err
		}
		seq, err := h.meta.Commit(ctx, &b)
		switch {
		case err == nil:
			h.log.InfoContext(ctx, "npm package changed", "action", c.action, "repository", rp.name, "package", name,
				"versions", sortedKeys(c.versions))
			return formatRev(seq, value), true, nil
		case errors.Is(err, meta.ErrConflict) && attempt < maxAttempts-1:
			// Another change, or a garbage-collection sweep, got there
			// first: plan again.
		case errors.Is(err, meta.ErrConflict), errors.Is(err, gc.ErrDoomed):
			return "", false, errRetry
		default:
			return "", false, err
		}
	}
}

// sortedKeys returns the keys of m, sorted.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// statBlobs checks that blobs exist, after the view that guarded the
// batch was read.
func (h *Handler) statBlobs(ctx context.Context, ds ...blob.Digest) error {
	for _, d := range ds {
		if _, err := h.blobs.Stat(ctx, d); errors.Is(err, blob.ErrNotFound) {
			return errRetry // swept since it was committed; the client publishes again
		} else if err != nil {
			return err
		}
	}
	return nil
}

// putBlob commits b to the blob store.
func (h *Handler) putBlob(ctx context.Context, b []byte) (blob.Info, error) {
	up, err := h.blobs.NewUpload(ctx)
	if err != nil {
		return blob.Info{}, err
	}
	if _, err := up.Write(b); err != nil {
		up.Cancel()
		return blob.Info{}, err
	}
	return up.Commit(ctx, blob.FromBytes(b))
}

// clone returns a copy of p that changes do not share, or a new record
// created now if p is nil.
func (p *pkgRecord) clone(now func() time.Time) *pkgRecord {
	if p == nil {
		return &pkgRecord{Created: now().UTC()}
	}
	c := *p
	c.Tags = slices.Clone(p.Tags)
	return &c
}

// unpublish replaces the live versions named in removed with tombstones
// in c, and moves p's dist-tags off them: a tag that points at one is
// removed, and if "latest" is, it moves to the highest version left,
// preferring releases to pre-releases; with no version left, the package
// has no dist-tags.
func unpublish(c *change, p *pkgRecord, vrs map[string]*versionRecord, removed []string, now time.Time) {
	gone := map[string]bool{}
	for _, ver := range removed {
		gone[ver] = true
		c.versions[ver] = &versionRecord{Kind: kindTombstone, Published: vrs[ver].Published, Unpublished: now}
	}
	latestGone := gone[p.tag("latest")]
	p.Tags = slices.DeleteFunc(p.Tags, func(t distTag) bool { return gone[t.Version] })
	if !latestGone {
		return
	}
	var best string
	var bestRelease bool
	for ver, vr := range vrs {
		if vr.Kind != kindLive || gone[ver] {
			continue
		}
		pv, _ := parseVersion(ver)
		release := len(pv.pre) == 0
		if best == "" || release && !bestRelease || release == bestRelease && compareVersions(ver, best) > 0 {
			best, bestRelease = ver, release
		}
	}
	if best == "" {
		p.Tags = nil
		return
	}
	p.setTag("latest", best)
}
