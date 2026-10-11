package gc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// MarkFunc returns the digests of the blobs a metadata record references.
// It must not retain key or value. An error means the record cannot be
// read, which makes a run refuse to delete anything.
type MarkFunc func(key, value []byte) ([]blob.Digest, error)

// Marker is a package's registration with the garbage collector: for
// every metadata key prefix the package owns, the function that returns
// the blobs a record under it references, or nil if its records
// reference none. Every package that writes metadata registers one; a
// key under no registered prefix makes a run refuse to delete anything,
// because nothing says which blobs its record keeps alive. No prefix may
// start with another, in one marker or across markers.
//
// The collector knows no format's encodings: it only calls the
// functions. CheckMarker, and the gctest package built on it, let a
// format's tests prove that its marker covers every record it writes.
type Marker map[string]MarkFunc

// ownMarker is the gc package's own keys, which reference nothing.
var ownMarker = Marker{EpochKey: nil, DoomedPrefix: nil, lastKey: nil}

// prefix is one registered key prefix.
type prefix struct {
	p    string
	mark MarkFunc
}

// registry holds the registered prefixes.
type registry struct {
	prefixes []prefix // sorted
}

func newRegistry(markers []Marker) (*registry, error) {
	r := &registry{}
	for _, m := range slices.Concat(markers, []Marker{ownMarker}) {
		for _, p := range slices.Sorted(maps.Keys(m)) {
			r.prefixes = append(r.prefixes, prefix{p, m[p]})
		}
	}
	slices.SortFunc(r.prefixes, func(a, b prefix) int { return strings.Compare(a.p, b.p) })
	for i, p := range r.prefixes {
		if p.p == "" {
			return nil, errors.New("gc: a marker registers an empty prefix")
		}
		// Sorted, every prefix between p and a prefix that starts with p
		// starts with p too, so comparing neighbors finds every overlap.
		if i > 0 && strings.HasPrefix(p.p, r.prefixes[i-1].p) {
			return nil, fmt.Errorf("gc: prefix %q starts with prefix %q, which is registered too", p.p, r.prefixes[i-1].p)
		}
	}
	return r, nil
}

// maxUnreadable bounds the unreadable records a scan describes.
const maxUnreadable = 5

// scanned describes a scan of a metadata view.
type scanned struct {
	keys       int64
	unclaimed  map[string]int64 // keys under no registered prefix, by keyFamily
	unreadable []string         // up to maxUnreadable descriptions
	badRecords int64            // records whose function could not read them
}

// refusal returns why the scanned view makes a run delete nothing, or nil.
func (s *scanned) refusal() []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(s.unclaimed)) {
		out = append(out, fmt.Sprintf("%d metadata keys starting %q are under no prefix registered with the garbage collector, "+
			"so the blobs they reference are unknown", s.unclaimed[name], name))
	}
	if s.badRecords > 0 {
		out = append(out, fmt.Sprintf("%d metadata records cannot be read, so the blobs they reference are unknown: %s",
			s.badRecords, strings.Join(s.unreadable, "; ")))
	}
	return out
}

// keyFamily names the family of an unregistered key for a report: the
// key up to its second 0x00 separator, so it shows the owner and the kind
// of record, as in "pypi\x00file\x00", without the rest of the key.
func keyFamily(key []byte) string {
	end := len(key)
	if i := bytes.IndexByte(key, 0); i >= 0 {
		end = i + 1
		if j := bytes.IndexByte(key[i+1:], 0); j >= 0 {
			end = i + 1 + j + 1
		}
	}
	return string(key[:min(end, 64)])
}

// scanEvery is how many keys a scan reads between checks of its context.
const scanEvery = 1 << 16

// scan marks view v: it scans the keys under each registered prefix,
// calling mark for each blob their records reference, and the keys
// between the prefixes, which no marker claims. A record in skip at the
// version skip gives is not marked. It returns ctx's error if ctx ends
// first.
func (r *registry) scan(ctx context.Context, v meta.View, skip map[string]meta.Seq, mark func(blob.Digest)) (*scanned, error) {
	s := &scanned{unclaimed: map[string]int64{}}
	var err error
	tick := func() bool {
		s.keys++
		if s.keys%scanEvery == 0 {
			err = ctx.Err()
		}
		return err == nil
	}
	// gap scans the keys after the key after, up to next or, if next is
	// empty, to the end: no prefix claims them. Keys under a prefix are
	// contiguous, so the gaps and the prefixes cover every key once.
	var after []byte // the last key scanned
	gap := func(next string) {
		v.Scan(nil, after, func(k []byte, _ meta.Record) bool {
			if next != "" && string(k) >= next {
				return false
			}
			after = k
			s.unclaimed[keyFamily(k)]++
			return tick()
		})
		after = bytes.Clone(after)
	}
	for _, p := range r.prefixes {
		if gap(p.p); err != nil {
			return nil, err
		}
		v.Scan([]byte(p.p), nil, func(k []byte, rec meta.Record) bool {
			after = k
			if ver, ok := skip[string(k)]; ok && ver == rec.Version {
				return tick()
			}
			if p.mark != nil {
				ds, merr := p.mark(k, rec.Value)
				if merr != nil {
					s.badRecords++
					if len(s.unreadable) < maxUnreadable {
						s.unreadable = append(s.unreadable, fmt.Sprintf("key %q: %v", abbrev(k), merr))
					}
				}
				for _, d := range ds {
					mark(d)
				}
			}
			return tick()
		})
		if err != nil {
			return nil, err
		}
		after = bytes.Clone(after)
	}
	if gap(""); err != nil {
		return nil, err
	}
	return s, nil
}

// CheckMarker marks view v with markers, and the gc package's own, as a
// run does, and returns the digests the records reference and the
// problems that would make a run refuse to delete anything: keys under
// no registered prefix, and records a function cannot read. It is for
// tests that prove a format's marker covers every record it writes.
func CheckMarker(v meta.View, markers ...Marker) (refs []blob.Digest, problems []string, err error) {
	reg, err := newRegistry(markers)
	if err != nil {
		return nil, nil, err
	}
	s, err := reg.scan(context.Background(), v, nil, func(d blob.Digest) { refs = append(refs, d) })
	if err != nil {
		return nil, nil, err
	}
	return refs, s.refusal(), nil
}

// abbrev shortens a key for a report.
func abbrev(key []byte) string {
	const max = 120
	if len(key) <= max {
		return string(key)
	}
	return string(key[:max]) + "..."
}
