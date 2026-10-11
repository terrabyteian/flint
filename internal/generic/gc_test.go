package generic

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/gc/gctest"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

// TestGCMarker writes every kind of record generic files repositories
// write, hosted and proxied, and checks that the markers cover them all
// and mark exactly the blobs that live records link: not a deleted
// file's, and not one an overwritten or removed file had.
func TestGCMarker(t *testing.T) {
	e := newEnv(t)
	kept, deleted, replaced, removed := content(1), content(2), content(3), content(4)
	e.put(http.StatusCreated, "/generic/local/kept", kept)
	e.put(http.StatusCreated, "/generic/local/deleted", deleted)
	e.expect(http.StatusNoContent, "DELETE", "/generic/local/deleted", nil)
	e.put(http.StatusCreated, "/generic/scratch/latest", replaced)
	e.put(http.StatusOK, "/generic/scratch/latest", kept)
	e.put(http.StatusCreated, "/generic/scratch/removed", removed)
	e.expect(http.StatusNoContent, "DELETE", "/generic/scratch/removed", nil)
	revalidated, immutable := content(5), content(6)
	e.up.set("/dl/revalidated", revalidated)
	e.up.set("/dl/immutable", immutable)
	e.get(http.StatusOK, "/generic/remote/revalidated")
	e.get(http.StatusOK, "/generic/releases/immutable")
	e.settle()

	v := e.meta.View()
	defer v.Release()
	for _, k := range [][]byte{fileKey("local", "kept"), fileKey("local", "deleted"),
		upstream.DocKey("remote", "revalidated"), upstream.FileKey("releases", "immutable")} {
		if _, ok := v.Get(k); !ok {
			t.Errorf("the test writes no record %q", k)
		}
	}

	got := gctest.CheckStored(t, e.meta, e.blobs, GCMarker(), upstream.Marks)
	want := []blob.Digest{digestOf(kept), digestOf(kept), digestOf(revalidated), digestOf(immutable)}
	slices.SortFunc(got, func(a, b blob.Digest) int { return strings.Compare(a.String(), b.String()) })
	slices.SortFunc(want, func(a, b blob.Digest) int { return strings.Compare(a.String(), b.String()) })
	if !slices.Equal(got, want) {
		t.Errorf("marked %v, want %v", got, want)
	}

	var refs []blob.Digest
	if err := References(v, func(d blob.Digest) error { refs = append(refs, d); return nil }); err != nil {
		t.Fatal(err)
	}
	if want := []blob.Digest{digestOf(kept), digestOf(kept)}; !slices.Equal(refs, want) {
		t.Errorf("References reported %v, want %v", refs, want)
	}
}

// TestGCMarkerUnreadable checks that a record under the generic prefix
// that the marker cannot read makes a run refuse to delete anything, and
// that References fails on it.
func TestGCMarkerUnreadable(t *testing.T) {
	for _, value := range [][]byte{nil, {recordFormat}, {recordFormat, 9}, {recordFormat, kindFile, 1, 2}, {2, kindTombstone, 0},
		append((&fileRecord{Kind: kindTombstone}).encode(), 0)} {
		e := newEnv(t)
		var b meta.Batch
		b.Put(fileKey("local", "x"), value)
		if _, err := e.meta.Commit(context.Background(), &b); err != nil {
			t.Fatal(err)
		}
		v := e.meta.View()
		_, problems, err := gc.CheckMarker(v, GCMarker())
		if err != nil || len(problems) == 0 {
			t.Errorf("value %x: problems %q, err %v", value, problems, err)
		}
		if err := References(v, func(blob.Digest) error { return nil }); err == nil {
			t.Errorf("value %x: References did not fail", value)
		}
		v.Release()
	}
}

// TestRecordRoundTrip checks that records decode to what was encoded.
func TestRecordRoundTrip(t *testing.T) {
	e := newEnv(t)
	for _, f := range []*fileRecord{
		{Kind: kindFile, Digest: digestOf(content(1)), Size: 123456789, ContentType: "text/plain", Uploaded: e.now()},
		{Kind: kindFile, Digest: digestOf(nil), Size: 0, ContentType: ""},
		{Kind: kindTombstone, Deleted: e.now()},
	} {
		got, err := decodeFile(f.encode())
		if err != nil || got.Kind != f.Kind || got.Digest != f.Digest || got.Size != f.Size || got.ContentType != f.ContentType ||
			!got.Uploaded.Equal(f.Uploaded) || !got.Deleted.Equal(f.Deleted) {
			t.Errorf("round trip of %+v: %+v, %v", f, got, err)
		}
	}
}
