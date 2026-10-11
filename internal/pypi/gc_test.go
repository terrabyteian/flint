package pypi

import (
	"context"
	"net/http"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/gc/gctest"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

// TestGCMarker writes every kind of PyPI record and checks that the
// marker covers them all and marks exactly the blobs that live records
// link: not a deleted file's.
func TestGCMarker(t *testing.T) {
	e := newEnv(t)
	kept, deleted := wheel("pkg", "1.0", nil), sdist("pkg", "0.9", nil)
	e.mustUpload("local", kept)
	e.mustUpload("local", deleted)
	if w := e.do("DELETE", "/api/v1/pypi/local/projects/pkg/files/"+deleted.filename, nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	cached := wheel("up", "1.0", nil)
	e.up.add("up", upFile{dist: cached, metadata: true})
	for _, repo := range []string{"remote", "small"} {
		e.get("/pypi/"+repo+"/simple/up/", http.StatusOK)
		e.get("/pypi/"+repo+"/files/up/"+cached.filename, http.StatusOK)
		e.get("/pypi/"+repo+"/files/up/"+cached.filename+".metadata", http.StatusOK)
	}
	e.settle()
	if err := e.h.FlushPullTimes(context.Background()); err != nil {
		t.Fatal(err)
	}

	v := e.meta.View()
	defer v.Release()
	for _, ns := range []string{nsProject, nsFile, nsIndex, nsName, nsMetadata, nsPulled + "file\x00", nsPulled + "metadata\x00"} {
		found := false
		v.Scan([]byte(ns), nil, func([]byte, meta.Record) bool { found = true; return false })
		if !found {
			t.Errorf("the test writes no record under %q", ns)
		}
	}
	rec, _ := v.Get(upstream.DocKey("remote", "up"))
	page, err := upstream.DecodeDocRecord(rec.Value)
	if err != nil {
		t.Fatal(err)
	}

	got := map[blob.Digest]bool{}
	for _, d := range gctest.CheckStored(t, e.meta, e.blobs, GCMarker(), upstream.Marks) {
		got[d] = true
	}
	want := []blob.Digest{blob.FromBytes(kept.body), blob.FromBytes(kept.metadata),
		blob.FromBytes(cached.body), blob.FromBytes(cached.metadata), page.Digest}
	if len(got) != len(want) {
		t.Errorf("marked %v, want %v", got, want)
	}
	for _, d := range want {
		if !got[d] {
			t.Errorf("%s is not marked", d)
		}
	}
	if got[blob.FromBytes(deleted.body)] {
		t.Error("a deleted file's blob is marked")
	}
}

// TestGCMarkerUnreadable checks that a record under any PyPI prefix that
// the marker cannot read makes a run refuse to delete anything.
func TestGCMarkerUnreadable(t *testing.T) {
	for ns := range GCMarker() {
		t.Run(ns, func(t *testing.T) {
			e := newEnv(t)
			var b meta.Batch
			b.Put(key(ns, "local", "x"), []byte{recordFormat, 0xff})
			if _, err := e.meta.Commit(context.Background(), &b); err != nil {
				t.Fatal(err)
			}
			v := e.meta.View()
			defer v.Release()
			_, problems, err := gc.CheckMarker(v, GCMarker())
			if err != nil || len(problems) == 0 {
				t.Errorf("an unreadable record: problems %q, err %v", problems, err)
			}
		})
	}
}
