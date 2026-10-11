package cargo

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

// TestGCMarker writes every kind of record Cargo repositories write, and
// checks that the markers cover them all and mark exactly the blobs that
// live records link: not a deleted version's.
func TestGCMarker(t *testing.T) {
	e := newEnv(t)
	kept, deleted, yanked := newCrate("pkg", "1.0.0"), newCrate("pkg", "0.9.0"), newCrate("pkg", "0.8.0")
	e.mustPublish("local", kept)
	e.mustPublish("local", deleted)
	e.mustPublish("local", yanked)
	if w := e.do("DELETE", "/api/v1/cargo/local/crates/pkg/0.9.0", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if w := e.do("DELETE", "/cargo/local/api/v1/crates/pkg/0.8.0/yank", nil); w.Code != http.StatusOK {
		t.Fatalf("yank: %d %s", w.Code, w.Body)
	}
	cached := newCrate("up", "1.0.0")
	e.up.add(cached)
	for _, repo := range []string{"remote", "small"} {
		e.get("/cargo/"+repo+"/api/v1/crates/up/1.0.0/download", http.StatusOK)
	}
	e.settle()
	if err := e.h.FlushPullTimes(context.Background()); err != nil {
		t.Fatal(err)
	}

	v := e.meta.View()
	defer v.Release()
	for _, ns := range []string{nsCrate, nsVersion, upstream.NSDoc, upstream.NSFile, upstream.NSPulled} {
		found := false
		v.Scan([]byte(ns), nil, func([]byte, meta.Record) bool { found = true; return false })
		if !found {
			t.Errorf("the test writes no record under %q", ns)
		}
	}
	var docs []blob.Digest
	for _, k := range []string{"2/up", "config.json"} {
		rec, _ := v.Get(upstream.DocKey("remote", k))
		d, err := upstream.DecodeDocRecord(rec.Value)
		if err != nil {
			t.Fatalf("document %s: %v", k, err)
		}
		docs = append(docs, d.Digest)
	}

	got := map[blob.Digest]bool{}
	for _, d := range gctest.CheckStored(t, e.meta, e.blobs, GCMarker(), upstream.Marks) {
		got[d] = true
	}
	want := append([]blob.Digest{blob.FromBytes(kept.body), blob.FromBytes(yanked.body), blob.FromBytes(cached.body)}, docs...)
	if len(got) != len(want) {
		t.Errorf("marked %v, want %v", got, want)
	}
	for _, d := range want {
		if !got[d] {
			t.Errorf("%s is not marked", d)
		}
	}
	if got[blob.FromBytes(deleted.body)] {
		t.Error("a deleted version's .crate file is marked")
	}

	// Backups find the same blobs.
	refs := map[blob.Digest]bool{}
	for _, f := range []func(meta.View, func(blob.Digest) error) error{References, upstream.References} {
		if err := f(v, func(d blob.Digest) error { refs[d] = true; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range want {
		if !refs[d] {
			t.Errorf("%s is not a backup reference", d)
		}
	}
	if refs[blob.FromBytes(deleted.body)] {
		t.Error("a deleted version's .crate file is a backup reference")
	}
}

// TestGCMarkerUnreadable checks that a record under any Cargo prefix that
// the marker cannot read makes a run refuse to delete anything, and that
// backups refuse it too.
func TestGCMarkerUnreadable(t *testing.T) {
	for ns := range GCMarker() {
		for _, value := range [][]byte{{recordFormat, 0xff}, {9}, nil} {
			e := newEnv(t)
			var b meta.Batch
			b.Put(key(ns, "local", "x"), value)
			if _, err := e.meta.Commit(context.Background(), &b); err != nil {
				t.Fatal(err)
			}
			v := e.meta.View()
			_, problems, err := gc.CheckMarker(v, GCMarker())
			if err != nil || len(problems) == 0 {
				t.Errorf("%q %x: problems %q, err %v", ns, value, problems, err)
			}
			if ns == nsVersion {
				if err := References(v, func(blob.Digest) error { return nil }); err == nil {
					t.Errorf("%q %x: References read it", ns, value)
				}
			}
			v.Release()
		}
	}
}

func TestRecordsRoundTrip(t *testing.T) {
	d := blob.FromBytes([]byte("x"))
	for _, vr := range []*versionRecord{
		{Kind: kindLive, Vers: "1.0.0+b", Line: []byte(`{"a":1}`), Digest: d, Size: 7, Description: "desc"},
		{Kind: kindTombstone, Vers: "1.0.0"},
	} {
		got, err := decodeVersion(vr.encode())
		if err != nil || got.Kind != vr.Kind || got.Vers != vr.Vers || string(got.Line) != string(vr.Line) ||
			got.Digest != vr.Digest || got.Size != vr.Size || got.Description != vr.Description {
			t.Errorf("round trip of %+v: %+v, %v", vr, got, err)
		}
	}
	if _, err := decodeVersion((&versionRecord{Kind: kindLive, Vers: "1.0.0"}).encode()); err == nil {
		t.Error("a live version without a digest decoded")
	}
	c, err := decodeCrate((&crateRecord{Name: "Foo"}).encode())
	if err != nil || c.Name != "Foo" {
		t.Errorf("crate record: %+v, %v", c, err)
	}
	if _, err := decodeCrate(append((&crateRecord{Name: "Foo"}).encode(), 0)); err == nil {
		t.Error("a crate record with trailing bytes decoded")
	}
}
