package maven

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

// TestGCMarker writes every kind of record Maven repositories write, and
// checks that the markers cover them all and mark exactly the blobs live
// records link: not a deleted file's.
func TestGCMarker(t *testing.T) {
	e := newEnv(t)
	kept, deleted := []byte("kept jar"), []byte("deleted jar")
	e.deploy("releases", artifact("com.acme", "lib", "1.0", "lib-1.0.jar"), kept)
	e.deploy("releases", artifact("com.acme", "lib", "1.0", "lib-1.0-sources.jar"), deleted)
	e.want("DELETE", "/maven/releases/"+artifact("com.acme", "lib", "1.0", "lib-1.0-sources.jar"), nil, http.StatusNoContent, "")
	snapshot := []byte("snapshot jar")
	e.deploy("snapshots", "com/acme/lib/1.1-SNAPSHOT/lib-1.1-20261011.120000-1.jar", snapshot)
	e.put("/maven/releases/com/acme/plugins/maven-metadata.xml",
		[]byte(`<metadata><plugins><plugin><prefix>p</prefix><artifactId>p-maven-plugin</artifactId></plugin></plugins></metadata>`),
		http.StatusCreated)
	cached, doc := []byte("cached jar"), upstreamMetadata("org.demo", "lib", "1.0")
	e.up.put("/maven2/"+artifact("org.demo", "lib", "1.0", "lib-1.0.jar"), cached)
	e.up.put("/maven2/org/demo/lib/maven-metadata.xml", doc)
	for _, repo := range []string{"central", "small"} {
		e.get("/maven/"+repo+"/"+artifact("org.demo", "lib", "1.0", "lib-1.0.jar"), http.StatusOK)
		e.get("/maven/"+repo+"/org/demo/lib/maven-metadata.xml", http.StatusOK)
	}
	e.settle()
	if err := e.h.FlushPullTimes(context.Background()); err != nil {
		t.Fatal(err)
	}

	v := e.meta.View()
	for _, ns := range []string{nsFile, nsVersion, nsPlugin, upstream.NSFile, upstream.NSDoc, upstream.NSPulled} {
		found := false
		v.Scan([]byte(ns), nil, func([]byte, meta.Record) bool { found = true; return false })
		if !found {
			t.Errorf("the test writes no record under %q", ns)
		}
	}
	v.Release()

	got := map[blob.Digest]bool{}
	for _, d := range gctest.CheckStored(t, e.meta, e.blobs, GCMarker(), upstream.Marks) {
		got[d] = true
	}
	want := []blob.Digest{blob.FromBytes(kept), blob.FromBytes(snapshot), blob.FromBytes(cached), blob.FromBytes(doc)}
	if len(got) != len(want) {
		t.Errorf("marked %d blobs, want %d: %v", len(got), len(want), got)
	}
	for _, d := range want {
		if !got[d] {
			t.Errorf("%s is not marked", d)
		}
	}
	if got[blob.FromBytes(deleted)] {
		t.Error("a deleted file's blob is marked")
	}

	// References reports the hosted files' blobs, for backups.
	v = e.meta.View()
	defer v.Release()
	var refs []blob.Digest
	if err := References(v, func(d blob.Digest) error { refs = append(refs, d); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Errorf("References = %v, want the kept and snapshot files", refs)
	}
}

// TestGCMarkerUnreadable checks that a record under any Maven prefix that
// the marker cannot read makes a run refuse to delete anything.
func TestGCMarkerUnreadable(t *testing.T) {
	for ns := range GCMarker() {
		t.Run(ns, func(t *testing.T) {
			e := newEnv(t)
			var b meta.Batch
			b.Put(key(ns, "releases", "x"), []byte{recordFormat, 0xff})
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
