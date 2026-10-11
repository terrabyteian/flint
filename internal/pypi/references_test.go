package pypi

import (
	"errors"
	"net/http"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/upstream"
)

func TestReferences(t *testing.T) {
	e := newEnv(t)
	kept, deleted := wheel("pkg", "1.0", nil), sdist("pkg", "0.9", nil)
	e.mustUpload("local", kept)
	e.mustUpload("local", deleted)
	if w := e.do("DELETE", "/api/v1/pypi/local/projects/pkg/files/"+deleted.filename, nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	cached := wheel("up", "1.0", nil)
	e.up.add("up", upFile{dist: cached, metadata: true})
	e.get("/pypi/remote/files/up/"+cached.filename, http.StatusOK)
	e.get("/pypi/remote/files/up/"+cached.filename+".metadata", http.StatusOK)
	e.settle()

	v := e.meta.View()
	defer v.Release()
	// The project page is a document of the shared proxy cache, which
	// upstream.References reports.
	rec, _ := v.Get(upstream.DocKey("remote", "up"))
	page, err := upstream.DecodeDocRecord(rec.Value)
	if err != nil {
		t.Fatal(err)
	}
	pages := map[blob.Digest]int{}
	if err := upstream.References(v, func(d blob.Digest) error { pages[d]++; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(pages) != 1 || pages[page.Digest] != 1 {
		t.Errorf("the shared cache's references: %v, want the page %s", pages, page.Digest)
	}
	got := map[blob.Digest]int{}
	if err := References(v, func(d blob.Digest) error { got[d]++; return nil }); err != nil {
		t.Fatal(err)
	}
	wantRefs := map[blob.Digest]int{
		blob.FromBytes(kept.body): 1, blob.FromBytes(kept.metadata): 1,
		blob.FromBytes(cached.body): 1, blob.FromBytes(cached.metadata): 1,
	}
	if blob.FromBytes(kept.metadata) == blob.FromBytes(cached.metadata) {
		t.Fatal("the test needs distinct metadata")
	}
	if len(got) != len(wantRefs) {
		t.Fatalf("got %d digests %v, want %d", len(got), got, len(wantRefs))
	}
	for d, n := range wantRefs {
		if got[d] != n {
			t.Errorf("%s reported %d times, want %d", d, got[d], n)
		}
	}
	if got[blob.FromBytes(deleted.body)] != 0 {
		t.Error("a deleted file's blob was reported")
	}

	stop := errors.New("stop")
	var seen []blob.Digest
	err = References(v, func(d blob.Digest) error { seen = append(seen, d); return stop })
	if !errors.Is(err, stop) || len(seen) != 1 || got[seen[0]] == 0 {
		t.Fatalf("stopping: err %v after %d calls", err, len(seen))
	}
}
