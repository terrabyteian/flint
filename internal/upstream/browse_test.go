package upstream_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

func TestCacheView(t *testing.T) {
	ms, err := meta.Open("/data/meta", meta.Options{FS: fsys.NewMem(), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()
	fetched := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	b := new(meta.Batch)
	for _, p := range []string{"a.txt", "dir/x", "dir/sub/y", "dir/sub/z", "dir-2/q", "e.txt", "zz/1"} {
		f := &upstream.FileRecord{Digest: blob.FromBytes([]byte(p)), Size: int64(len(p)), Fetched: fetched}
		b.Put(upstream.FileKey("remote", p), upstream.EncodeFileRecord(f))
	}
	// Another repository's file, which must not show.
	f := &upstream.FileRecord{Digest: blob.FromBytes([]byte("o")), Size: 1}
	b.Put(upstream.FileKey("remote2", "b.txt"), upstream.EncodeFileRecord(f))
	if _, err := ms.Commit(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	c := upstream.CacheView{Meta: ms}
	names := func(dir string, q browse.Query) ([]string, bool) {
		t.Helper()
		es, more, err := c.ListFiles("remote", dir, q)
		if err != nil {
			t.Fatalf("ListFiles(%q, %+v): %v", dir, q, err)
		}
		var out []string
		for _, e := range es {
			if e.Dir != (e.Name[len(e.Name)-1] == '/') {
				t.Errorf("entry %+v", e)
			}
			out = append(out, e.Name)
		}
		return out, more
	}
	check := func(got []string, more bool, want []string, wantMore bool) {
		t.Helper()
		if len(got) != len(want) || more != wantMore {
			t.Fatalf("got %v, %v; want %v, %v", got, more, want, wantMore)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	}
	got, more := names("", browse.Query{})
	check(got, more, []string{"a.txt", "dir-2/", "dir/", "e.txt", "zz/"}, false)
	got, more = names("", browse.Query{Limit: 2})
	check(got, more, []string{"a.txt", "dir-2/"}, true)
	got, more = names("", browse.Query{Limit: 2, After: "dir-2/"})
	check(got, more, []string{"dir/", "e.txt"}, true)
	got, more = names("", browse.Query{Filter: "TXT"})
	check(got, more, []string{"a.txt", "e.txt"}, false)
	got, more = names("dir/", browse.Query{})
	check(got, more, []string{"sub/", "x"}, false)
	es, _, _ := c.ListFiles("remote", "dir/sub/", browse.Query{})
	if len(es) != 2 || es[0].Size != 9 || es[0].Digest != blob.FromBytes([]byte("dir/sub/y")).String() ||
		!es[0].Time.Equal(fetched) {
		t.Errorf("files %+v", es)
	}
	for _, dir := range []string{"missing/", "a.txt"} {
		if _, _, err := c.ListFiles("remote", dir, browse.Query{}); !errors.Is(err, browse.ErrNotFound) {
			t.Errorf("ListFiles(%q): got %v", dir, err)
		}
	}
	if es, _, err := c.ListFiles("empty", "", browse.Query{}); err != nil || len(es) != 0 {
		t.Errorf("empty repository: %v, %v", es, err)
	}
}
