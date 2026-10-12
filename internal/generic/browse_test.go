package generic

import (
	"errors"
	"net/http"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/upstream"
)

func TestBrowse(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"tools/1.0/tool.tar.gz", "tools/2.0/tool.tar.gz", "tools/README.md", "a b.txt", "zeta"} {
		e.put(http.StatusCreated, "/generic/local/"+escapePath(p), []byte("body of "+p))
	}
	e.expect(http.StatusNoContent, "DELETE", "/generic/local/zeta", nil)

	es, more, err := e.h.ListFiles("local", "", browse.Query{})
	if err != nil || more || len(es) != 2 || es[0].Name != "a b.txt" || es[1].Name != "tools/" || !es[1].Dir {
		t.Fatalf("root: %+v, %v, %v", es, more, err)
	}
	f := es[0]
	if f.URL != "/generic/local/a%20b.txt" || f.Size != int64(len("body of a b.txt")) ||
		f.Digest != blob.FromBytes([]byte("body of a b.txt")).String() || f.Time.IsZero() {
		t.Errorf("file %+v", f)
	}
	if body := e.get(http.StatusOK, f.URL); body != "body of a b.txt" {
		t.Errorf("download %q", body)
	}
	es, more, _ = e.h.ListFiles("local", "tools/", browse.Query{Limit: 2})
	if len(es) != 2 || es[0].Name != "1.0/" || es[1].Name != "2.0/" || !more {
		t.Errorf("first page of tools/: %+v, %v", es, more)
	}
	es, more, _ = e.h.ListFiles("local", "tools/", browse.Query{Limit: 2, After: "2.0/"})
	if len(es) != 1 || es[0].Name != "README.md" || more {
		t.Errorf("second page of tools/: %+v, %v", es, more)
	}
	for _, c := range []struct{ repo, dir string }{{"local", "missing/"}, {"local", "tools"}, {"remote", ""}, {"all", ""}} {
		if _, _, err := e.h.ListFiles(c.repo, c.dir, browse.Query{}); !errors.Is(err, browse.ErrNotFound) {
			t.Errorf("ListFiles(%s, %q): got %v", c.repo, c.dir, err)
		}
	}

	// An immutable proxy repository's cache shows in the shared proxy cache's view.
	e.up.set("/dl/pkg/1.0/file.bin", []byte("cached"))
	e.get(http.StatusOK, "/generic/releases/pkg/1.0/file.bin")
	e.settle()
	cached, _, err := upstream.CacheView{Meta: e.meta}.ListFiles("releases", "pkg/1.0/", browse.Query{})
	if err != nil || len(cached) != 1 || cached[0].Name != "file.bin" || cached[0].Size != 6 {
		t.Errorf("cached: %+v, %v", cached, err)
	}
}
