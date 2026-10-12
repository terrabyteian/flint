package cargo

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/terrabyteian/flint/internal/browse"
)

func TestBrowse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	foo := newCrate("Foo_Bar", "1.0.0")
	e.mustPublish("local", foo)
	e.advance(1)
	e.mustPublish("local", newCrate("Foo_Bar", "1.10.0"))
	e.mustPublish("local", newCrate("zed", "0.1.0"))
	if w := e.do("DELETE", "/cargo/local/api/v1/crates/foo-bar/1.0.0/yank", nil); w.Code != http.StatusOK {
		t.Fatalf("yank: %d %s", w.Code, w.Body)
	}

	pkgs, more, err := e.h.ListPackages("local", browse.Query{Limit: 1})
	if err != nil || !more || len(pkgs) != 1 {
		t.Fatalf("first page: %+v, %v, %v", pkgs, more, err)
	}
	if p := pkgs[0]; p.Name != "Foo_Bar" || p.Latest != "1.10.0" || p.Versions != 2 || p.Summary != "The Foo_Bar crate" {
		t.Errorf("crate %+v", p)
	}
	pkgs, more, _ = e.h.ListPackages("local", browse.Query{Limit: 1, After: "Foo_Bar"})
	if len(pkgs) != 1 || pkgs[0].Name != "zed" || more {
		t.Errorf("second page: %+v, %v", pkgs, more)
	}

	d, err := e.h.Package(ctx, "local", "foo-bar")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "Foo_Bar" || len(d.Versions) != 2 || d.Versions[0].Version != "1.10.0" ||
		len(d.Versions[1].Notes) != 1 || d.Versions[1].Notes[0] != "yanked" {
		t.Fatalf("detail %+v", d)
	}
	f := d.Versions[1].Files[0]
	if f.URL != "/cargo/local/api/v1/crates/Foo_Bar/1.0.0/download" || f.Size != int64(len(foo.body)) {
		t.Errorf("file %+v", f)
	}
	if w := e.get(f.URL, http.StatusOK); w.Body.Len() != len(foo.body) {
		t.Errorf("download: %d bytes", w.Body.Len())
	}
	for _, c := range []struct{ repo, name string }{{"local", "missing"}, {"remote", "zed"}, {"all", "zed"}} {
		if _, err := e.h.Package(ctx, c.repo, c.name); !errors.Is(err, browse.ErrNotFound) {
			t.Errorf("Package(%s, %s): got %v", c.repo, c.name, err)
		}
	}
}
