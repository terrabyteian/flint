package npm

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/browse"
)

func TestBrowse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.publish("local", newPkg("@acme/widget", "1.0.0"), http.StatusOK)
	e.advance(1)
	e.publish("local", newPkg("@acme/widget", "1.10.0"), http.StatusOK)
	e.publish("local", newPkg("left-pad", "0.1.0"), http.StatusOK)
	e.expect("PUT", "/npm/local/-/package/@acme%2fwidget/dist-tags/stable", strings.NewReader(`"1.0.0"`),
		http.StatusOK, "Content-Type", "application/json")

	pkgs, more, err := e.h.ListPackages("local", browse.Query{Limit: 1})
	if err != nil || !more || len(pkgs) != 1 {
		t.Fatalf("first page: %+v, %v, %v", pkgs, more, err)
	}
	if p := pkgs[0]; p.Name != "@acme/widget" || p.Latest != "1.10.0" || p.Versions != 2 {
		t.Errorf("package %+v", p)
	}
	pkgs, more, _ = e.h.ListPackages("local", browse.Query{Limit: 1, After: "@acme/widget"})
	if len(pkgs) != 1 || pkgs[0].Name != "left-pad" || more {
		t.Errorf("second page: %+v, %v", pkgs, more)
	}
	if pkgs, _, _ := e.h.ListPackages("local", browse.Query{Filter: "PAD"}); len(pkgs) != 1 {
		t.Errorf("filtered: %+v", pkgs)
	}

	d, err := e.h.Package(ctx, "local", "@acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	if d.Summary != "the @acme/widget package" || len(d.Versions) != 2 || d.Versions[0].Version != "1.10.0" {
		t.Errorf("detail %+v", d)
	}
	if len(d.Tags) != 2 || d.Tags[0] != (browse.Tag{Name: "latest", Version: "1.10.0"}) ||
		d.Tags[1] != (browse.Tag{Name: "stable", Version: "1.0.0"}) {
		t.Errorf("tags %+v", d.Tags)
	}
	f := d.Versions[1].Files[0]
	if f.Name != "widget-1.0.0.tgz" || f.URL != "/npm/local/@acme/widget/-/widget-1.0.0.tgz" {
		t.Errorf("file %+v", f)
	}
	if w := e.expect("GET", f.URL, nil, http.StatusOK); w.Body.String() != "tarball of @acme/widget@1.0.0" {
		t.Errorf("download: %q", w.Body)
	}

	for _, c := range []struct{ repo, name string }{{"local", "missing"}, {"remote", "@acme/widget"}, {"all", "left-pad"}} {
		if _, err := e.h.Package(ctx, c.repo, c.name); !errors.Is(err, browse.ErrNotFound) {
			t.Errorf("Package(%s, %s): got %v", c.repo, c.name, err)
		}
	}
}
