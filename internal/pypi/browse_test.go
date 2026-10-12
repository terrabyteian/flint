package pypi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/browse"
)

func TestBrowseHosted(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.mustUpload("local", wheel("My_App", "1.0", nil))
	e.mustUpload("local", sdist("My_App", "1.0", nil))
	e.advance(1)
	e.mustUpload("local", wheel("My_App", "1.10", nil))
	e.mustUpload("local", wheel("other", "0.1", nil))
	e.mustUpload("local", wheel("zeta", "2.0", nil))
	if w := e.do("PUT", "/api/v1/pypi/local/projects/my-app/releases/1.0/yank",
		strings.NewReader(`{"reason": "broken"}`)); w.Code != http.StatusOK {
		t.Fatalf("yank: %d %s", w.Code, w.Body)
	}

	pkgs, more, err := e.h.ListPackages("local", browse.Query{Limit: 2})
	if err != nil || more != true || len(pkgs) != 2 {
		t.Fatalf("first page: %+v, %v, %v", pkgs, more, err)
	}
	if p := pkgs[0]; p.Name != "My_App" || p.Latest != "1.10" || p.Versions != 2 || !p.Updated.Equal(e.now()) {
		t.Errorf("package %+v", p)
	}
	pkgs, more, _ = e.h.ListPackages("local", browse.Query{Limit: 2, After: pkgs[1].Name})
	if len(pkgs) != 1 || pkgs[0].Name != "zeta" || more {
		t.Errorf("second page: %+v, %v", pkgs, more)
	}
	if pkgs, _, _ := e.h.ListPackages("local", browse.Query{Filter: "app"}); len(pkgs) != 1 {
		t.Errorf("filtered: %+v", pkgs)
	}

	d, err := e.h.Package(ctx, "local", "my-app")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "My_App" || d.Summary != "The My_App package" || len(d.Versions) != 2 {
		t.Fatalf("detail %+v", d)
	}
	v0, v1 := d.Versions[0], d.Versions[1]
	if v0.Version != "1.10" || len(v0.Files) != 1 || len(v0.Notes) != 0 {
		t.Errorf("newest version %+v", v0)
	}
	if v1.Version != "1.0" || len(v1.Files) != 2 || len(v1.Notes) != 1 || v1.Notes[0] != "yanked: broken" {
		t.Errorf("older version %+v", v1)
	}
	f := v0.Files[0]
	if f.URL != "/pypi/local/files/my-app/"+f.Name || !strings.HasPrefix(f.Digest, "sha256:") || f.Size == 0 {
		t.Errorf("file %+v", f)
	}
	if w := e.get(f.URL, http.StatusOK); w.Body.Len() != int(f.Size) {
		t.Errorf("download of %s: %d bytes", f.URL, w.Body.Len())
	}

	for _, c := range []struct{ repo, project string }{{"local", "missing"}, {"all", "my-app"}, {"nope", "my-app"}} {
		if _, err := e.h.Package(ctx, c.repo, c.project); !errors.Is(err, browse.ErrNotFound) {
			t.Errorf("Package(%s, %s): got %v", c.repo, c.project, err)
		}
	}
	if _, _, err := e.h.ListPackages("all", browse.Query{}); !errors.Is(err, browse.ErrNotFound) {
		t.Errorf("virtual repository: got %v", err)
	}
}

func TestBrowseProxy(t *testing.T) {
	e := newEnv(t)
	a := wheel("pkg", "1.0", nil)
	b := wheel("pkg", "2.0", nil)
	// A file name may spell the project in any case.
	c := sdist("pkg", "3.0", nil)
	c.filename = "PKG-3.0.tar.gz"
	// Another project's name starts the same.
	x := wheel("pkgx", "1.0", nil)
	e.up.add("pkg", upFile{dist: a}, upFile{dist: b}, upFile{dist: c})
	e.up.add("pkgx", upFile{dist: x})
	e.up.add("other", upFile{dist: wheel("other", "1.0", nil)})
	e.page("remote", "pkg")
	e.page("remote", "pkgx")
	e.page("remote", "other")
	e.get("/pypi/remote/files/pkg/"+a.filename, http.StatusOK)
	e.get("/pypi/remote/files/pkg/"+c.filename, http.StatusOK)
	e.get("/pypi/remote/files/pkgx/"+x.filename, http.StatusOK)
	e.settle()

	pkgs, more, err := e.h.ListPackages("remote", browse.Query{})
	if err != nil || more || len(pkgs) != 2 || pkgs[0].Name != "pkg" || pkgs[0].Latest != "3.0" || pkgs[1].Name != "pkgx" {
		t.Fatalf("cached packages: %+v, %v, %v", pkgs, more, err)
	}
	d, err := e.h.Package(context.Background(), "remote", "pkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Versions) != 2 || d.Versions[0].Version != "3.0" || d.Versions[0].Files[0].Name != c.filename ||
		d.Versions[1].Version != "1.0" || d.Versions[1].Files[0].Name != a.filename {
		t.Errorf("cached detail %+v", d)
	}
	if d, err := e.h.Package(context.Background(), "remote", "PkgX"); err != nil || len(d.Versions) != 1 || d.Versions[0].Files[0].Name != x.filename {
		t.Errorf("cached detail of pkgx: %+v, %v", d, err)
	}
	if _, err := e.h.Package(context.Background(), "remote", "other"); !errors.Is(err, browse.ErrNotFound) {
		t.Errorf("project with nothing cached: got %v", err)
	}
}

func TestNamePrefixes(t *testing.T) {
	for project, want := range map[string][]string{
		"pkg":    {"PKG", "PKg", "PkG", "Pkg", "pKG", "pKg", "pkG", "pkg"},
		"a-b":    {"A", "a"},
		"1x2yz9": {"1X2Y", "1X2y", "1x2Y", "1x2y"},
		"-a":     {""},
		"":       {""},
	} {
		if got := namePrefixes(project); !slices.Equal(got, want) {
			t.Errorf("namePrefixes(%q) = %q, want %q", project, got, want)
		}
	}
}
