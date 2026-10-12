package maven

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
	e.deploy("releases", artifact("com.acme", "lib", "1.0", "lib-1.0.jar"), []byte("jar 1.0"))
	e.deploy("releases", artifact("com.acme", "lib", "1.0", "lib-1.0.pom"), []byte("<project/>"))
	e.advance(1)
	e.deploy("releases", artifact("com.acme", "lib", "1.10", "lib-1.10.jar"), []byte("jar 1.10"))
	e.deploy("releases", artifact("com.acme", "lib-extra", "2.0", "lib-extra-2.0.jar"), []byte("extra"))
	e.deploy("releases", artifact("org.other", "thing", "0.1", "thing-0.1.jar"), []byte("thing"))
	e.deploy("snapshots", artifact("com.acme", "lib", "2.0-SNAPSHOT", "lib-2.0-20261001.120000-1.jar"), []byte("snap"))

	list := func(repo string, q browse.Query) ([]string, bool) {
		t.Helper()
		pkgs, more, err := e.h.ListPackages(repo, q)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range pkgs {
			out = append(out, p.Name+"@"+p.Latest)
		}
		return out, more
	}
	if got, more := list("releases", browse.Query{}); len(got) != 3 || got[0] != "com.acme:lib@1.10" ||
		got[1] != "com.acme:lib-extra@2.0" || got[2] != "org.other:thing@0.1" || more {
		t.Errorf("all: %v, %v", got, more)
	}
	if got, more := list("releases", browse.Query{Limit: 1}); len(got) != 1 || !more {
		t.Errorf("first page: %v, %v", got, more)
	}
	if got, more := list("releases", browse.Query{Limit: 1, After: "com.acme:lib"}); len(got) != 1 ||
		got[0] != "com.acme:lib-extra@2.0" || !more {
		t.Errorf("second page: %v, %v", got, more)
	}
	if got, _ := list("releases", browse.Query{Filter: "OTHER"}); len(got) != 1 {
		t.Errorf("filtered: %v", got)
	}

	d, err := e.h.Package(ctx, "releases", "com.acme:lib")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Versions) != 2 || d.Versions[0].Version != "1.10" || len(d.Versions[1].Files) < 2 {
		t.Fatalf("detail %+v", d)
	}
	var jar *browse.File
	for i, f := range d.Versions[1].Files {
		if f.Name == "lib-1.0.jar" {
			jar = &d.Versions[1].Files[i]
		}
	}
	if jar == nil || jar.URL != "/maven/releases/com/acme/lib/1.0/lib-1.0.jar" || jar.Size != 7 {
		t.Fatalf("jar %+v in %+v", jar, d.Versions[1].Files)
	}
	if r := e.get(jar.URL, http.StatusOK); r.body != "jar 1.0" {
		t.Errorf("download %q", r.body)
	}

	s, err := e.h.Package(ctx, "snapshots", "com.acme:lib")
	if err != nil || len(s.Versions) != 1 || len(s.Versions[0].Notes) != 1 || s.Versions[0].Notes[0] != "snapshot" {
		t.Errorf("snapshot detail %+v, %v", s, err)
	}

	for _, c := range []struct{ repo, name string }{
		{"releases", "com.acme:missing"}, {"releases", "no-colon"}, {"central", "com.acme:lib"}, {"all", "com.acme:lib"},
	} {
		if _, err := e.h.Package(ctx, c.repo, c.name); !errors.Is(err, browse.ErrNotFound) {
			t.Errorf("Package(%s, %s): got %v", c.repo, c.name, err)
		}
	}
}
