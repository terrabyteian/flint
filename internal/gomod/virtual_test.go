package gomod

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc/gctest"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

func TestVirtual(t *testing.T) {
	e := newEnv(t)
	v1, v11 := newModule(t, "example.com/lib", "v1.0.0"), newModule(t, "example.com/lib", "v1.1.0")
	// The second member has v1.1.0 too, with other content: the first
	// member's must win, as only it matches the checksum database.
	other11, v12 := newModule(t, "example.com/lib", "v1.1.0"), newModule(t, "example.com/lib", "v1.2.0")
	other11.zip = newModule(t, "example.com/lib", "v1.1.0-other").zip
	e.up.add(v1, v11)
	e.up2.add(other11, v12)
	e.db.add(v1, v11, v12)
	base := "/go/go-all/example.com/lib"
	e.get(base+"/@v/list", http.StatusOK, "v1.0.0\nv1.1.0\nv1.2.0\n")
	e.get(base+"/@latest", http.StatusOK, v11.info())
	e.get(base+"/@v/v1.1.0.info", http.StatusOK, v11.info())
	e.get(base+"/@v/v1.1.0.zip", http.StatusOK, string(v11.zip))
	e.get(base+"/@v/v1.2.0.info", http.StatusOK, v12.info())
	e.get(base+"/@v/v1.2.0.mod", http.StatusOK, string(v12.mod))
	e.get(base+"/@v/v1.2.0.zip", http.StatusOK, string(v12.zip))
	e.get(base+"/@v/v9.0.0.zip", http.StatusNotFound, "")
	e.get("/go/go-all/example.com/none/@v/list", http.StatusNotFound, "")
	if got := e.auth.reset(); len(got) == 0 || got[0] != "virtual go-all :pull" {
		t.Errorf("authorizations %q", got)
	}
	e.settle()

	// A member whose upstream is down with nothing cached is skipped.
	v2 := newModule(t, "example.com/lib", "v2.0.0+incompatible")
	e.up2.add(v2)
	e.db.add(v2)
	e.up.set(func(p *goProxy) { p.down = true })
	e.get(base+"/@v/v2.0.0+incompatible.zip", http.StatusOK, string(v2.zip))
	if got := e.metric(`flint_virtual_member_skips_total{repository="go-all",member="goproxy"}`); got != "1" {
		t.Errorf("skips %q", got)
	}
	// What a member cached is served from it while its upstream is down.
	e.get(base+"/@v/v1.1.0.zip", http.StatusOK, string(v11.zip))
	e.advance(testWindow)
	e.get(base+"/@v/list", http.StatusOK, "v1.0.0\nv1.1.0\nv1.2.0\nv2.0.0+incompatible\n")
	// With every member failing, the request fails.
	e.up2.set(func(p *goProxy) { p.down = true })
	w := e.do(http.MethodGet, "/go/go-all/example.com/uncached/@v/list")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "no member of go-all") {
		t.Errorf("every member failing: %d %q", w.Code, w.Body)
	}

	// The checksum database is served through the first member that
	// proxies it.
	e.get("/go/go-all/sumdb/sum.example.com/supported", http.StatusOK, "")
	e.get("/go/go-all/sumdb/sum.example.com/lookup/example.com/lib@v1.1.0", http.StatusOK, "")
	e.get("/go/go-all/sumdb/sum.golang.org/supported", http.StatusNotFound, "")
}

func TestVirtualFilters(t *testing.T) {
	e := newEnv(t)
	// An attacker publishes the internal module path upstream.
	internal, public := newModule(t, "corp.example.com/lib", "v1.0.0"), newModule(t, "corp.example.com/lib", "v1.0.0")
	public.zip = newModule(t, "corp.example.com/lib", "v6.6.6").zip
	open := newModule(t, "example.com/open", "v1.0.0")
	e.up.add(public, open)
	e.up2.add(internal)
	e.db.add(public, open)
	// corp-all serves corp.example.com/* from corp only, which checks
	// no sums for it, and everything else from goproxy.
	e.get("/go/corp-all/corp.example.com/lib/@v/v1.0.0.zip", http.StatusOK, string(internal.zip))
	e.get("/go/corp-all/corp.example.com/lib/@v/list", http.StatusOK, "v1.0.0\n")
	e.get("/go/corp-all/example.com/open/@v/v1.0.0.zip", http.StatusOK, string(open.zip))
	if got := e.up.took(); slices.ContainsFunc(got, func(p string) bool { return strings.HasPrefix(p, "/corp.example.com/") }) {
		t.Errorf("the public upstream was asked about an internal module: %q", got)
	}
	if got := e.up2.took(); slices.ContainsFunc(got, func(p string) bool { return strings.HasPrefix(p, "/example.com/") }) {
		t.Errorf("the internal upstream was asked about a public module: %q", got)
	}
	// go-all excludes corp.example.com/* from goproxy, and second does
	// not have it.
	e.get("/go/go-all/corp.example.com/lib/@v/list", http.StatusOK, "v1.0.0\n")
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("the excluded member's upstream was asked: %q", got)
	}
}

func TestVirtualQuery(t *testing.T) {
	e := newEnv(t)
	a := newModule(t, "example.com/m", "v0.0.0-20260102030405-aaaaaaaaaaaa")
	b := newModule(t, "example.com/m", "v0.0.0-20260102030405-bbbbbbbbbbbb")
	e.up.add(a)
	e.up2.add(b)
	e.up2.set(func(p *goProxy) { p.queries["example.com/m@dev"] = b.version })
	e.up.set(func(p *goProxy) { p.queries["example.com/m@main"] = a.version })
	e.up2.set(func(p *goProxy) { p.queries["example.com/m@main"] = b.version })
	// The first member that answers a query answers it.
	e.get("/go/go-all/example.com/m/@v/main.info", http.StatusOK, a.info())
	e.get("/go/go-all/example.com/m/@v/dev.info", http.StatusOK, b.info())
	e.get("/go/go-all/example.com/m/@v/nope.info", http.StatusNotFound, "")
}

// TestGCMarker writes every kind of record the Go repositories write and
// checks that the shared proxy cache's marker, which is theirs, covers
// them all and marks every blob they reference.
func TestGCMarker(t *testing.T) {
	e := newEnv(t)
	m := newModule(t, "example.com/m", "v1.0.0")
	pseudo := newModule(t, "example.com/m", "v0.0.0-20260102030405-abcdefabcdef")
	e.up.add(m, pseudo)
	e.up.set(func(p *goProxy) { p.queries["example.com/m@main"] = pseudo.version })
	e.db.add(m, pseudo)
	var bodies []string
	for _, repo := range []string{"goproxy", "small"} {
		for _, path := range []string{"example.com/m/@v/list", "example.com/m/@latest", "example.com/m/@v/main.info",
			"example.com/m/@v/v1.0.0.info", "example.com/m/@v/v1.0.0.mod", "example.com/m/@v/v1.0.0.zip",
			"sumdb/sum.example.com/latest", "sumdb/sum.example.com/tile/8/0/000.p/2"} {
			bodies = append(bodies, e.get("/go/"+repo+"/"+path, http.StatusOK, "").Body.String())
		}
	}
	e.get("/go/go-all/example.com/m/@v/v1.0.0.zip", http.StatusOK, string(m.zip))
	e.settle()
	if err := e.paths.FlushPullTimes(ctx); err != nil {
		t.Fatal(err)
	}

	v := e.meta.View()
	defer v.Release()
	for _, ns := range []string{upstream.NSDoc, upstream.NSFile, upstream.NSPulled} {
		found := false
		v.Scan([]byte(ns), nil, func([]byte, meta.Record) bool { found = true; return false })
		if !found {
			t.Errorf("the test writes no record under %q", ns)
		}
	}
	// The query's answer was cached as the pseudo-version's .info.
	if f, _ := e.paths.Lookup(e.h.repos["goproxy"].proxy.path, "example.com/m/@v/"+pseudo.version+".info"); f == nil {
		t.Error("the query's answer was not cached as the version's .info")
	}
	marked := map[blob.Digest]bool{}
	for _, d := range gctest.CheckStored(t, e.meta, e.blobs, upstream.Marks) {
		marked[d] = true
	}
	for _, b := range bodies {
		if d := blob.FromBytes([]byte(b)); !marked[d] {
			t.Errorf("the blob of %.40q is not marked", b)
		}
	}
	// The record the zip and go.mod were verified against too.
	lookup := e.get("/go/goproxy/sumdb/sum.example.com/lookup/example.com/m@v1.0.0", http.StatusOK, "").Body.String()
	if !marked[blob.FromBytes([]byte(lookup))] {
		t.Error("the checksum database record is not marked")
	}
}
