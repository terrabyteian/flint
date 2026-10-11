package gomod

import (
	"bytes"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/upstream"
)

func TestProxy(t *testing.T) {
	e := newEnv(t)
	v1, v2 := newModule(t, "example.com/Lib", "v1.0.0"), newModule(t, "example.com/Lib", "v1.1.0")
	e.up.add(v1, v2)
	e.db.add(v1, v2)
	base := "/go/goproxy/example.com/!lib"
	if w := e.get(base+"/@v/list", http.StatusOK, "v1.0.0\nv1.1.0\n"); w.Header().Get("Content-Type") != ctText {
		t.Errorf("list content type %q", w.Header().Get("Content-Type"))
	}
	e.get(base+"/@latest", http.StatusOK, v2.info())
	if w := e.get(base+"/@v/v1.0.0.info", http.StatusOK, v1.info()); w.Header().Get("Content-Type") != ctJSON {
		t.Errorf("info content type %q", w.Header().Get("Content-Type"))
	}
	e.get(base+"/@v/v1.0.0.mod", http.StatusOK, string(v1.mod))
	if w := e.get(base+"/@v/v1.0.0.zip", http.StatusOK, string(v1.zip)); w.Header().Get("Content-Type") != ctZip {
		t.Errorf("zip content type %q", w.Header().Get("Content-Type"))
	}
	e.settle()
	// The checksum database was asked once for the version's record,
	// and the tile that proves it, which verified both files.
	if got := e.db.took(); !slices.Equal(got, []string{"/lookup/example.com/!lib@v1.0.0", "/tile/8/0/000.p/2"}) {
		t.Errorf("checksum database requests %q", got)
	}
	if got := e.auth.reset(); len(got) == 0 || got[0] != "goproxy:pull" {
		t.Errorf("authorizations %q", got)
	}

	// A version's files are cached forever; the list and @latest are
	// served from the cache within the window, and stale when the
	// upstream is down.
	e.up.took()
	e.up.set(func(p *goProxy) { p.down = true })
	for path, body := range map[string]string{
		"/@v/v1.0.0.info": v1.info(), "/@v/v1.0.0.mod": string(v1.mod), "/@v/v1.0.0.zip": string(v1.zip),
		"/@v/list": "v1.0.0\nv1.1.0\n", "/@latest": v2.info()} {
		e.get(base+path, http.StatusOK, body)
	}
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("upstream requests for cached content: %q", got)
	}
	e.advance(testWindow)
	e.get(base+"/@v/list", http.StatusOK, "v1.0.0\nv1.1.0\n")
	if got := e.metric(`flint_proxy_requests_total{repository="goproxy",result="stale"}`); got != "1" {
		t.Errorf("stale count %q", got)
	}
	// Content never cached cannot be served.
	if w := e.do(http.MethodGet, base+"/@v/v1.1.0.zip"); w.Code != http.StatusServiceUnavailable {
		t.Errorf("an uncached zip with the upstream down: %d", w.Code)
	}
	// And a restart keeps everything cached.
	e.restart()
	e.get(base+"/@v/v1.0.0.zip", http.StatusOK, string(v1.zip))
	e.get(base+"/@v/list", http.StatusOK, "v1.0.0\nv1.1.0\n")
}

func TestProxyNotFound(t *testing.T) {
	e := newEnv(t)
	m := newModule(t, "example.com/m", "v1.0.0")
	e.up.add(m)
	e.db.add(m)
	e.up.set(func(p *goProxy) { p.gone["example.com/gone"] = true })
	// Answers the go command falls back on with a comma-separated
	// GOPROXY are passed on as they are.
	e.get("/go/goproxy/example.com/missing/@v/list", http.StatusNotFound, "")
	e.get("/go/goproxy/example.com/gone/@v/list", http.StatusGone, "")
	e.get("/go/goproxy/example.com/gone/@latest", http.StatusGone, "")
	e.get("/go/goproxy/example.com/m/@v/v9.9.9.zip", http.StatusNotFound, "")
	e.get("/go/goproxy/example.com/m/@v/v9.9.9.info", http.StatusNotFound, "")
	// Remembered for a while.
	e.up.took()
	e.get("/go/goproxy/example.com/missing/@v/list", http.StatusNotFound, "")
	e.get("/go/goproxy/example.com/m/@v/v9.9.9.zip", http.StatusNotFound, "")
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("upstream requests for content it just said it lacks: %q", got)
	}
}

func TestProxyVerifies(t *testing.T) {
	e := newEnv(t)
	m := newModule(t, "example.com/m", "v1.0.0")
	e.up.add(m)
	e.db.add(m)
	// Content that does not match the checksum database is refused,
	// and never cached.
	e.up.set(func(p *goProxy) {
		p.corrupt["example.com/m@v1.0.0.zip"] = true
		p.corrupt["example.com/m@v1.0.0.mod"] = true
	})
	for _, ext := range []string{"zip", "mod"} {
		if w := e.do(http.MethodGet, "/go/goproxy/example.com/m/@v/v1.0.0."+ext); w.Code != http.StatusBadGateway {
			t.Errorf("a corrupt .%s: %d %q, want 502", ext, w.Code, w.Body)
		}
	}
	e.settle()
	for _, ext := range []string{"zip", "mod"} {
		if f, _ := e.paths.Lookup(e.h.repos["goproxy"].proxy.path, "example.com/m/@v/v1.0.0."+ext); f != nil {
			t.Errorf("a corrupt .%s was cached", ext)
		}
	}
	// Once the upstream serves the right bytes, they are cached.
	e.up.set(func(p *goProxy) { clear(p.corrupt) })
	e.advance(testWindow)
	e.get("/go/goproxy/example.com/m/@v/v1.0.0.mod", http.StatusOK, string(m.mod))
	e.get("/go/goproxy/example.com/m/@v/v1.0.0.zip", http.StatusOK, string(m.zip))
	// A record the checksum database's key did not sign verifies
	// nothing, and is not cached.
	n := newModule(t, "example.com/n", "v1.0.0")
	e.up.add(n)
	e.db.add(n)
	e.db.set(func(db *sumDB) { db.forge["example.com/n@v1.0.0"] = true })
	if w := e.do(http.MethodGet, "/go/goproxy/example.com/n/@v/v1.0.0.mod"); w.Code != http.StatusBadGateway ||
		!strings.Contains(w.Body.String(), "checksum database sum.example.com") {
		t.Errorf("a .mod with a forged record: %d %q", w.Code, w.Body)
	}
	e.db.set(func(db *sumDB) { clear(db.forge) })
	e.advance(testWindow)
	e.get("/go/goproxy/example.com/n/@v/v1.0.0.mod", http.StatusOK, string(n.mod))
	// A module the checksum database does not know is not cached.
	o := newModule(t, "example.com/o", "v1.0.0")
	e.up.add(o)
	if w := e.do(http.MethodGet, "/go/goproxy/example.com/o/@v/v1.0.0.zip"); w.Code != http.StatusBadGateway ||
		!strings.Contains(w.Body.String(), "verifying example.com/o@v1.0.0 against the checksum database") {
		t.Errorf("a zip the checksum database does not know: %d %q", w.Code, w.Body)
	}
	// A canonical .info must name its version.
	e.up.set(func(p *goProxy) { p.queries["example.com/m@v1.0.1"] = "v1.0.0" })
	if w := e.do(http.MethodGet, "/go/goproxy/example.com/m/@v/v1.0.1.info"); w.Code != http.StatusBadGateway {
		t.Errorf("a .info naming another version: %d %q", w.Code, w.Body)
	}
}

func TestProxyNoSumCheck(t *testing.T) {
	e := newEnv(t)
	private := newModule(t, "corp.example.com/lib", "v1.0.0")
	public := newModule(t, "example.com/pub", "v1.0.0")
	e.up2.add(private, public)
	e.get("/go/corp/corp.example.com/lib/@v/v1.0.0.zip", http.StatusOK, string(private.zip))
	e.get("/go/corp/corp.example.com/lib/@v/v1.0.0.mod", http.StatusOK, string(private.mod))
	if got := e.db.took(); len(got) != 0 {
		t.Errorf("the checksum database was asked about a private module: %q", got)
	}
	// Other modules are still checked.
	if w := e.do(http.MethodGet, "/go/corp/example.com/pub/@v/v1.0.0.zip"); w.Code != http.StatusBadGateway {
		t.Errorf("a public module the checksum database does not know: %d", w.Code)
	}
}

func TestProxyQuery(t *testing.T) {
	e := newEnv(t)
	pseudo := newModule(t, "example.com/m", "v0.0.0-20260102030405-abcdefabcdef")
	e.up.add(pseudo)
	e.db.add(pseudo)
	e.up.set(func(p *goProxy) { p.queries["example.com/m@main"] = pseudo.version })
	e.get("/go/goproxy/example.com/m/@v/main.info", http.StatusOK, pseudo.info())
	e.up.set(func(p *goProxy) { p.down = true })
	e.up.took()
	// The answer is the pseudo-version's .info too: cached, it is
	// served without the upstream.
	e.get("/go/goproxy/example.com/m/@v/"+pseudo.version+".info", http.StatusOK, pseudo.info())
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("upstream requests: %q", got)
	}
	// A query is revalidated: a new answer replaces it.
	e.up.set(func(p *goProxy) { p.down = false })
	next := newModule(t, "example.com/m", "v0.0.0-20260202030405-123456123456")
	e.up.add(next)
	e.up.set(func(p *goProxy) { p.queries["example.com/m@main"] = next.version })
	e.advance(testWindow)
	e.get("/go/goproxy/example.com/m/@v/main.info", http.StatusOK, next.info())
	// An answer flint cannot read never replaces the cached one.
	e.up.set(func(p *goProxy) { p.queries["example.com/m@main"] = "garbage" })
	e.advance(testWindow)
	e.get("/go/goproxy/example.com/m/@v/main.info", http.StatusOK, next.info())
}

func TestSumDB(t *testing.T) {
	e := newEnv(t)
	m := newModule(t, "example.com/m", "v1.0.0")
	e.db.add(m)
	e.db.set(func(db *sumDB) { db.tiles["8/data/x001/234"] = []byte("data tile") })
	tile, _ := e.db.tile("8/0/000.p/1")
	base := "/go/goproxy/sumdb/sum.example.com"
	e.get(base+"/supported", http.StatusOK, "")
	e.get("/go/goproxy/sumdb/sum.golang.org/supported", http.StatusNotFound, "")
	latest := e.get(base+"/latest", http.StatusOK, "").Body.String()
	if !strings.HasPrefix(latest, "go.sum database tree\n1\n") {
		t.Errorf("latest %q", latest)
	}
	lookup := e.get(base+"/lookup/example.com/m@v1.0.0", http.StatusOK, "").Body.String()
	if !strings.Contains(lookup, "example.com/m v1.0.0/go.mod h1:") {
		t.Errorf("lookup %q", lookup)
	}
	e.get(base+"/tile/8/0/000.p/1", http.StatusOK, string(tile))
	e.get(base+"/tile/8/data/x001/234", http.StatusOK, "data tile")
	e.get(base+"/tile/8/0/001", http.StatusNotFound, "")
	for _, bad := range []string{"/tile/8/0/1", "/tile/x/0/001", "/tile/8/0/x01/234", "/tile/8/0/001.p/0", "/lookup/example.com/m@main",
		"/lookup/m@v1.0.0", "/other"} {
		e.get(base+bad, http.StatusNotFound, "")
	}
	// Lookups and tiles are cached forever, the tree head for a
	// minute, and stale when the database is down.
	e.db.took()
	e.db.set(func(db *sumDB) { db.down = true })
	e.get(base+"/lookup/example.com/m@v1.0.0", http.StatusOK, lookup)
	e.get(base+"/tile/8/0/000.p/1", http.StatusOK, string(tile))
	e.get(base+"/latest", http.StatusOK, latest)
	if got := e.db.took(); len(got) != 0 {
		t.Errorf("checksum database requests for cached content: %q", got)
	}
	e.advance(sumdbRevalidate)
	e.get(base+"/latest", http.StatusOK, latest)
	if got := e.db.took(); len(got) == 0 {
		t.Error("the tree head was not revalidated after a minute")
	}
	// A lookup or tree head the database's key did not sign is never
	// served or cached.
	n := newModule(t, "example.com/n", "v1.0.0")
	e.db.add(n)
	e.db.set(func(db *sumDB) { db.down = false; db.forge["example.com/n@v1.0.0"] = true })
	e.advance(upstream.DefaultOfflineFor)
	if w := e.do(http.MethodGet, base+"/lookup/example.com/n@v1.0.0"); w.Code != http.StatusBadGateway {
		t.Errorf("a forged lookup: %d %q", w.Code, w.Body)
	}
	other := newSumDB(t, "sum.example.com")
	e.db.set(func(db *sumDB) { db.priv = other.priv })
	e.advance(sumdbRevalidate)
	e.get(base+"/latest", http.StatusOK, latest)
	// The module proxy's upstream was never asked: the checksum
	// database has its own.
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("module proxy requests: %q", got)
	}
}

// TestSumDBProof checks that a record of the checksum database is
// trusted only once the database's tiles prove it is in a tree
// consistent with the latest tree seen.
func TestSumDBProof(t *testing.T) {
	e := newEnv(t)
	p := e.h.repos["goproxy"].proxy
	cached := func(path string) bool {
		t.Helper()
		e.settle()
		f, err := e.paths.Lookup(p.path, path)
		if err != nil {
			t.Fatal(err)
		}
		return f != nil
	}
	// 300 records: a full tile of records, and partial tiles.
	var ms []*module
	for i := range 300 {
		ms = append(ms, newModule(t, fmt.Sprintf("example.com/m%d", i), "v1.0.0"))
	}
	e.up.add(ms...)
	e.db.add(ms...)
	const fullTile = "sumdb/sum.example.com/tile/8/0/000"

	// A full tile that does not prove the tree is refused, and nothing
	// is cached.
	e.db.set(func(db *sumDB) { db.tiles["8/0/000"] = bytes.Repeat([]byte{1}, 256*32) })
	if w := e.do(http.MethodGet, "/go/goproxy/example.com/m5/@v/v1.0.0.zip"); w.Code != http.StatusBadGateway {
		t.Errorf("a zip proven by a bad tile: %d %q", w.Code, w.Body)
	}
	for _, path := range []string{"example.com/m5/@v/v1.0.0.zip", "sumdb/sum.example.com/lookup/example.com/m5@v1.0.0", fullTile} {
		if cached(path) {
			t.Errorf("%s was cached with a bad tile", path)
		}
	}

	// A record the tiles prove is trusted: the full tile that proves it
	// is cached, the tree's partial tiles are not.
	e.db.set(func(db *sumDB) { clear(db.tiles) })
	e.advance(testWindow)
	e.get("/go/goproxy/example.com/m5/@v/v1.0.0.zip", http.StatusOK, string(ms[5].zip))
	e.get("/go/goproxy/example.com/m299/@v/v1.0.0.mod", http.StatusOK, string(ms[299].mod))
	if !cached(fullTile) {
		t.Error("the full tile was not cached")
	}
	for _, path := range []string{"sumdb/sum.example.com/tile/8/0/001.p/44", "sumdb/sum.example.com/tile/8/1/000.p/1"} {
		if cached(path) {
			t.Errorf("the partial tile %s was cached", path)
		}
	}

	// The tiles are fetched while the lookup is: a repository allowed
	// one checksum database request at a time proves records too.
	e.get("/go/small/example.com/m9/@v/v1.0.0.zip", http.StatusOK, string(ms[9].zip))
	e.get("/go/small/sumdb/sum.example.com/lookup/example.com/m10@v1.0.0", http.StatusOK, "")

	// A forged record, with the database's genuine signed tree head, is
	// not in the tree: content matching it is refused, and neither it nor
	// the record is cached.
	evil := newModule(t, "example.com/m7", "v1.0.0")
	evil.build(t, string(evil.mod), "package x // evil\n")
	e.up.set(func(up *goProxy) { up.modules["example.com/m7"] = []*module{evil} })
	e.db.set(func(db *sumDB) { db.lie["example.com/m7@v1.0.0"] = evil.record() })
	for _, path := range []string{"example.com/m7/@v/v1.0.0.zip", "sumdb/sum.example.com/lookup/example.com/m7@v1.0.0"} {
		if w := e.do(http.MethodGet, "/go/goproxy/"+path); w.Code != http.StatusBadGateway {
			t.Errorf("%s with a forged record: %d %q", path, w.Code, w.Body)
		}
		if cached(path) {
			t.Errorf("%s was cached with a forged record", path)
		}
	}

	// A tree head that is not consistent with the latest seen, as a
	// database that rewrote its log signs, is refused: its records are
	// not trusted, and it does not replace the cached tree head.
	base := "/go/goproxy/sumdb/sum.example.com"
	latest := e.get(base+"/latest", http.StatusOK, "").Body.String()
	n := newModule(t, "example.com/n", "v1.0.0")
	e.up.add(n)
	e.db.set(func(db *sumDB) { db.order[0], db.order[1] = db.order[1], db.order[0] })
	e.db.add(n)
	for _, path := range []string{"example.com/n/@v/v1.0.0.zip", "sumdb/sum.example.com/lookup/example.com/n@v1.0.0"} {
		if w := e.do(http.MethodGet, "/go/goproxy/"+path); w.Code != http.StatusBadGateway {
			t.Errorf("%s with an inconsistent tree head: %d %q", path, w.Code, w.Body)
		}
		if cached(path) {
			t.Errorf("%s was cached with an inconsistent tree head", path)
		}
	}
	e.advance(sumdbRevalidate)
	e.get(base+"/latest", http.StatusOK, latest)
}

// TestSumDBProofReuse checks that proofs reuse the tiles of the latest
// tree proven, and replace a corrupt cached tile with a verified one.
func TestSumDBProofReuse(t *testing.T) {
	e := newEnv(t)
	var ms []*module
	for i := range 300 {
		ms = append(ms, newModule(t, fmt.Sprintf("example.com/m%d", i), "v1.0.0"))
	}
	e.up.add(ms...)
	e.db.add(ms...)
	base := "/go/goproxy/sumdb/sum.example.com"

	// A tile the database once served corrupt, cached through a
	// client's request, is fetched again when a proof needs it, and
	// replaced by the tile that passes.
	tile, _ := e.db.tile("8/0/000")
	e.db.set(func(db *sumDB) { db.tiles["8/0/000"] = bytes.Repeat([]byte{1}, 256*32) })
	e.get(base+"/tile/8/0/000", http.StatusOK, "")
	e.db.set(func(db *sumDB) { clear(db.tiles) })
	e.get("/go/goproxy/example.com/m5/@v/v1.0.0.zip", http.StatusOK, string(ms[5].zip))
	e.settle()
	e.db.set(func(db *sumDB) { db.down = true })
	e.get(base+"/tile/8/0/000", http.StatusOK, string(tile))
	e.db.set(func(db *sumDB) { db.down = false })

	// Records of the latest tree proven, and its tree head, are proven
	// with the tiles already read: the database is asked for the
	// lookups and the tree head alone.
	e.db.took()
	e.get("/go/goproxy/example.com/m6/@v/v1.0.0.zip", http.StatusOK, string(ms[6].zip))
	e.get("/go/goproxy/example.com/m299/@v/v1.0.0.mod", http.StatusOK, string(ms[299].mod))
	e.get(base+"/latest", http.StatusOK, "")
	if got := e.db.took(); !slices.Equal(got, []string{"/lookup/example.com/m6@v1.0.0", "/lookup/example.com/m299@v1.0.0", "/latest"}) {
		t.Errorf("checksum database requests for the tree proven: %q", got)
	}
	// A newer tree's partial tiles are read once.
	n := newModule(t, "example.com/n", "v1.0.0")
	e.up.add(n)
	e.db.add(n)
	e.get("/go/goproxy/example.com/n/@v/v1.0.0.zip", http.StatusOK, string(n.zip))
	e.get("/go/goproxy/example.com/m7/@v/v1.0.0.zip", http.StatusOK, string(ms[7].zip))
	if got := e.db.took(); !slices.Equal(got, []string{"/lookup/example.com/n@v1.0.0", "/tile/8/0/001.p/45", "/tile/8/1/000.p/1",
		"/lookup/example.com/m7@v1.0.0"}) {
		t.Errorf("checksum database requests for a newer tree: %q", got)
	}
}

// TestSumDBOversizedTile checks that a cached tile larger than any tile
// is fetched again when a proof needs it, and replaced by the tile that
// passes.
func TestSumDBOversizedTile(t *testing.T) {
	e := newEnv(t)
	var ms []*module
	for i := range 300 {
		ms = append(ms, newModule(t, fmt.Sprintf("example.com/m%d", i), "v1.0.0"))
	}
	e.up.add(ms...)
	e.db.add(ms...)
	base := "/go/goproxy/sumdb/sum.example.com"
	tile, _ := e.db.tile("8/0/000")
	e.db.set(func(db *sumDB) { db.tiles["8/0/000"] = bytes.Repeat([]byte("<html>"), 2*maxTile) })
	e.get(base+"/tile/8/0/000", http.StatusOK, "")
	e.db.set(func(db *sumDB) { clear(db.tiles) })
	e.get("/go/goproxy/example.com/m5/@v/v1.0.0.zip", http.StatusOK, string(ms[5].zip))
	e.settle()
	e.db.set(func(db *sumDB) { db.down = true })
	e.get(base+"/tile/8/0/000", http.StatusOK, string(tile))
}

func TestRequests(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{
		"/go/nope/example.com/m/@v/list", // not a repository
		"/go/pypi/example.com/m/@v/list", // another format's
		"/go/goproxy",
		"/go/goproxy/",
		"/go/goproxy/example.com/m",
		"/go/goproxy/example.com/M/@v/list",       // not case-encoded
		"/go/goproxy/example.com/!/@v/list",       // a bad encoding
		"/go/goproxy/nodot/m/@v/list",             // no dot in the first element
		"/go/goproxy/example.com//m/@v/list",      // an empty element
		"/go/goproxy/example.com/m/@v/v1.0.0.tar", // not a file the protocol has
		"/go/goproxy/example.com/m/@v/main.zip",   // a query names no zip
		"/go/goproxy/example.com/m/@v/v1.0.zip",   // not canonical
		"/go/goproxy/example.com/m/@v/.info",
		"/go/goproxy/example.com/m/@v/info", // no extension
		"/go/goproxy/example.com/m/@v/v1.0.0",
		"/go/goproxy/sumdb/",
		"/go/goproxy/sumdb/sum.example.com",
	} {
		e.get(path, http.StatusNotFound, "")
	}
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("upstream requests for malformed paths: %q", got)
	}
	if w := e.do(http.MethodPut, "/go/goproxy/example.com/m/@v/v1.0.0.zip"); w.Code != http.StatusMethodNotAllowed ||
		w.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("PUT: %d, Allow %q", w.Code, w.Header().Get("Allow"))
	}
	e.auth.reset()
	e.auth.deny = true
	if w := e.do(http.MethodGet, "/go/go-all/example.com/m/@v/list"); w.Code != http.StatusUnauthorized {
		t.Errorf("a refused request: %d", w.Code)
	}
	if got := e.auth.reset(); !slices.Equal(got, []string{"virtual go-all :pull"}) {
		t.Errorf("authorizations %q", got)
	}
}

func TestPaths(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/!azure/azure-sdk-for-go": "github.com/Azure/azure-sdk-for-go",
		"example.com/m":                      "example.com/m",
		"v1.0.0-!r!c1":                       "v1.0.0-RC1",
	} {
		if got, ok := unescape(in); !ok || got != want {
			t.Errorf("unescape(%q) = %q, %v", in, got, ok)
		}
		if got := escape(want); got != in {
			t.Errorf("escape(%q) = %q", want, got)
		}
	}
	for _, in := range []string{"example.com/M", "example.com/!", "example.com/!1"} {
		if _, ok := unescape(in); ok {
			t.Errorf("unescape(%q) succeeded", in)
		}
	}
	for p, want := range map[string]bool{
		"example.com/m": true, "golang.org/x/text": true, "gopkg.in/yaml.v3": true, "github.com/Azure/go_x~y": true,
		"example": false, "Example.com/m": false, "example.com/": false, "example.com/.m": false, "example.com/m.": false,
		"-example.com/m": false, "example.com/m@v": false, "example_x.com/m": false, "": false,
	} {
		if got := validPath(p); got != want {
			t.Errorf("validPath(%q) = %v", p, got)
		}
	}
	for v, want := range map[string]bool{
		"v1.0.0": true, "v0.0.0-20260102030405-abcdefabcdef": true, "v2.0.0+incompatible": true, "v1.0.0-rc.1": true,
		"v1.0.0-0.20260102030405-abcdefabcdef": true,
		"v1.0":                                 false, "1.0.0": false, "v01.0.0": false, "v1.0.0-": false, "v1.0.0-rc.01": false, "v1.0.0+build": false,
		"master": false, "v1.0.0-rc..1": false,
	} {
		if got := canonical(v); got != want {
			t.Errorf("canonical(%q) = %v", v, got)
		}
	}
	for tile, want := range map[string]bool{
		"8/0/000": true, "8/1/x001/234": true, "8/0/x123/x456/789.p/255": true, "8/data/001": true,
		"8/0": false, "8/0/1": false, "8/x/000": false, "8/0/001/234": false, "8/0/x001.p/3": false, "8/0/000.p/": false,
	} {
		if got := validTile(tile); got != want {
			t.Errorf("validTile(%q) = %v", tile, got)
		}
	}
}
