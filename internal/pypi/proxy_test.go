package pypi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
)

// pagesTook filters the page requests from requests the index took.
func pagesTook(reqs []string) []string {
	var out []string
	for _, r := range reqs {
		if strings.HasPrefix(r, "page ") {
			out = append(out, r)
		}
	}
	return out
}

func TestProxyPageRevalidation(t *testing.T) {
	e := newEnv(t)
	a := wheel("pkg", "1.0", nil)
	e.up.add("pkg", upFile{dist: a, metadata: true})

	p := e.page("remote", "pkg")
	if !slices.Equal(p.filenames(), []string{a.filename}) || p.Files[0].Hashes["sha256"] != a.sha256() ||
		p.Files[0].URL != "../../files/pkg/"+a.filename || p.Files[0].UploadTime != "2026-01-02T03:04:05.123456Z" ||
		*p.Files[0].Size != int64(len(a.body)) || p.Files[0].CoreMetadata == nil {
		t.Fatalf("proxied page %+v", p)
	}
	if got := pagesTook(e.up.took()); !slices.Equal(got, []string{"page /simple/pkg/ "}) {
		t.Errorf("first fetch: %q", got)
	}
	// Within the window: from the cache.
	e.advance(testWindow / 2)
	e.page("remote", "pkg")
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("within the window: %q", got)
	}
	// After it: a conditional request, answered 304.
	e.advance(testWindow)
	e.page("remote", "pkg")
	if got := e.up.took(); len(got) != 1 || !strings.HasSuffix(got[0], `"`) {
		t.Errorf("revalidation: %q, want a request with If-None-Match", got)
	}
	if got := e.metric(`flint_proxy_requests_total{repository="remote",result="revalidated"}`); got != "1" {
		t.Errorf("revalidated metric %q", got)
	}
	// A new release upstream shows after the next window.
	b := wheel("pkg", "2.0", nil)
	e.up.add("pkg", upFile{dist: b})
	e.page("remote", "pkg")
	e.advance(testWindow)
	if got := e.page("remote", "pkg").filenames(); !slices.Equal(got, []string{a.filename, b.filename}) {
		t.Errorf("after an upstream change: %q", got)
	}
	// A restart forgets confirmations, not the cached page.
	e.restart()
	e.up.set(func(x *index) { x.down = true })
	if got := e.page("remote", "pkg").filenames(); len(got) != 2 {
		t.Errorf("after a restart with the upstream down: %q", got)
	}
	if got := e.metric(`flint_proxy_requests_total{repository="remote",result="stale"}`); got != "1" {
		t.Errorf("stale metric %q", got)
	}
	// The root index lists cached projects.
	if w := e.get("/pypi/remote/simple/", http.StatusOK); !strings.Contains(w.Body.String(), `href="pkg/"`) {
		t.Errorf("proxy root index %s", w.Body)
	}
}

func TestProxyOutage(t *testing.T) {
	e := newEnv(t)
	a := wheel("pkg", "1.0", nil)
	e.up.add("pkg", upFile{dist: a})
	e.up.add("gone", upFile{dist: wheel("gone", "1.0", nil)})
	e.page("remote", "pkg")
	e.page("remote", "gone")
	e.get("/pypi/remote/files/pkg/"+a.filename, http.StatusOK)
	e.settle()

	e.up.set(func(x *index) { x.down = true })
	e.advance(2 * testWindow)
	// Cached pages and files keep serving.
	e.page("remote", "pkg")
	if w := e.get("/pypi/remote/files/pkg/"+a.filename, http.StatusOK); !bytes.Equal(w.Body.Bytes(), a.body) {
		t.Error("the cached file is wrong")
	}
	// What was never cached cannot be served.
	w := e.get("/pypi/remote/simple/other/", http.StatusServiceUnavailable)
	if !strings.Contains(w.Body.String(), "unavailable") {
		t.Errorf("uncached project with the upstream down: %s", w.Body)
	}
	// A project the upstream answers is not found is not found, even if
	// cached.
	e.up.set(func(x *index) { x.down = false; delete(x.projects, "gone") })
	e.advance(2 * testWindow)
	e.get("/pypi/remote/simple/gone/", http.StatusNotFound)
	e.get("/pypi/remote/simple/never/", http.StatusNotFound)
}

func TestProxyFiles(t *testing.T) {
	e := newEnv(t)
	a := wheel("pkg", "1.0", nil)
	unhashed := sdist("pkg", "1.0", nil)
	bad := wheel("pkg", "2.0", nil)
	e.up.add("pkg", upFile{dist: a, metadata: true}, upFile{dist: unhashed, noHash: true}, upFile{dist: bad})
	e.up.set(func(x *index) { x.corrupt[bad.filename] = true })
	e.page("remote", "pkg")
	e.up.took()

	// Fetched from the files host, verified, and cached.
	if w := e.get("/pypi/remote/files/pkg/"+a.filename, http.StatusOK); !bytes.Equal(w.Body.Bytes(), a.body) {
		t.Fatal("the fetched file is wrong")
	}
	e.settle()
	if !e.has(fileKey("remote", a.filename)) {
		t.Error("the fetched file is not cached")
	}
	e.up.took()
	e.get("/pypi/remote/files/pkg/"+a.filename, http.StatusOK)
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("a cached file went upstream: %q", got)
	}
	// The core-metadata file, verified and cached.
	for range 2 {
		if w := e.get("/pypi/remote/files/pkg/"+a.filename+".metadata", http.StatusOK); !bytes.Equal(w.Body.Bytes(), a.metadata) {
			t.Fatalf("core metadata %q", w.Body)
		}
	}
	if got := e.up.took(); len(got) != 1 || !strings.HasSuffix(got[0], ".metadata") || !e.has(metadataKey("remote", a.filename)) {
		t.Errorf("core metadata fetches %q", got)
	}
	e.get("/pypi/remote/files/pkg/"+unhashed.filename+".metadata", http.StatusNotFound)

	// A file without a hash passes through, uncached.
	if w := e.get("/pypi/remote/files/pkg/"+unhashed.filename, http.StatusOK); !bytes.Equal(w.Body.Bytes(), unhashed.body) {
		t.Error("the unhashed file is wrong")
	}
	if e.has(fileKey("remote", unhashed.filename)) {
		t.Error("a file without a hash was cached")
	}
	// A file that does not match its hash is refused, or cut off if part
	// of it is out already, and not cached.
	func() {
		defer func() {
			if p := recover(); p != nil && p != http.ErrAbortHandler {
				t.Errorf("a corrupted file: panic %v", p)
			}
		}()
		if w := e.do("GET", "/pypi/remote/files/pkg/"+bad.filename, nil); w.Code != http.StatusBadGateway ||
			!strings.Contains(w.Body.String(), "did not match its sha256 digest") {
			t.Errorf("a corrupted file: %d %s", w.Code, w.Body)
		}
	}()
	e.settle()
	if e.has(fileKey("remote", bad.filename)) {
		t.Error("a corrupted file was cached")
	}
	e.get("/pypi/remote/files/pkg/nope-1.0.tar.gz", http.StatusNotFound)

	// A file stored for another repository is still fetched: a proxy
	// serves only what its own upstream sent it.
	e.up.took()
	e.page("small", "pkg")
	e.get("/pypi/small/files/pkg/"+a.filename, http.StatusOK)
	e.settle()
	if got := e.up.took(); len(got) != 2 || !strings.HasPrefix(got[0], "page ") || got[1] != "file /packages/"+a.filename {
		t.Errorf("another proxy's requests: %q", got)
	}
	if !e.has(fileKey("small", a.filename)) {
		t.Error("the fetched file was not cached")
	}
}

func TestProxyDoesNotServeForeignBlobs(t *testing.T) {
	e := newEnv(t)
	private := wheel("secret", "1.0", nil)
	e.mustUpload("local", private)
	// An upstream page names the private file's digests for a file of
	// its own, whose bytes it does not have.
	evil := dist{name: "evil", version: "1.0", filename: "evil-1.0-py3-none-any.whl", body: private.body, metadata: private.metadata}
	e.up.add("evil", upFile{dist: evil, metadata: true})
	e.up.set(func(x *index) { x.corrupt[evil.filename] = true })
	for _, name := range []string{evil.filename, evil.filename + ".metadata"} {
		func() {
			defer func() {
				if p := recover(); p != nil && p != http.ErrAbortHandler {
					t.Errorf("%s: panic %v", name, p)
				}
			}()
			w := e.do("GET", "/pypi/remote/files/evil/"+name, nil)
			if w.Code == http.StatusOK || bytes.Equal(w.Body.Bytes(), private.body) || bytes.Equal(w.Body.Bytes(), private.metadata) {
				t.Errorf("%s: %d, served the private bytes", name, w.Code)
			}
		}()
	}
	e.settle()
	if e.has(fileKey("remote", evil.filename)) || e.has(metadataKey("remote", evil.filename)) {
		t.Error("the private blobs were linked to the proxy repository")
	}
}

func TestProxyStalePageWithHangingUpstream(t *testing.T) {
	saved := revalidateTimeout
	revalidateTimeout = 100 * time.Millisecond
	t.Cleanup(func() { revalidateTimeout = saved })
	e := newEnv(t)
	a := wheel("pkg", "1.0", nil)
	e.up.add("pkg", upFile{dist: a})
	e.page("remote", "pkg")
	// After a restart the page is in neither memory cache, and the
	// upstream does not answer within the revalidation timeout.
	e.restart()
	e.up.set(func(x *index) { x.hang = true })
	if got := e.page("remote", "pkg").filenames(); !slices.Equal(got, []string{a.filename}) {
		t.Errorf("with the upstream hanging: %q", got)
	}
	if got := e.metric(`flint_proxy_requests_total{repository="remote",result="stale"}`); got != "1" {
		t.Errorf("stale metric %q", got)
	}
}

func TestProxyHTMLUpstream(t *testing.T) {
	e := newEnv(t)
	e.up.set(func(x *index) { x.html = true })
	a := wheel("pkg", "1.0", nil)
	r := wheel("pkg", "1.1", nil)
	y := sdist("pkg", "0.9", nil)
	e.up.add("pkg", upFile{dist: a, metadata: true}, upFile{dist: y, yanked: "bad"}, upFile{dist: r, relative: true})
	p := e.page("remote", "pkg")
	if got := p.filenames(); !slices.Equal(got, []string{y.filename, a.filename, r.filename}) {
		t.Fatalf("files %q", got)
	}
	if p.Files[1].Hashes["sha256"] != a.sha256() || p.Files[1].RequiresPython != ">=3.9" || p.Files[1].CoreMetadata == nil ||
		p.Files[0].Yanked != "bad" || p.Files[1].Size != nil {
		t.Errorf("parsed page %+v", p)
	}
	if w := e.get("/pypi/remote/files/pkg/"+r.filename, http.StatusOK); !bytes.Equal(w.Body.Bytes(), r.body) {
		t.Error("the relatively linked file is wrong")
	}
	if !slices.Equal(p.Versions, []string{"0.9", "1.0", "1.1"}) {
		t.Errorf("versions from file names %q", p.Versions)
	}
	if w := e.get("/pypi/remote/files/pkg/"+a.filename, http.StatusOK); !bytes.Equal(w.Body.Bytes(), a.body) {
		t.Error("the file is wrong")
	}
}

func TestParseHTMLPage(t *testing.T) {
	base := mustURL(t, "https://index.example/simple/pkg/")
	page := `<!DOCTYPE html><html><head><meta name="pypi:repository-version" content="1.0"></head><body>
<!-- <a href="commented-1.0.tar.gz">x</a> -->
<a href="https://files.example/p/pkg-1.0.tar.gz#sha256=` + strings.Repeat("A", 64) + `" data-requires-python="&gt;=3.8&amp;" data-yanked="">pkg-1.0.tar.gz</a>
<a data-core-metadata="true" href=../../p/pkg-1.1-py3-none-any.whl#md5=00 >  <b>pkg-1.1-py3-none-any.whl</b> </a>
<a href='/p/pkg-2.0.zip' data-dist-info-metadata="sha256=` + strings.Repeat("b", 64) + `">pkg-2.0.zip</a>
<a href="javascript:alert(1)">bad</a>
<a name="anchor-without-href">x</a>
<abbr>not a link</abbr>
<a href="https://files.example/p/bad%2Fname.whl">bad/name.whl</a>
</body></html>`
	p := parseHTMLPage([]byte(page), base, "pkg")
	if got := p.filenames(); !slices.Equal(got, []string{"pkg-1.0.tar.gz", "pkg-1.1-py3-none-any.whl", "pkg-2.0.zip"}) {
		t.Fatalf("files %q", got)
	}
	f0, f1, f2 := p.Files[0], p.Files[1], p.Files[2]
	if f0.URL != "https://files.example/p/pkg-1.0.tar.gz" || f0.SHA256 != strings.Repeat("a", 64) || f0.RequiresPython != ">=3.8&" ||
		!f0.Yanked || f0.YankedReason != "" || f0.Version != "1.0" || f0.Metadata {
		t.Errorf("first file %+v", f0)
	}
	if f1.URL != "https://index.example/p/pkg-1.1-py3-none-any.whl" || f1.SHA256 != "" || !f1.Metadata || f1.MetadataSHA256 != "" {
		t.Errorf("second file %+v", f1)
	}
	if f2.URL != "https://index.example/p/pkg-2.0.zip" || !f2.Metadata || f2.MetadataSHA256 != strings.Repeat("b", 64) {
		t.Errorf("third file %+v", f2)
	}
}

func (p *projectDoc) filenames() []string {
	var out []string
	for _, f := range p.Files {
		out = append(out, f.Filename)
	}
	return out
}

func TestParseJSONPage(t *testing.T) {
	base := mustURL(t, "https://index.example/simple/pkg/")
	if _, err := parseJSONPage([]byte(`{"meta": {"api-version": "2.0"}, "files": []}`), base, "pkg"); err == nil {
		t.Error("API version 2 accepted")
	}
	if _, err := parseJSONPage([]byte(`[`), base, "pkg"); err == nil {
		t.Error("invalid JSON accepted")
	}
	p, err := parseJSONPage([]byte(`{"meta": {"api-version": "1.0"}, "files": [
		{"filename": "pkg-1.0.tar.gz", "url": "/f/pkg-1.0.tar.gz", "hashes": {"sha256": "nothex"}, "dist-info-metadata": {"sha256": "`+strings.Repeat("c", 64)+`"}, "yanked": true},
		{"filename": "../evil", "url": "x"},
		{"filename": "other-1.0.tar.gz", "url": "/f/other-1.0.tar.gz"},
		{"filename": "pkg-1.1.tar.gz", "url": "/f/pkg-1.1.tar.gz", "yanked": null},
		{"filename": "pkg-1.2.tar.gz", "url": "/f/pkg-1.2.tar.gz", "yanked": false},
		{"filename": "pkg-1.3.tar.gz", "url": "/f/pkg-1.3.tar.gz", "yanked": "broken"}
	]}`), base, "pkg")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.filenames(); !slices.Equal(got, []string{"pkg-1.0.tar.gz", "pkg-1.1.tar.gz", "pkg-1.2.tar.gz", "pkg-1.3.tar.gz"}) {
		t.Fatalf("files %q", got)
	}
	if p.Files[1].Yanked || p.Files[2].Yanked || !p.Files[3].Yanked || p.Files[3].YankedReason != "broken" {
		t.Errorf("yanked: %v %v %v %q", p.Files[1].Yanked, p.Files[2].Yanked, p.Files[3].Yanked, p.Files[3].YankedReason)
	}
	if p.Files[0].URL != "https://index.example/f/pkg-1.0.tar.gz" || p.Files[0].SHA256 != "" ||
		p.Files[0].MetadataSHA256 != strings.Repeat("c", 64) || !p.Files[0].Yanked || p.Files[0].Size != -1 {
		t.Errorf("parsed %+v", p.Files)
	}
}

func TestProxyCacheIsPerProject(t *testing.T) {
	e := newEnv(t)
	// A page lists only files whose names belong to its project.
	victim := wheel("victim", "1.0", nil)
	e.up.add("evil", upFile{dist: victim, metadata: true})
	if got := e.page("remote", "evil").filenames(); len(got) != 0 {
		t.Errorf("another project's files on a page: %q", got)
	}
	e.get("/pypi/remote/files/evil/"+victim.filename+".metadata", http.StatusNotFound)
	// A source distribution name two projects can claim: the core-metadata
	// file cached through one project's page does not serve the other.
	shared := sdist("foo", "1-1", metadataFor("foo", "1.post1"))
	e.up.add("foo", upFile{dist: shared, metadata: true})
	e.up.add("foo-1", upFile{dist: shared, metadata: true})
	e.get("/pypi/remote/files/foo/"+shared.filename+".metadata", http.StatusOK)
	e.up.took()
	e.get("/pypi/remote/files/foo-1/"+shared.filename+".metadata", http.StatusOK)
	if got := e.up.took(); !slices.Contains(got, "file /packages/"+shared.filename+".metadata") {
		t.Errorf("core metadata cached for another project was served: %q", got)
	}
}

func TestProxyMetadataFetchIsPerProject(t *testing.T) {
	e := newEnv(t)
	fooMD, foo1MD := metadataFor("foo", "1.post1"), metadataFor("foo-1", "1")
	asked, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/foo/foo-1-1.tar.gz.metadata":
			close(asked)
			<-release
			w.Write(fooMD)
		case "/foo-1/foo-1-1.tar.gz.metadata":
			w.Write(foo1MD)
		}
	}))
	defer srv.Close()
	rp := e.h.repos["remote"]
	ctx := context.Background()
	fooDone := make(chan []byte)
	go func() {
		b, _ := e.h.fetchMetadata(ctx, "", rp, "foo", "foo-1-1.tar.gz", srv.URL+"/foo/foo-1-1.tar.gz.metadata", blob.FromBytes(fooMD))
		fooDone <- b
	}()
	<-asked
	// Another project's file of the same name, while the first fetch is
	// in progress, is fetched from its own page's link.
	foo1Done := make(chan []byte)
	go func() {
		b, _ := e.h.fetchMetadata(ctx, "", rp, "foo-1", "foo-1-1.tar.gz", srv.URL+"/foo-1/foo-1-1.tar.gz.metadata", blob.FromBytes(foo1MD))
		foo1Done <- b
	}()
	select {
	case b := <-foo1Done:
		if !bytes.Equal(b, foo1MD) {
			t.Errorf("foo-1's core metadata %q", b)
		}
		close(release)
	case <-time.After(5 * time.Second):
		close(release)
		t.Errorf("foo-1's fetch waited for foo's, and got %q", <-foo1Done)
	}
	if b := <-fooDone; !bytes.Equal(b, fooMD) {
		t.Errorf("foo's core metadata %q", b)
	}
}

func TestProxyDiskPressure(t *testing.T) {
	e := newEnv(t)
	a := wheel("pkg", "1.0", nil)
	e.up.add("pkg", upFile{dist: a})
	e.page("remote", "pkg")
	e.free.Store(1 << 20) // below the 1 GiB threshold
	e.advance(2 * time.Second)
	if w := e.get("/pypi/remote/files/pkg/"+a.filename, http.StatusOK); !bytes.Equal(w.Body.Bytes(), a.body) {
		t.Fatal("the passed-through file is wrong")
	}
	e.settle()
	if e.has(fileKey("remote", a.filename)) {
		t.Error("a file was cached under disk pressure")
	}
	if got := e.metric(`flint_proxy_requests_total{repository="remote",result="passthrough"}`); got != "1" {
		t.Errorf("passthrough metric %q", got)
	}
}

func TestProxySizeLimit(t *testing.T) {
	e := newEnv(t)
	// The small repository holds 2500 bytes; these are about 600 each.
	var ds []dist
	for _, v := range []string{"1", "2", "3", "4", "5"} {
		d := wheel("pkg", v+".0", nil)
		ds = append(ds, d)
		e.up.add("pkg", upFile{dist: d})
	}
	for _, d := range ds {
		e.get("/pypi/small/files/pkg/"+d.filename, http.StatusOK)
		e.settle()
		e.advance(time.Minute)
	}
	if err := e.h.Evict(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.has(fileKey("small", ds[0].filename)) || !e.has(fileKey("small", ds[4].filename)) {
		t.Error("eviction did not remove the least recently pulled file first")
	}
	c := e.h.repos["small"].proxy.cache
	if c.Size() > c.Limit() {
		t.Errorf("cached %d bytes over the %d limit", c.Size(), c.Limit())
	}
	// Pull times persist, and a restart reloads the tracker.
	if err := e.h.FlushPullTimes(context.Background()); err != nil {
		t.Fatal(err)
	}
	size := c.Size()
	e.restart()
	if got := e.h.repos["small"].proxy.cache.Size(); got != size {
		t.Errorf("reloaded size %d, want %d", got, size)
	}
	if !e.has(pulledKey(fileKey("small", ds[4].filename))) {
		t.Error("pull times were not persisted")
	}
	// Evicted files are fetched again on demand.
	e.get("/pypi/small/files/pkg/"+ds[0].filename, http.StatusOK)
}

func TestRunProxy(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.RunProxy(ctx); close(done) }()
	a := wheel("pkg", "1.0", nil)
	e.up.add("pkg", upFile{dist: a})
	e.get("/pypi/small/files/pkg/"+a.filename, http.StatusOK)
	e.settle()
	cancel()
	<-done
	if !e.has(pulledKey(fileKey("small", a.filename))) {
		t.Error("the pull times were not persisted on stop")
	}
}

func TestVirtual(t *testing.T) {
	e := newEnv(t)
	up1 := wheel("shared", "1.0", nil)
	upOnly := wheel("public", "1.0", nil)
	e.up.add("shared", upFile{dist: up1, metadata: true})
	e.up.add("public", upFile{dist: upOnly})

	// Without a hosted copy, the upstream's files come through.
	if got := e.page("all", "shared").filenames(); !slices.Equal(got, []string{up1.filename}) {
		t.Fatalf("shared before the hosted upload: %q", got)
	}
	if w := e.get("/pypi/all/files/shared/"+up1.filename, http.StatusOK); !bytes.Equal(w.Body.Bytes(), up1.body) {
		t.Fatal("file through the virtual repository is wrong")
	}
	e.get("/pypi/all/files/shared/"+up1.filename+".metadata", http.StatusOK)

	// Once a hosted member owns the name, the upstream's versions are
	// never served, not even ones it has that the hosted repository lacks.
	h1 := wheel("shared", "0.1", nil)
	e.mustUpload("local", h1)
	e.up.took()
	p := e.page("all", "shared")
	if got := p.filenames(); !slices.Equal(got, []string{h1.filename}) || !slices.Equal(p.Versions, []string{"0.1"}) {
		t.Errorf("shared after the hosted upload: %q %q", got, p.Versions)
	}
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("a protected name was looked up upstream: %q", got)
	}
	e.get("/pypi/all/files/shared/"+up1.filename, http.StatusNotFound)
	if w := e.get("/pypi/all/files/shared/"+h1.filename, http.StatusOK); !bytes.Equal(w.Body.Bytes(), h1.body) {
		t.Error("the hosted file through the virtual repository is wrong")
	}
	if v := jsonVersion(t, e, "/pypi/all/pypi/shared/json"); v != "0.1" {
		t.Errorf("JSON API through the virtual repository: %s", v)
	}
	// Deleting the hosted files does not hand the name back.
	e.do("DELETE", "/api/v1/pypi/local/projects/shared/files/"+h1.filename, nil)
	e.get("/pypi/all/simple/shared/", http.StatusNotFound)

	// Without protection, the members merge, the first member winning
	// where they have the same file name.
	same := wheel("public", "1.0", metadataFor("public", "1.0", "Summary: hosted copy"))
	e.mustUpload("local", same)
	h2 := wheel("public", "0.5", nil)
	e.mustUpload("local", h2)
	p = e.page("open", "public")
	if got := p.filenames(); !slices.Equal(got, []string{h2.filename, upOnly.filename}) {
		t.Fatalf("merged files %q", got)
	}
	if p.Files[1].Hashes["sha256"] != same.sha256() {
		t.Error("the merged page does not list the first member's file")
	}
	if w := e.get("/pypi/open/files/public/"+same.filename, http.StatusOK); !bytes.Equal(w.Body.Bytes(), same.body) {
		t.Error("the merged file is not the first member's")
	}
	if w := e.get("/pypi/open/simple/", http.StatusOK, "Accept", mtSimpleJSON); !strings.Contains(w.Body.String(), `{"name":"public"}`) ||
		!strings.Contains(w.Body.String(), `{"name":"shared"}`) {
		t.Errorf("virtual root index %s", w.Body)
	}
	// The protected virtual repository serves only the hosted versions.
	if got := e.page("all", "public").filenames(); !slices.Equal(got, []string{h2.filename, same.filename}) {
		t.Errorf("protected files %q", got)
	}
}

func TestVirtualMemberFailure(t *testing.T) {
	e := newEnv(t)
	e.mustUpload("team", wheel("x", "1.0", nil)) // not a member
	e.up.set(func(x *index) { x.down = true })
	// Only the proxy member could answer: the failure shows.
	e.get("/pypi/all/simple/pkg/", http.StatusServiceUnavailable)
	// With protection off, the hosted member's files are served while
	// the upstream is down.
	h := wheel("pkg", "1.0", nil)
	e.mustUpload("local", h)
	if got := e.page("open", "pkg").filenames(); !slices.Equal(got, []string{h.filename}) {
		t.Errorf("files while the upstream is down: %q", got)
	}
}

func TestProxyAuthorization(t *testing.T) {
	e := newEnv(t)
	e.up.add("pkg", upFile{dist: wheel("pkg", "1.0", nil)})
	e.auth.status = http.StatusUnauthorized
	w := e.get("/pypi/remote/simple/pkg/", http.StatusUnauthorized)
	if w.Header().Get("WWW-Authenticate") != `Basic realm="flint"` {
		t.Errorf("challenge %q", w.Header().Get("WWW-Authenticate"))
	}
	e.auth.status = http.StatusForbidden
	e.get("/pypi/all/simple/pkg/", http.StatusForbidden)
	e.auth.status = http.StatusInternalServerError
	e.get("/pypi/all/simple/pkg/", http.StatusInternalServerError)
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("unauthorized requests reached the upstream: %q", got)
	}
	e.auth.status = 0
	e.auth.reset()
	e.page("all", "pkg")
	if got := e.auth.reset(); !slices.Equal(got, []string{"all:pull"}) {
		t.Errorf("authorization of a virtual repository %q, want only the virtual repository", got)
	}
}

func TestProxyJSONAPI(t *testing.T) {
	e := newEnv(t)
	a := wheel("pkg", "1.0", metadataFor("pkg", "1.0", "Requires-Dist: idna", "Requires-Python: >=3.10"))
	b := wheel("pkg", "2.0b1", nil)
	old := sdist("pkg", "0.5", nil)
	e.up.add("pkg", upFile{dist: a, metadata: true}, upFile{dist: b, metadata: true}, upFile{dist: old})
	var out struct {
		Info       map[string]any   `json:"info"`
		LastSerial int64            `json:"last_serial"`
		Releases   map[string][]any `json:"releases"`
		URLs       []map[string]any `json:"urls"`
	}
	if err := json.Unmarshal(e.get("/pypi/remote/pypi/pkg/json", http.StatusOK).Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// The latest final release, described by its core-metadata file,
	// which is fetched and cached.
	if out.Info["version"] != "1.0" || out.Info["summary"] != "The pkg package" || out.Info["requires_dist"].([]any)[0] != "idna" ||
		out.Info["requires_python"] != ">=3.10" || len(out.Releases) != 3 || len(out.URLs) != 1 || out.LastSerial == 0 {
		t.Errorf("proxied JSON API: %+v", out)
	}
	if u := out.URLs[0]; u["packagetype"] != "bdist_wheel" || u["size"] != float64(len(a.body)) ||
		u["upload_time_iso_8601"] != "2026-01-02T03:04:05.123456Z" {
		t.Errorf("url entry %v", u)
	}
	if !e.has(metadataKey("remote", a.filename)) {
		t.Error("the core-metadata file was not cached")
	}
	// A release without core metadata has a minimal description.
	if err := json.Unmarshal(e.get("/pypi/remote/pypi/pkg/0.5/json", http.StatusOK).Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Info["version"] != "0.5" || out.Info["name"] != "pkg" || out.Info["summary"] != "" {
		t.Errorf("minimal info %v", out.Info)
	}
	// Offline, the cached metadata still describes the release.
	e.up.set(func(x *index) { x.down = true })
	e.advance(2 * testWindow)
	if v := jsonVersion(t, e, "/pypi/remote/pypi/pkg/json"); v != "1.0" {
		t.Errorf("offline JSON API version %s", v)
	}
}

func TestProxyPageNotStoredIsNotFresh(t *testing.T) {
	e := newEnv(t)
	a := wheel("pkg", "1.0", nil)
	e.up.add("pkg", upFile{dist: a})
	e.page("remote", "pkg")
	// A new release while the disk is full: served, but not stored, so
	// the next request asks the upstream again instead of serving the
	// older cached page.
	e.up.add("pkg", upFile{dist: wheel("pkg", "2.0", nil)})
	e.free.Store(1 << 20)
	e.advance(2 * testWindow)
	if got := e.page("remote", "pkg").filenames(); len(got) != 2 {
		t.Fatalf("under disk pressure: %q", got)
	}
	e.up.took()
	if got := e.page("remote", "pkg").filenames(); len(got) != 2 {
		t.Errorf("the next request: %q", got)
	}
	if got := pagesTook(e.up.took()); len(got) != 1 {
		t.Errorf("the next request did not revalidate: %q", got)
	}
}
