package upstream_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/upstream"
)

// fileUpstream is a fake path-addressed upstream: it serves files by
// path, can corrupt them, answer 410, or redirect to another server.
type fileUpstream struct {
	*httptest.Server

	mu       sync.Mutex
	files    map[string][]byte
	gone     map[string]bool
	redirect map[string]string
	corrupt  bool
	down     bool
	requests []string
}

func newFileUpstream(t *testing.T) *fileUpstream {
	u := &fileUpstream{files: map[string][]byte{}, gone: map[string]bool{}, redirect: map[string]string{}}
	u.Server = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.Close)
	return u
}

func (u *fileUpstream) put(path string, b []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.files[path] = b
}

func (u *fileUpstream) set(f func(u *fileUpstream)) {
	u.mu.Lock()
	defer u.mu.Unlock()
	f(u)
}

func (u *fileUpstream) took() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	r := u.requests
	u.requests = nil
	return r
}

func (u *fileUpstream) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.requests = append(u.requests, r.Method+" "+r.URL.Path)
	b, ok := u.files[r.URL.Path]
	gone, target, corrupt, down := u.gone[r.URL.Path], u.redirect[r.URL.Path], u.corrupt, u.down
	u.mu.Unlock()
	switch {
	case down:
		w.WriteHeader(http.StatusBadGateway)
	case target != "":
		http.Redirect(w, r, target, http.StatusFound)
	case gone:
		w.WriteHeader(http.StatusGone)
	case !ok:
		http.NotFound(w, r)
	default:
		if corrupt {
			b = append(bytes.Clone(b[:len(b)-1]), b[len(b)-1]^1)
		}
		w.Header().Set("Content-Type", "application/x-test")
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Write(b)
	}
}

// pathEnv serves path-addressed proxy repositories through a PathCache
// on a real HTTP server, so aborted responses reach the client as such.
type pathEnv struct {
	*docEnv
	pc      *upstream.PathCache
	fetcher *upstream.Fetcher
	files   *fileUpstream
	repos   map[string]*upstream.PathRepo
	srv     *httptest.Server
	expect  map[string]upstream.Expect // by path
}

func newPathEnv(t *testing.T, limit int64, policy upstream.Policy) *pathEnv {
	e := &pathEnv{docEnv: newDocEnv(t), files: newFileUpstream(t), expect: map[string]upstream.Expect{}}
	e.fetcher = upstream.NewFetcher(e.blobs, 0)
	e.restartPath(limit, policy)
	e.srv = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.srv.Close)
	return e
}

// restartPath builds a new PathCache over the same stores.
func (e *pathEnv) restartPath(limit int64, policy upstream.Policy) {
	e.t.Helper()
	e.pc = upstream.NewPathCache(upstream.PathCacheOptions{Meta: e.meta, Blobs: e.blobs, Fetcher: e.fetcher, Docs: e.c,
		Space: e.space, Metrics: e.pm, Logger: quiet, Now: e.clock.Now})
	e.repos = map[string]*upstream.PathRepo{}
	for _, name := range []string{"remote", "other"} {
		rp := &upstream.PathRepo{Name: name, Format: "generic", Revalidate: docWindow, SizeLimit: limit,
			Client: newClient(e.t, e.files.URL, upstream.Options{Now: e.clock.Now, Policy: policy})}
		if name == "other" {
			rp.SizeLimit = 0
		}
		if err := e.pc.Add(rp); err != nil {
			e.t.Fatal(err)
		}
		e.repos[name] = rp
	}
}

// serve routes /<repo>/<path>: paths under passthru/ are passed
// through, *.xml files are documents, and everything else is immutable.
func (e *pathEnv) serve(w http.ResponseWriter, r *http.Request) {
	repo, path, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	rp := e.repos[repo]
	rt := &upstream.Route{Kind: upstream.Immutable, Path: path, URL: e.files.URL + "/" + path, Expect: upstream.Expect{Size: -1},
		KeepGone: r.URL.Query().Has("keepgone")}
	switch {
	case strings.HasPrefix(path, "passthru/"):
		rt.Kind = upstream.PassThrough
	case strings.HasSuffix(path, ".xml"):
		rt.Kind = upstream.Mutable
		if r.URL.Query().Has("upper") {
			rt.Rewrite, rt.Variant = upper, "upper"
		}
	default:
		e.t.Helper()
		if x, ok := e.expect[path]; ok {
			rt.Expect = x
		}
		rt.Expect.Compute = []string{upstream.SHA1}
	}
	e.pc.Serve(w, r, rp, rt, "tester")
}

// fetch requests a path and returns the status and body; a body cut
// off by the server is reported as err.
func (e *pathEnv) fetch(method, path string, hdr ...string) (int, string, error) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), err
}

func (e *pathEnv) want(path string, status int, body string) {
	e.t.Helper()
	got, b, err := e.fetch(http.MethodGet, path)
	if err != nil || got != status || (body != "" && b != body) {
		e.t.Fatalf("GET %s = %d %q, %v; want %d %q", path, got, b, err, status, body)
	}
}

// settle waits until fetches in progress have linked their files.
func (e *pathEnv) settle() {
	deadline := time.Now().Add(5 * time.Second)
	for e.fetcher.Active() > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
}

func TestPathCacheImmutable(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	data := bytes.Repeat([]byte("jar!"), 50000)
	e.files.put("/com/acme/lib/1.0/lib-1.0.jar", data)
	s1 := sha1.Sum(data)
	e.expect["com/acme/lib/1.0/lib-1.0.jar"] = upstream.Expect{Size: -1, Sums: upstream.Sums{upstream.SHA1: s1[:]}}
	e.want("/remote/com/acme/lib/1.0/lib-1.0.jar", http.StatusOK, string(data))
	e.settle()
	rec, err := e.pc.Lookup(e.repos["remote"], "com/acme/lib/1.0/lib-1.0.jar")
	if err != nil || rec == nil {
		t.Fatalf("Lookup = %+v, %v", rec, err)
	}
	if rec.Digest != blob.FromBytes(data) || rec.Size != int64(len(data)) || rec.ContentType != "application/x-test" ||
		!bytes.Equal(rec.Sums[upstream.SHA1], s1[:]) || rec.Fetched.IsZero() {
		t.Errorf("record %+v", rec)
	}
	e.files.took()
	// Cached forever: served without asking the upstream, with ranges.
	e.want("/remote/com/acme/lib/1.0/lib-1.0.jar", http.StatusOK, string(data))
	if status, b, _ := e.fetch(http.MethodGet, "/remote/com/acme/lib/1.0/lib-1.0.jar", "Range", "bytes=0-3"); status != http.StatusPartialContent || b != "jar!" {
		t.Errorf("range request: %d %q", status, b)
	}
	if status, b, _ := e.fetch(http.MethodHead, "/remote/com/acme/lib/1.0/lib-1.0.jar"); status != http.StatusOK || b != "" {
		t.Errorf("HEAD: %d %q", status, b)
	}
	e.clock.Add(24 * time.Hour)
	e.files.set(func(u *fileUpstream) { u.down = true })
	e.want("/remote/com/acme/lib/1.0/lib-1.0.jar", http.StatusOK, string(data))
	if got := e.files.took(); len(got) != 0 {
		t.Errorf("requests for cached content: %q", got)
	}
	// A HEAD of uncached content asks the upstream with HEAD.
	e.files.set(func(u *fileUpstream) { u.down = false })
	e.files.put("/b.bin", []byte("bee"))
	if status, _, _ := e.fetch(http.MethodHead, "/remote/b.bin"); status != http.StatusOK {
		t.Errorf("HEAD of uncached content: %d", status)
	}
	if got := e.files.took(); len(got) != 1 || got[0] != "HEAD /b.bin" {
		t.Errorf("HEAD requests: %q", got)
	}
}

func TestPathCacheVerifierMismatch(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	data := bytes.Repeat([]byte("tgz!"), 100000)
	e.files.put("/pkg.tgz", data)
	s512 := sha512.Sum512(data)
	e.expect["pkg.tgz"] = upstream.Expect{Size: -1, Sums: upstream.Sums{upstream.SHA512: s512[:]}}
	e.files.set(func(u *fileUpstream) { u.corrupt = true })
	// A fetch that fails before the response starts is answered 502;
	// one that fails later is cut off.
	status, b, err := e.fetch(http.MethodGet, "/remote/pkg.tgz")
	if err == nil && status != http.StatusBadGateway || len(b) >= len(data) {
		t.Fatalf("corrupt content: %d, %d bytes, %v; want 502 or a cut-off response", status, len(b), err)
	}
	e.settle()
	if rec, _ := e.pc.Lookup(e.repos["remote"], "pkg.tgz"); rec != nil {
		t.Error("content that failed verification was cached")
	}
	bad := data[: len(data)-1 : len(data)-1]
	bad = append(bad, data[len(data)-1]^1)
	if _, err := e.blobs.Stat(ctx, blob.FromBytes(bad)); err == nil {
		t.Error("content that failed verification entered the blob store")
	}
	// Once the upstream serves the right bytes, they are cached.
	e.files.set(func(u *fileUpstream) { u.corrupt = false; u.down = false })
	e.clock.Add(upstream.DefaultOfflineFor)
	e.want("/remote/pkg.tgz", http.StatusOK, string(data))
}

func TestPathCacheNegative(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	for range 3 {
		e.want("/remote/missing-sources.jar", http.StatusNotFound, "")
	}
	if got := e.files.took(); len(got) != 1 {
		t.Errorf("upstream requests for a missing file within the window: %q, want one", got)
	}
	// Per repository.
	e.want("/other/missing-sources.jar", http.StatusNotFound, "")
	if got := e.files.took(); len(got) != 1 {
		t.Errorf("another repository's requests: %q, want one", got)
	}
	// After the window, the upstream is asked again.
	e.files.put("/missing-sources.jar", []byte("now here"))
	e.want("/remote/missing-sources.jar", http.StatusNotFound, "")
	e.clock.Add(upstream.DefaultNotFoundTTL)
	e.want("/remote/missing-sources.jar", http.StatusOK, "now here")
	// Documents are remembered too.
	e.want("/remote/maven-metadata-missing.xml", http.StatusNotFound, "")
	e.want("/remote/maven-metadata-missing.xml", http.StatusNotFound, "")
	if got := e.files.took(); len(got) != 2 {
		t.Errorf("requests: %q, want the file and one document request", got)
	}
	// 410 is 404, or 410 where the protocol distinguishes them.
	e.files.set(func(u *fileUpstream) { u.gone["/gone.zip"] = true })
	e.want("/remote/gone.zip", http.StatusNotFound, "")
	e.clock.Add(upstream.DefaultNotFoundTTL)
	e.want("/remote/gone.zip?keepgone", http.StatusGone, "")
	// A remembered 410 is still one.
	e.want("/remote/gone.zip?keepgone", http.StatusGone, "")
	e.want("/remote/gone.zip", http.StatusNotFound, "")
	e.files.set(func(u *fileUpstream) { u.gone["/gone.xml"] = true })
	e.want("/remote/gone.xml?keepgone", http.StatusGone, "")
	e.want("/remote/gone.xml?keepgone", http.StatusGone, "")
	if got := e.files.took(); len(got) != 3 {
		t.Errorf("requests: %q, want the file twice and the document once", got)
	}
}

func TestPathCacheMutable(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	e.files.put("/maven-metadata.xml", []byte("<metadata>1</metadata>"))
	e.want("/remote/maven-metadata.xml", http.StatusOK, "<metadata>1</metadata>")
	e.want("/remote/maven-metadata.xml?upper", http.StatusOK, "<METADATA>1</METADATA>")
	e.files.took()
	e.files.put("/maven-metadata.xml", []byte("<metadata>2</metadata>"))
	e.want("/remote/maven-metadata.xml", http.StatusOK, "<metadata>1</metadata>")
	if got := e.files.took(); len(got) != 0 {
		t.Errorf("requests within the window: %q", got)
	}
	e.clock.Add(docWindow)
	e.want("/remote/maven-metadata.xml", http.StatusOK, "<metadata>2</metadata>")
	// An unreachable upstream has the cached document served.
	e.clock.Add(docWindow)
	e.files.set(func(u *fileUpstream) { u.down = true })
	e.want("/remote/maven-metadata.xml", http.StatusOK, "<metadata>2</metadata>")
	e.files.set(func(u *fileUpstream) { u.down = false })
	e.clock.Add(upstream.DefaultOfflineFor)
	// One the upstream no longer has is answered 404.
	e.files.set(func(u *fileUpstream) { delete(u.files, "/maven-metadata.xml") })
	e.want("/remote/maven-metadata.xml", http.StatusNotFound, "")
}

func TestPathCachePassThrough(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	e.files.put("/passthru/search", []byte("results"))
	e.want("/remote/passthru/search", http.StatusOK, "results")
	e.want("/remote/passthru/search", http.StatusOK, "results")
	if got := e.files.took(); len(got) != 2 {
		t.Errorf("pass-through requests: %q, want two", got)
	}
	if rec, _ := e.pc.Lookup(e.repos["remote"], "passthru/search"); rec != nil {
		t.Error("pass-through content was cached")
	}
}

func TestPathCacheDiskPressure(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	data := []byte("big release artifact")
	e.files.put("/rel.tar", data)
	s1 := sha1.Sum(data)
	e.expect["rel.tar"] = upstream.Expect{Size: int64(len(data)), Sums: upstream.Sums{upstream.SHA1: s1[:]}}
	e.free.Store(0)
	e.clock.Add(time.Second)
	e.want("/remote/rel.tar", http.StatusOK, string(data))
	e.settle()
	if rec, _ := e.pc.Lookup(e.repos["remote"], "rel.tar"); rec != nil {
		t.Error("content was cached under disk pressure")
	}
	// Passed through content is still verified.
	e.files.set(func(u *fileUpstream) { u.corrupt = true })
	if _, b, err := e.fetch(http.MethodGet, "/remote/rel.tar"); err == nil || len(b) >= len(data) {
		t.Errorf("corrupt pass-through: %q, %v; want it cut off", b, err)
	}
	// Content with a check is held in memory and checked first.
	z := moduleZip(t, goModule.files)
	e.files.set(func(u *fileUpstream) { u.corrupt = false })
	e.files.put("/m.zip", z)
	e.expect["m.zip"] = upstream.Expect{Size: -1, Check: upstream.CheckGoZipH1(goModule.zipH1)}
	e.want("/remote/m.zip", http.StatusOK, string(z))
	e.expect["m.zip"] = upstream.Expect{Size: -1, Check: upstream.CheckGoZipH1(goModule.goModH1)}
	if status, _, _ := e.fetch(http.MethodGet, "/remote/m.zip"); status != http.StatusBadGateway {
		t.Errorf("a pass-through that fails its check: %d, want 502", status)
	}
	// With room again, it is cached.
	e.free.Store(1 << 40)
	e.clock.Add(time.Second)
	e.want("/remote/rel.tar", http.StatusOK, string(data))
	e.settle()
	if rec, _ := e.pc.Lookup(e.repos["remote"], "rel.tar"); rec == nil {
		t.Error("content was not cached with room again")
	}
}

func TestPathCacheSizeLimit(t *testing.T) {
	e := newPathEnv(t, 250, upstream.Policy{})
	for i := range 3 {
		e.files.put(fmt.Sprintf("/f%d", i), bytes.Repeat([]byte{'a' + byte(i)}, 100))
	}
	e.files.put("/huge", bytes.Repeat([]byte("h"), 300))
	// Larger than the limit: passed through.
	e.want("/remote/huge", http.StatusOK, strings.Repeat("h", 300))
	e.settle()
	if rec, _ := e.pc.Lookup(e.repos["remote"], "huge"); rec != nil {
		t.Error("content over the size limit was cached")
	}
	for i := range 2 {
		e.want(fmt.Sprintf("/remote/f%d", i), http.StatusOK, "")
		e.settle()
		e.clock.Add(time.Minute)
	}
	e.want("/remote/f0", http.StatusOK, "") // f0 is now the most recently pulled
	e.clock.Add(time.Minute)
	if err := e.pc.FlushPullTimes(ctx); err != nil {
		t.Fatal(err)
	}
	// A restart loads what is cached and the pull times.
	e.restartPath(250, upstream.Policy{})
	e.want("/remote/f2", http.StatusOK, "")
	e.settle()
	if err := e.pc.Evict(ctx); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{"f0": true, "f1": false, "f2": true} {
		if rec, _ := e.pc.Lookup(e.repos["remote"], path); (rec != nil) != want {
			t.Errorf("%s cached = %v after eviction, want %v", path, rec != nil, want)
		}
	}
}

func TestPathCacheOwnUpstreamOnly(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	theirs := newFileUpstream(t)
	theirs.put("/lib.jar", []byte("theirs"))
	e.files.put("/lib.jar", []byte("ours"))
	e.repos["other"].Client = newClient(t, theirs.URL, upstream.Options{})
	e.want("/remote/lib.jar", http.StatusOK, "ours")
	e.settle()
	// The other repository's upstream sent other bytes for the same
	// path: it serves those, never the blob cached for remote.
	e.files.took()
	rt := &upstream.Route{Kind: upstream.Immutable, Path: "lib.jar", URL: theirs.URL + "/lib.jar", Expect: upstream.Expect{Size: -1}}
	w := httptest.NewRecorder()
	e.pc.Serve(w, httptest.NewRequest(http.MethodGet, "/other/lib.jar", nil), e.repos["other"], rt, "tester")
	if w.Body.String() != "theirs" {
		t.Errorf("other repository served %q", w.Body)
	}
	// And a path its upstream does not have is not found, though remote
	// caches it.
	theirs.set(func(u *fileUpstream) { delete(u.files, "/lib.jar") })
	e.settle()
	rt.Path, rt.URL = "lib2.jar", theirs.URL+"/lib.jar"
	w = httptest.NewRecorder()
	e.pc.Serve(w, httptest.NewRequest(http.MethodGet, "/other/lib2.jar", nil), e.repos["other"], rt, "tester")
	if w.Code != http.StatusNotFound {
		t.Errorf("a path the upstream does not have: %d, want 404", w.Code)
	}
}

func TestPathCacheRedirectPolicy(t *testing.T) {
	cdn := newFileUpstream(t)
	cdn.put("/asset.tar.gz", []byte("release"))
	e := newPathEnv(t, 0, upstream.Policy{})
	e.files.set(func(u *fileUpstream) { u.redirect["/download/asset.tar.gz"] = cdn.URL + "/asset.tar.gz" })
	if status, _, _ := e.fetch(http.MethodGet, "/remote/download/asset.tar.gz"); status != http.StatusBadGateway {
		t.Errorf("a redirect to a host not allowed: %d, want 502", status)
	}
	if got := cdn.took(); len(got) != 0 {
		t.Errorf("the host not allowed got requests: %q", got)
	}
	e.restartPath(0, upstream.Policy{AllowHosts: []string{strings.TrimPrefix(cdn.URL, "http://")}})
	e.want("/remote/download/asset.tar.gz", http.StatusOK, "release")
}
