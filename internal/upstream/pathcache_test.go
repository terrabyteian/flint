package upstream_test

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/upstream"
)

// fileUpstream is a fake path-addressed upstream: it serves files by
// path, with the headers set for them, can corrupt them, answer 410, or
// redirect to another server.
type fileUpstream struct {
	*httptest.Server

	mu       sync.Mutex
	files    map[string][]byte
	headers  map[string]http.Header
	gone     map[string]bool
	redirect map[string]string
	corrupt  bool
	down     bool
	requests []string
}

func newFileUpstream(t *testing.T) *fileUpstream {
	u := &fileUpstream{files: map[string][]byte{}, headers: map[string]http.Header{}, gone: map[string]bool{},
		redirect: map[string]string{}}
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
	hdr := u.headers[r.URL.Path]
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
		for k, v := range hdr {
			w.Header()[k] = v
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

// TestPathCacheFromResponse checks that digests derived from the
// upstream's response are verified like any other, and that content the
// upstream offers nothing to verify against is passed through without
// being cached.
func TestPathCacheFromResponse(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	// The test's verifier expects the sha1 the upstream announces in
	// X-Checksum-SHA1, and refuses content without one.
	fromHeader := func(_ context.Context, h http.Header) (upstream.Sums, error) {
		v := h.Get("X-Checksum-SHA1")
		if v == "" {
			return nil, upstream.ErrUnverifiable
		}
		sum, err := hex.DecodeString(v)
		if err != nil {
			return nil, errors.New("a malformed checksum header")
		}
		return upstream.Sums{upstream.SHA1: sum}, nil
	}
	data := bytes.Repeat([]byte("pom!"), 30000)
	s1 := sha1.Sum(data)
	for _, p := range []string{"good.pom", "bad.pom", "none.pom", "malformed.pom"} {
		e.files.put("/"+p, data)
		e.expect[p] = upstream.Expect{Size: -1, FromResponse: fromHeader}
	}
	// none.pom's verifier asks for a sidecar first, as a Maven proxy's
	// does when the upstream sends no checksum header.
	e.expect["none.pom"] = upstream.Expect{Size: -1, FromResponse: func(ctx context.Context, h http.Header) (upstream.Sums, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.files.URL+"/none.pom.sha1", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		return fromHeader(ctx, h)
	}}
	e.files.headers["/good.pom"] = http.Header{"X-Checksum-Sha1": {hex.EncodeToString(s1[:])}}
	e.files.headers["/bad.pom"] = http.Header{"X-Checksum-Sha1": {strings.Repeat("0", 40)}}
	e.files.headers["/malformed.pom"] = http.Header{"X-Checksum-Sha1": {"zz"}}

	e.want("/remote/good.pom", http.StatusOK, string(data))
	e.settle()
	if rec, _ := e.pc.Lookup(e.repos["remote"], "good.pom"); rec == nil || !bytes.Equal(rec.Sums[upstream.SHA1], s1[:]) {
		t.Errorf("verified content: record %+v", rec)
	}

	if _, b, err := e.fetch(http.MethodGet, "/remote/bad.pom"); err == nil || len(b) >= len(data) {
		t.Errorf("content that does not match its announced digest: %d bytes, %v; want a cut-off response", len(b), err)
	}
	if status, _, _ := e.fetch(http.MethodGet, "/remote/malformed.pom"); status != http.StatusBadGateway {
		t.Errorf("a failing FromResponse: %d, want 502", status)
	}
	e.files.took()
	e.want("/remote/none.pom", http.StatusOK, string(data))
	e.settle()
	if got := e.files.took(); !slices.Equal(got, []string{"GET /none.pom", "GET /none.pom.sha1", "GET /none.pom"}) {
		t.Errorf("upstream requests for unverifiable content %q; want its sidecar asked for once", got)
	}
	for _, p := range []string{"bad.pom", "none.pom", "malformed.pom"} {
		if rec, _ := e.pc.Lookup(e.repos["remote"], p); rec != nil {
			t.Errorf("%s was cached", p)
		}
	}

	// Passed through under disk pressure, content is verified against
	// the derived digests too.
	e.free.Store(0)
	e.clock.Add(time.Second)
	if _, b, err := e.fetch(http.MethodGet, "/remote/bad.pom"); err == nil || len(b) >= len(data) {
		t.Errorf("a pass-through that does not match its announced digest: %d bytes, %v; want it cut off", len(b), err)
	}
	e.files.took()
	e.want("/remote/none.pom", http.StatusOK, string(data))
	if got := e.files.took(); !slices.Equal(got, []string{"GET /none.pom", "GET /none.pom.sha1"}) {
		t.Errorf("upstream requests for unverifiable content passed through %q", got)
	}
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

func TestPathCacheRead(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	rp := e.repos["remote"]
	route := func(path string) *upstream.Route {
		return &upstream.Route{Kind: upstream.Immutable, Path: path, URL: e.files.URL + "/" + path, Expect: upstream.Expect{Size: -1}}
	}
	e.files.put("/record", []byte("signed record"))
	b, result, err := e.pc.Read(ctx, rp, route("record"), "tester", 100)
	if err != nil || string(b) != "signed record" || result != upstream.ResultFetched {
		t.Fatalf("Read = %q, %s, %v", b, result, err)
	}
	e.settle()
	if rec, _ := e.pc.Lookup(rp, "record"); rec == nil {
		t.Error("Read did not cache the content")
	}
	e.files.took()
	b, result, err = e.pc.Read(ctx, rp, route("record"), "tester", 100)
	if err != nil || string(b) != "signed record" || result != upstream.ResultHit {
		t.Errorf("cached Read = %q, %s, %v", b, result, err)
	}
	if got := e.files.took(); len(got) != 0 {
		t.Errorf("requests for cached content: %q", got)
	}
	// It is served as Serve caches it, the other way round too.
	e.want("/remote/record", http.StatusOK, "signed record")
	e.files.put("/served", []byte("served first"))
	e.want("/remote/served", http.StatusOK, "served first")
	e.settle()
	if b, result, err := e.pc.Read(ctx, rp, route("served"), "tester", 100); err != nil || string(b) != "served first" || result != upstream.ResultHit {
		t.Errorf("Read of served content = %q, %s, %v", b, result, err)
	}
	// Larger than the limit, cached or not.
	if _, _, err := e.pc.Read(ctx, rp, route("record"), "tester", 5); !errors.Is(err, upstream.ErrTooLarge) {
		t.Errorf("cached content over the limit: %v", err)
	}
	e.files.put("/big", bytes.Repeat([]byte("b"), 1000))
	if _, _, err := e.pc.Read(ctx, rp, route("big"), "tester", 10); !errors.Is(err, upstream.ErrTooLarge) {
		t.Errorf("content over the limit: %v", err)
	}
	// Not found, and remembered.
	e.files.took()
	if _, _, err := e.pc.Read(ctx, rp, route("missing"), "tester", 100); !errors.Is(err, upstream.ErrNotFound) {
		t.Errorf("missing content: %v", err)
	}
	e.want("/remote/missing", http.StatusNotFound, "")
	if got := e.files.took(); len(got) != 1 {
		t.Errorf("requests: %q, want one for the missing content", got)
	}
	// Pass-through content is fetched every time, and never cached.
	e.files.put("/record", []byte("changed record"))
	pass := route("record")
	pass.Kind = upstream.PassThrough
	if b, result, err := e.pc.Read(ctx, rp, pass, "tester", 100); err != nil || string(b) != "changed record" || result != upstream.ResultPassthrough {
		t.Errorf("pass-through Read = %q, %s, %v", b, result, err)
	}
	e.files.put("/fresh", []byte("fresh"))
	pass = route("fresh")
	pass.Kind = upstream.PassThrough
	if b, _, err := e.pc.Read(ctx, rp, pass, "tester", 100); err != nil || string(b) != "fresh" {
		t.Errorf("pass-through Read = %q, %v", b, err)
	}
	e.settle()
	if rec, _ := e.pc.Lookup(rp, "fresh"); rec != nil {
		t.Error("pass-through content was cached")
	}
	// Verified, with the check, before it is returned or cached.
	z := moduleZip(t, goModule.files)
	e.files.put("/m.zip", z)
	bad := route("m.zip")
	bad.Expect.Check = upstream.CheckGoZipH1(goModule.goModH1)
	if _, _, err := e.pc.Read(ctx, rp, bad, "tester", 1<<20); !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Errorf("content failing its check: %v", err)
	}
	if rec, _ := e.pc.Lookup(rp, "m.zip"); rec != nil {
		t.Error("content failing its check was cached")
	}
	// Under disk pressure it is read through, still checked.
	e.free.Store(0)
	e.clock.Add(time.Second)
	good := route("m.zip")
	good.Expect.Check = upstream.CheckGoZipH1(goModule.zipH1)
	if b, result, err := e.pc.Read(ctx, rp, good, "tester", 1<<20); err != nil || !bytes.Equal(b, z) || result != upstream.ResultPassthrough {
		t.Errorf("Read under disk pressure = %d bytes, %s, %v", len(b), result, err)
	}
	if _, _, err := e.pc.Read(ctx, rp, bad, "tester", 1<<20); !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Errorf("content failing its check under disk pressure: %v", err)
	}
	if rec, _ := e.pc.Lookup(rp, "m.zip"); rec != nil {
		t.Error("content was cached under disk pressure")
	}
}

func TestPathCacheDoc(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	rp := e.repos["remote"]
	var validated []string
	route := &upstream.Route{Kind: upstream.Mutable, Path: "@latest", URL: e.files.URL + "/@latest", ContentType: "application/json",
		Validate: func(ctx context.Context, d *upstream.Doc) error {
			b := e.read(d)
			validated = append(validated, b)
			if !strings.HasPrefix(b, "v") {
				return errors.New("not a version")
			}
			return nil
		},
		Also: func(ctx context.Context, d *upstream.Doc) string { return e.read(d) + ".info" }}
	e.files.put("/@latest", []byte("v1"))
	d, err := e.pc.Doc(ctx, rp, route, "tester")
	if err != nil || e.read(d) != "v1" || d.Result != upstream.ResultFetched {
		t.Fatalf("Doc = %+v, %v", d, err)
	}
	// The document is cached as the immutable content Also names.
	rec, err := e.pc.Lookup(rp, "v1.info")
	if err != nil || rec == nil || rec.Digest != d.Digest || rec.ContentType != "application/json" {
		t.Fatalf("v1.info = %+v, %v", rec, err)
	}
	e.want("/remote/v1.info", http.StatusOK, "v1")
	// A document that fails validation is not cached or served: the
	// cached copy is.
	e.clock.Add(docWindow)
	e.files.put("/@latest", []byte("garbage"))
	if d, err := e.pc.Doc(ctx, rp, route, "tester"); err != nil || e.read(d) != "v1" || d.Result != upstream.ResultStale {
		t.Errorf("Doc after an invalid document = %+v, %v", d, err)
	}
	if rec, _ := e.pc.Lookup(rp, "garbage.info"); rec != nil {
		t.Error("an invalid document was cached as immutable content")
	}
	e.files.put("/@latest", []byte("v2"))
	e.clock.Add(upstream.DefaultOfflineFor)
	if d, err := e.pc.Doc(ctx, rp, route, "tester"); err != nil || e.read(d) != "v2" {
		t.Errorf("Doc = %+v, %v", d, err)
	}
	if rec, _ := e.pc.Lookup(rp, "v2.info"); rec == nil {
		t.Error("v2.info was not cached")
	}
	if !slices.Equal(validated, []string{"v1", "garbage", "v2"}) {
		t.Errorf("validated %q", validated)
	}
	// Something cached already is not replaced.
	e.files.put("/v3.info", []byte("the upstream's v3.info"))
	e.want("/remote/v3.info", http.StatusOK, "the upstream's v3.info")
	e.settle()
	e.files.put("/@latest", []byte("v3"))
	e.clock.Add(docWindow)
	if _, err := e.pc.Doc(ctx, rp, route, "tester"); err != nil {
		t.Fatal(err)
	}
	e.want("/remote/v3.info", http.StatusOK, "the upstream's v3.info")
	// Not found, and remembered.
	route.Path, route.URL = "missing", e.files.URL+"/missing"
	if _, err := e.pc.Doc(ctx, rp, route, "tester"); !errors.Is(err, upstream.ErrNotFound) {
		t.Errorf("a missing document: %v", err)
	}
	e.files.took()
	if _, err := e.pc.Doc(ctx, rp, route, "tester"); !errors.Is(err, upstream.ErrNotFound) {
		t.Errorf("a missing document: %v", err)
	}
	if got := e.files.took(); len(got) != 0 {
		t.Errorf("requests for a remembered missing document: %q", got)
	}
}

// read returns a document's content.
func (e *pathEnv) read(d *upstream.Doc) string {
	e.t.Helper()
	f, err := e.c.Open(ctx, d)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func TestPathCacheRouteClient(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	rp := e.repos["remote"]
	second := newFileUpstream(t)
	client := newClient(t, second.URL, upstream.Options{Now: e.clock.Now})
	second.put("/tile/0", []byte("tile"))
	second.put("/latest", []byte("tree 1"))
	serve := func(rt *upstream.Route) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		e.pc.Serve(w, httptest.NewRequest(http.MethodGet, "/remote/"+rt.Path, nil), rp, rt, "tester")
		return w
	}
	tile := &upstream.Route{Kind: upstream.Immutable, Path: "sumdb/tile/0", URL: second.URL + "/tile/0", Expect: upstream.Expect{Size: -1}, Client: client}
	if w := serve(tile); w.Code != http.StatusOK || w.Body.String() != "tile" {
		t.Fatalf("immutable content of the second upstream: %d %q", w.Code, w.Body)
	}
	latest := &upstream.Route{Kind: upstream.Mutable, Path: "sumdb/latest", URL: second.URL + "/latest", Client: client, Revalidate: time.Second}
	if w := serve(latest); w.Code != http.StatusOK || w.Body.String() != "tree 1" {
		t.Fatalf("a document of the second upstream: %d %q", w.Code, w.Body)
	}
	if got := e.files.took(); len(got) != 0 {
		t.Errorf("the repository's upstream got requests: %q", got)
	}
	// The route's revalidation window applies, not the repository's.
	second.put("/latest", []byte("tree 2"))
	e.clock.Add(time.Second)
	if w := serve(latest); w.Body.String() != "tree 2" {
		t.Errorf("after the route's window: %q", w.Body)
	}
	// The second upstream being down does not mark the first offline.
	second.set(func(u *fileUpstream) { u.down = true })
	second.put("/tile/1", []byte("tile 1"))
	tile.Path, tile.URL = "sumdb/tile/1", second.URL+"/tile/1"
	if w := serve(tile); w.Code != http.StatusServiceUnavailable {
		t.Errorf("immutable content of an unreachable upstream: %d", w.Code)
	}
	if !client.Offline() || rp.Client.Offline() {
		t.Errorf("offline: the route's client %v, the repository's %v", client.Offline(), rp.Client.Offline())
	}
}

func TestPathCacheCheck(t *testing.T) {
	e := newPathEnv(t, 0, upstream.Policy{})
	z := moduleZip(t, goModule.files)
	e.files.put("/m.zip", z)
	// Content with a check is sent only once it passed, so a failure is
	// an error status, not a response cut off.
	e.expect["m.zip"] = upstream.Expect{Size: -1, Check: upstream.CheckGoZipH1(goModule.goModH1)}
	if status, _, err := e.fetch(http.MethodGet, "/remote/m.zip"); err != nil || status != http.StatusBadGateway {
		t.Errorf("content failing its check: %d, %v; want 502", status, err)
	}
	e.settle()
	if rec, _ := e.pc.Lookup(e.repos["remote"], "m.zip"); rec != nil {
		t.Error("content failing its check was cached")
	}
	e.expect["m.zip"] = upstream.Expect{Size: -1, Check: upstream.CheckGoZipH1(goModule.zipH1)}
	e.want("/remote/m.zip", http.StatusOK, string(z))
	e.settle()
	if rec, _ := e.pc.Lookup(e.repos["remote"], "m.zip"); rec == nil {
		t.Error("content passing its check was not cached")
	}
}
