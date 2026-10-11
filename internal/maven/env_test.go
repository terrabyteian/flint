package maven

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/upstream"
)

var quiet = slog.New(slog.DiscardHandler)

const testWindow = time.Minute

// testAuth records authorization checks, as "<repo>:<actions>", and
// allows them unless deny is set, when it answers 401 with a Basic
// challenge as flint's own Authorizer does.
type testAuth struct {
	mu    sync.Mutex
	calls []string
	deny  bool
}

func (a *testAuth) check(w http.ResponseWriter, call string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, call)
	if a.deny {
		w.Header().Set("WWW-Authenticate", `Basic realm="flint"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *testAuth) Authorize(w http.ResponseWriter, _ *http.Request, repo string, actions ...string) bool {
	return a.check(w, repo+":"+strings.Join(actions, ","))
}

func (a *testAuth) AuthorizeVirtual(w http.ResponseWriter, _ *http.Request, virtual, publishTo string, actions ...string) bool {
	return a.check(w, virtual+">"+publishTo+":"+strings.Join(actions, ","))
}

func (a *testAuth) reset() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.calls
	a.calls = nil
	return c
}

// fakeRepo is a fake upstream Maven repository. It serves files by
// path, with sidecars computed from their content, and announces a
// file's sha1 in X-Checksum-SHA1 when headers is set. It can serve
// corrupt content, omit sidecars, or be down.
type fakeRepo struct {
	*httptest.Server

	mu        sync.Mutex
	files     map[string][]byte
	headers   bool
	noSidecar map[string]bool // algorithms whose sidecars are not served
	badSum    bool            // announced checksums do not match
	down      bool
	requests  []string
}

func newFakeRepo(t *testing.T, headers bool) *fakeRepo {
	u := &fakeRepo{files: map[string][]byte{}, headers: headers, noSidecar: map[string]bool{}}
	u.Server = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.Close)
	return u
}

func (u *fakeRepo) put(path string, b []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.files[path] = b
}

func (u *fakeRepo) set(f func(u *fakeRepo)) {
	u.mu.Lock()
	defer u.mu.Unlock()
	f(u)
}

// took returns the requests since the last call, as "<method> <path>".
func (u *fakeRepo) took() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	r := u.requests
	u.requests = nil
	return r
}

func hexSum(alg string, b []byte) string {
	switch alg {
	case algMD5:
		s := md5.Sum(b)
		return hex.EncodeToString(s[:])
	case algSHA1:
		s := sha1.Sum(b)
		return hex.EncodeToString(s[:])
	case algSHA256:
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:])
	}
	s := sha512.Sum512(b)
	return hex.EncodeToString(s[:])
}

func (u *fakeRepo) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests = append(u.requests, r.Method+" "+r.URL.Path)
	if u.down {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	p := r.URL.Path
	if b, ok := u.files[p]; ok {
		if u.headers {
			sum := hexSum(algSHA1, b)
			if u.badSum {
				sum = strings.Repeat("0", 40)
			}
			w.Header().Set("X-Checksum-SHA1", sum)
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Header().Set("ETag", `"`+hexSum(algMD5, b)+`"`)
		if strings.HasSuffix(p, ".xml") {
			w.Header().Set("Content-Type", "text/xml")
		}
		if r.Method != http.MethodHead {
			w.Write(b)
		}
		return
	}
	for _, alg := range sidecarAlgs {
		if target, ok := strings.CutSuffix(p, "."+alg); ok {
			if b, ok := u.files[target]; ok && !u.noSidecar[alg] {
				sum := hexSum(alg, b)
				if u.badSum {
					sum = strings.Repeat("0", len(sum))
				}
				io.WriteString(w, sum+"  "+target[strings.LastIndexByte(target, '/')+1:]+"\n")
				return
			}
		}
	}
	http.NotFound(w, r)
}

// env is a Handler over in-memory stores, served by a real HTTP server
// so aborted responses reach clients as such, with these repositories:
//
//	releases   hosted, release versions
//	snapshots  hosted, snapshot versions
//	mixed      hosted, both
//	central    proxy of up, which announces checksums in headers
//	plain      proxy of plain, which serves only sidecars
//	small      proxy of up with a size limit
//	all        virtual: releases, snapshots, central except com.acme.*; publishes to releases
//	open       virtual: releases, central, without dependency-confusion protection
//	both       virtual: central, plain
//	scoped     virtual: mixed for com.acme.* only, central; publishes to mixed
type env struct {
	t       *testing.T
	fs      *fsys.Mem
	meta    meta.Store
	blobs   blob.Store
	auth    *testAuth
	up      *fakeRepo
	plain   *fakeRepo
	h       *Handler
	reg     *metrics.Registry
	srv     *httptest.Server
	fetcher *upstream.Fetcher
	free    atomic.Uint64
	cur     atomic.Pointer[Handler]

	mu    sync.Mutex
	clock time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, fs: fsys.NewMem(), auth: &testAuth{}, up: newFakeRepo(t, true), plain: newFakeRepo(t, false),
		clock: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	e.free.Store(100 << 30)
	ms, err := meta.Open("/data/meta", meta.Options{FS: e.fs, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	bs, err := blob.NewFS("/data", blob.Options{FS: e.fs})
	if err != nil {
		t.Fatal(err)
	}
	e.meta, e.blobs = ms, bs
	e.fetcher = upstream.NewFetcher(bs, 0)
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.cur.Load().ServeHTTP(w, r) }))
	t.Cleanup(e.srv.Close)
	e.restart()
	return e
}

func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clock = e.clock.Add(d)
}

// restart builds a new Handler over the same stores, as a restart would.
func (e *env) restart() {
	e.t.Helper()
	off := false
	proxy := func(url string, limit int64) *config.Proxy {
		return &config.Proxy{URL: url, RevalidateAfter: config.Duration{Duration: testWindow}, SizeLimit: config.ByteSize{Bytes: limit}}
	}
	repos := []config.Repository{
		{Name: "releases", Format: config.FormatMaven, Type: config.TypeHosted},
		{Name: "snapshots", Format: config.FormatMaven, Type: config.TypeHosted, Maven: &config.Maven{VersionPolicy: config.VersionPolicySnapshot}},
		{Name: "mixed", Format: config.FormatMaven, Type: config.TypeHosted, Maven: &config.Maven{VersionPolicy: config.VersionPolicyMixed}},
		{Name: "central", Format: config.FormatMaven, Type: config.TypeProxy, Proxy: proxy(e.up.URL+"/maven2", 0)},
		{Name: "plain", Format: config.FormatMaven, Type: config.TypeProxy, Proxy: proxy(e.plain.URL+"/repo/", 0)},
		{Name: "small", Format: config.FormatMaven, Type: config.TypeProxy, Proxy: proxy(e.up.URL+"/maven2", 2500)},
		{Name: "all", Format: config.FormatMaven, Type: config.TypeVirtual, Virtual: &config.Virtual{PublishTo: "releases",
			Members: []config.VirtualMember{{Name: "releases"}, {Name: "snapshots"}, {Name: "central", Exclude: []string{"com.acme.*"}}}}},
		{Name: "open", Format: config.FormatMaven, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("releases", "central"), DependencyConfusionProtection: &off}},
		{Name: "both", Format: config.FormatMaven, Type: config.TypeVirtual, Virtual: &config.Virtual{Members: config.Members("central", "plain")}},
		{Name: "scoped", Format: config.FormatMaven, Type: config.TypeVirtual, Virtual: &config.Virtual{PublishTo: "mixed",
			Members: []config.VirtualMember{{Name: "mixed", Include: []string{"com.acme.*"}}, {Name: "central"}}}},
		{Name: "pypi", Format: config.FormatPyPI, Type: config.TypeHosted},
	}
	space := upstream.NewSpace(upstream.SpaceOptions{
		Path:    "/data",
		Statfs:  func(string) (uint64, uint64, error) { return e.free.Load(), 1 << 40, nil },
		MinFree: func(uint64) uint64 { return 1 << 30 },
		Now:     e.now,
		Logger:  quiet,
	})
	e.reg = metrics.NewRegistry()
	h, err := New(Options{Meta: e.meta, Blobs: e.blobs, Repositories: repos, Authorizer: e.auth, Logger: quiet,
		Metrics: e.reg, Now: e.now, Space: space, Fetcher: e.fetcher,
		Upstream: upstream.Options{Attempts: 2, Backoff: time.Millisecond, Now: e.now}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.h = h
	e.cur.Store(h)
}

// response is an answer from the server.
type response struct {
	code   int
	header http.Header
	body   string
	err    error // a body cut off by the server
}

// do sends a request; hdr holds header names and values.
func (e *env) do(method, path string, body []byte, hdr ...string) response {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return response{err: err}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return response{code: resp.StatusCode, header: resp.Header, body: string(b), err: err}
}

// want sends a request and fails unless it is answered with status, and
// body unless it is empty.
func (e *env) want(method, path string, body []byte, status int, wantBody string) response {
	e.t.Helper()
	r := e.do(method, path, body)
	if r.err != nil || r.code != status || wantBody != "" && r.body != wantBody {
		e.t.Fatalf("%s %s = %d %.300q, %v; want %d %.300q", method, path, r.code, r.body, r.err, status, wantBody)
	}
	return r
}

func (e *env) get(path string, status int) response {
	e.t.Helper()
	return e.want(http.MethodGet, path, nil, status, "")
}

func (e *env) put(path string, body []byte, status int) response {
	e.t.Helper()
	return e.want(http.MethodPut, path, body, status, "")
}

// deploy uploads a file and its sidecars, as Maven does.
func (e *env) deploy(repo, path string, body []byte) {
	e.t.Helper()
	e.put("/maven/"+repo+"/"+path, body, http.StatusCreated)
	for _, alg := range []string{algMD5, algSHA1} {
		e.put("/maven/"+repo+"/"+path+"."+alg, []byte(hexSum(alg, body)), http.StatusCreated)
	}
}

// settle waits until fetches in progress have linked their files.
func (e *env) settle() {
	deadline := time.Now().Add(5 * time.Second)
	for e.fetcher.Active() > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
}

// metric returns a metric sample's value, or "".
func (e *env) metric(sample string) string {
	var b bytes.Buffer
	e.reg.WriteTo(&b)
	for line := range strings.SplitSeq(b.String(), "\n") {
		if v, ok := strings.CutPrefix(line, sample+" "); ok {
			return v
		}
	}
	return ""
}

// artifact is the path of an artifact file.
func artifact(group, id, version, file string) string {
	return strings.ReplaceAll(group, ".", "/") + "/" + id + "/" + version + "/" + file
}
