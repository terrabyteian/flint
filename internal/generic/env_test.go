package generic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// testAuth records authorization calls and allows them, unless deny
// names the repository.
type testAuth struct {
	mu    sync.Mutex
	calls []string
	deny  string
}

func (a *testAuth) record(w http.ResponseWriter, call, repo string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, call)
	if repo == a.deny {
		w.Header().Set("WWW-Authenticate", `Basic realm="flint"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *testAuth) Authorize(w http.ResponseWriter, _ *http.Request, repo string, actions ...string) bool {
	return a.record(w, repo+":"+strings.Join(actions, ","), repo)
}

func (a *testAuth) AuthorizeVirtual(w http.ResponseWriter, _ *http.Request, virtual, publishTo string, actions ...string) bool {
	return a.record(w, "virtual "+virtual+">"+publishTo+":"+strings.Join(actions, ","), virtual)
}

func (a *testAuth) reset() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.calls
	a.calls = nil
	return c
}

// origin is a fake upstream web server: files by path, with ETags and
// conditional requests, and request counts.
type origin struct {
	*httptest.Server
	mu       sync.Mutex
	files    map[string][]byte
	redirect map[string]string // path to the URL it redirects to
	hits     map[string]int
	down     atomic.Bool // answer 503 to everything
}

func newOrigin(t *testing.T) *origin {
	o := &origin{files: map[string][]byte{}, redirect: map[string]string{}, hits: map[string]int{}}
	o.Server = httptest.NewServer(http.HandlerFunc(o.serve))
	t.Cleanup(o.Close)
	return o
}

func (o *origin) serve(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	o.hits[r.URL.Path]++
	b, ok := o.files[r.URL.Path]
	to := o.redirect[r.URL.Path]
	o.mu.Unlock()
	switch {
	case o.down.Load():
		w.WriteHeader(http.StatusServiceUnavailable)
	case to != "":
		http.Redirect(w, r, to, http.StatusFound)
	case !ok:
		http.NotFound(w, r)
	default:
		sum := sha256.Sum256(b)
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
		w.Header().Set("Content-Type", "application/x-test")
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(b))
	}
}

func (o *origin) set(path string, b []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.files[path] = b
}

func (o *origin) remove(path string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.files, path)
}

func (o *origin) count(path string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hits[path]
}

// env is a Handler over in-memory stores with these repositories:
//
//	local     hosted
//	scratch   hosted, generic.allowOverwrite
//	team      hosted
//	remote    proxy of the fake upstream up, under /dl/; revalidated
//	releases  proxy of up, under /dl/, generic.immutable
//	elsewhere proxy of up, under /dl/, generic.immutable, allowing the host of other
//	all       virtual: local, remote
//	open      virtual: local, remote, without dependency-confusion protection
//	filtered  virtual: local for team-a/* only, team, remote except internal/*; publishes to team
type env struct {
	t       *testing.T
	fs      *fsys.Mem
	meta    meta.Store
	blobs   blob.Store
	auth    *testAuth
	up      *origin
	other   *origin
	h       *Handler
	reg     *metrics.Registry
	fetcher *upstream.Fetcher
	srv     http.Handler

	mu    sync.Mutex
	clock time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, fs: fsys.NewMem(), auth: &testAuth{}, up: newOrigin(t), other: newOrigin(t),
		clock: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
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
	e.restart()
	return e
}

// restart builds a new Handler over the same stores, as a restart would.
func (e *env) restart() {
	e.t.Helper()
	off := false
	otherHost, _ := url.Parse(e.other.URL)
	proxy := func(immutable bool, allow ...string) (*config.Proxy, *config.Generic) {
		return &config.Proxy{URL: e.up.URL + "/dl", RevalidateAfter: config.Duration{Duration: testWindow}, AllowHosts: allow},
			&config.Generic{Immutable: immutable}
	}
	remote, remoteG := proxy(false)
	releases, releasesG := proxy(true)
	elsewhere, elsewhereG := proxy(true, otherHost.Host)
	repos := []config.Repository{
		{Name: "local", Format: config.FormatGeneric, Type: config.TypeHosted},
		{Name: "scratch", Format: config.FormatGeneric, Type: config.TypeHosted, Generic: &config.Generic{AllowOverwrite: true}},
		{Name: "team", Format: config.FormatGeneric, Type: config.TypeHosted, AnonymousPull: true},
		{Name: "remote", Format: config.FormatGeneric, Type: config.TypeProxy, Proxy: remote, Generic: remoteG},
		{Name: "releases", Format: config.FormatGeneric, Type: config.TypeProxy, Proxy: releases, Generic: releasesG},
		{Name: "elsewhere", Format: config.FormatGeneric, Type: config.TypeProxy, Proxy: elsewhere, Generic: elsewhereG},
		{Name: "all", Format: config.FormatGeneric, Type: config.TypeVirtual, Virtual: &config.Virtual{Members: config.Members("local", "remote")}},
		{Name: "open", Format: config.FormatGeneric, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("local", "remote"), DependencyConfusionProtection: &off}},
		{Name: "filtered", Format: config.FormatGeneric, Type: config.TypeVirtual, Virtual: &config.Virtual{PublishTo: "team",
			Members: []config.VirtualMember{{Name: "local", Include: []string{"team-a/*"}}, {Name: "team"},
				{Name: "remote", Exclude: []string{"internal/*"}}}}},
		{Name: "pypi", Format: config.FormatPyPI, Type: config.TypeHosted},
	}
	e.reg = metrics.NewRegistry()
	e.fetcher = upstream.NewFetcher(e.blobs, 0)
	h, err := New(Options{Meta: e.meta, Blobs: e.blobs, Repositories: repos, Authorizer: e.auth, Logger: quiet,
		Metrics: e.reg, Now: e.now, Fetcher: e.fetcher, Upstream: upstream.Options{Attempts: 2, Backoff: time.Millisecond}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.h = h
	mux := http.NewServeMux()
	h.Register(mux)
	e.srv = mux
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

// do serves a request; hdr holds header name and value pairs.
func (e *env) do(method, path string, body []byte, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rd)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	return w
}

// expect serves a request and checks its status.
func (e *env) expect(status int, method, path string, body []byte, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	w := e.do(method, path, body, hdr...)
	if w.Code != status {
		e.t.Fatalf("%s %s: %d %q, want %d", method, path, w.Code, w.Body.String(), status)
	}
	return w
}

// put uploads body to a path and checks the status.
func (e *env) put(status int, path string, body []byte, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.expect(status, "PUT", path, body, hdr...)
}

// get downloads a path, checks the status, and returns the body.
func (e *env) get(status int, path string, hdr ...string) string {
	e.t.Helper()
	return e.expect(status, "GET", path, nil, hdr...).Body.String()
}

// list fetches a listing as JSON.
func (e *env) list(path string) listing {
	e.t.Helper()
	w := e.expect(http.StatusOK, "GET", path, nil, "Accept", "application/json")
	var l listing
	if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
		e.t.Fatalf("listing %s: %v: %s", path, err, w.Body)
	}
	return l
}

func names(l listing) string {
	var out []string
	for _, en := range l.Entries {
		out = append(out, en.Name)
	}
	return strings.Join(out, " ")
}

// settle waits until fetches in progress have cached their files.
func (e *env) settle() {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.fetcher.Active() > 0 {
		if time.Now().After(deadline) {
			e.t.Fatal("fetches did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *env) record(repo, path string) *fileRecord {
	e.t.Helper()
	f, err := e.h.lookup(repo, path)
	if err != nil {
		e.t.Fatal(err)
	}
	return f
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func digestOf(b []byte) blob.Digest { return blob.FromBytes(b) }

// metric returns the value of a sample line of the exposition, or "".
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

func content(n int) []byte { return []byte(fmt.Sprintf("content %d\n", n)) }
