package cargo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

// testAuth records authorization calls and answers with status, by
// default 200: "repo:actions", or "virtual>publishTo:actions".
type testAuth struct {
	mu     sync.Mutex
	calls  []string
	status int
}

func (a *testAuth) answer(w http.ResponseWriter, call string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, call)
	if a.status != 0 && a.status != http.StatusOK {
		writeError(w, a.status, "refused")
		return false
	}
	return true
}

func (a *testAuth) Authorize(w http.ResponseWriter, _ *http.Request, repo string, actions ...string) bool {
	return a.answer(w, repo+":"+strings.Join(actions, ","))
}

func (a *testAuth) AuthorizeVirtual(w http.ResponseWriter, _ *http.Request, virtual, publishTo string, actions ...string) bool {
	return a.answer(w, virtual+">"+publishTo+":"+strings.Join(actions, ","))
}

func (a *testAuth) reset() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.calls
	a.calls = nil
	return c
}

// env is a Handler over in-memory stores with these repositories:
//
//	local     hosted
//	team      hosted, anonymous pull
//	remote    proxy of the fake upstream index up
//	small     proxy of up with a size limit
//	all       virtual: local, remote; publishes to local
//	open      virtual: local, remote, without dependency-confusion protection, with anonymous pull
//	filtered  virtual: local for acme-* only, team, remote except acme-*; publishes to team
//	plain     virtual: local, team, without publishTo
//	scoped    virtual: local for acme-* only, remote; publishes to local
type env struct {
	t     *testing.T
	fs    *fsys.Mem
	meta  meta.Store
	blobs blob.Store
	auth  *testAuth
	up    *upIndex
	h     *Handler
	reg   *metrics.Registry
	srv   http.Handler

	mu    sync.Mutex
	clock time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, fs: fsys.NewMem(), auth: &testAuth{}, up: newUpIndex(t), clock: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
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
	repos := []config.Repository{
		{Name: "local", Format: config.FormatCargo, Type: config.TypeHosted},
		{Name: "team", Format: config.FormatCargo, Type: config.TypeHosted, AnonymousPull: true},
		{Name: "remote", Format: config.FormatCargo, Type: config.TypeProxy,
			Proxy: &config.Proxy{URL: "sparse+" + e.up.URL + "/index/", RevalidateAfter: config.Duration{Duration: testWindow}}},
		{Name: "small", Format: config.FormatCargo, Type: config.TypeProxy,
			Proxy: &config.Proxy{URL: e.up.URL + "/index", RevalidateAfter: config.Duration{Duration: testWindow},
				SizeLimit: config.ByteSize{Bytes: 400}}},
		{Name: "all", Format: config.FormatCargo, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("local", "remote"), PublishTo: "local"}},
		{Name: "open", Format: config.FormatCargo, Type: config.TypeVirtual, AnonymousPull: true,
			Virtual: &config.Virtual{Members: config.Members("local", "remote"), DependencyConfusionProtection: &off}},
		{Name: "filtered", Format: config.FormatCargo, Type: config.TypeVirtual, Virtual: &config.Virtual{PublishTo: "team",
			Members: []config.VirtualMember{{Name: "local", Include: []string{"Acme-*"}}, {Name: "team"},
				{Name: "remote", Exclude: []string{"acme_*"}}}}},
		{Name: "plain", Format: config.FormatCargo, Type: config.TypeVirtual, Virtual: &config.Virtual{Members: config.Members("local", "team")}},
		{Name: "scoped", Format: config.FormatCargo, Type: config.TypeVirtual, Virtual: &config.Virtual{PublishTo: "local",
			Members: []config.VirtualMember{{Name: "local", Include: []string{"acme-*"}}, {Name: "remote"}}}},
		{Name: "pypi", Format: config.FormatPyPI, Type: config.TypeHosted},
	}
	e.reg = metrics.NewRegistry()
	h, err := New(Options{Meta: e.meta, Blobs: e.blobs, Repositories: repos, Authorizer: e.auth, Logger: quiet,
		Metrics: e.reg, Now: e.now, Upstream: upstream.Options{Attempts: 2, Backoff: time.Millisecond}})
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

// aborted is the status do reports for a response the handler cut off,
// as a server would close the connection.
const aborted = -1

// do serves a request; hdr holds header name and value pairs.
func (e *env) do(method, path string, body io.Reader, hdr ...string) (w *httptest.ResponseRecorder) {
	e.t.Helper()
	r := httptest.NewRequest(method, path, body)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w = httptest.NewRecorder()
	defer func() {
		if v := recover(); v != nil {
			if v != http.ErrAbortHandler {
				panic(v)
			}
			w.Code = aborted
		}
	}()
	e.srv.ServeHTTP(w, r)
	return w
}

// get serves a GET and checks the status.
func (e *env) get(path string, status int, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	w := e.do("GET", path, nil, hdr...)
	if w.Code != status {
		e.t.Fatalf("GET %s: %d %q, want %d", path, w.Code, w.Body.String(), status)
	}
	return w
}

// index fetches a crate's index file from repo and decodes its lines.
func (e *env) index(repo, name string) []map[string]any {
	e.t.Helper()
	w := e.get("/cargo/"+repo+"/"+indexPath(strings.ToLower(name)), http.StatusOK)
	return decodeLines(e.t, w.Body.Bytes())
}

func decodeLines(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for ln := range strings.SplitSeq(strings.TrimSuffix(string(b), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("index line %q: %v", ln, err)
		}
		out = append(out, m)
	}
	return out
}

// versions returns the vers of index lines.
func versions(lines []map[string]any) []string {
	var out []string
	for _, l := range lines {
		out = append(out, l["vers"].(string))
	}
	return out
}

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

// settle waits until fetches in progress have linked their files.
func (e *env) settle() {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.h.fetcher.Active() > 0 {
		if time.Now().After(deadline) {
			e.t.Fatal("fetches did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *env) has(k []byte) bool {
	v := e.meta.View()
	defer v.Release()
	_, ok := v.Get(k)
	return ok
}

// crate is a .crate file and the publish metadata that goes with it.
type crate struct {
	meta map[string]any
	body []byte
}

func (c crate) name() string { return c.meta["name"].(string) }
func (c crate) vers() string { return c.meta["vers"].(string) }

func (c crate) sha256() string {
	s := sha256.Sum256(c.body)
	return hex.EncodeToString(s[:])
}

// newCrate builds a crate whose .crate file holds Cargo.toml and
// src/lib.rs under <name>-<version>/, with the given dependencies.
func newCrate(name, vers string, deps ...map[string]any) crate {
	return crate{meta: map[string]any{
		"name": name, "vers": vers, "deps": orEmpty(deps), "features": map[string][]string{},
		"authors": []string{"Alice"}, "description": "The " + name + " crate", "license": "MIT",
		"readme": "A readme.", "keywords": []string{}, "categories": []string{}, "badges": map[string]any{},
		"links": nil, "rust_version": nil,
	}, body: crateFile(name+"-"+vers+"/", "Cargo.toml", "src/lib.rs")}
}

func orEmpty(deps []map[string]any) []map[string]any {
	if deps == nil {
		return []map[string]any{}
	}
	return deps
}

// dep returns a dependency of a publish request.
func dep(name, req string) map[string]any {
	return map[string]any{"name": name, "version_req": req, "features": []string{}, "optional": false,
		"default_features": true, "target": nil, "kind": "normal", "registry": nil, "explicit_name_in_toml": nil}
}

// crateFile builds a gzip-compressed tar archive of the files named,
// under prefix.
func crateFile(prefix string, files ...string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		b := []byte("// " + f + "\n")
		tw.WriteHeader(&tar.Header{Name: prefix + f, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// publishBody frames a publish request.
func publishBody(md, body []byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint32(len(md)))
	b.Write(md)
	binary.Write(&b, binary.LittleEndian, uint32(len(body)))
	b.Write(body)
	return b.Bytes()
}

// publish publishes c to repo.
func (e *env) publish(repo string, c crate) *httptest.ResponseRecorder {
	e.t.Helper()
	md, err := json.Marshal(c.meta)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.do("PUT", "/cargo/"+repo+"/api/v1/crates/new", bytes.NewReader(publishBody(md, c.body)))
}

func (e *env) mustPublish(repo string, c crate) {
	e.t.Helper()
	if w := e.publish(repo, c); w.Code != http.StatusOK {
		e.t.Fatalf("publish %s@%s to %s: %d %s", c.name(), c.vers(), repo, w.Code, w.Body)
	}
}

// upIndex is a fake upstream sparse index: config.json, index files, and
// .crate files, which it serves from /index/ and /files/.
type upIndex struct {
	*httptest.Server
	t *testing.T

	mu       sync.Mutex
	lines    map[string][]string // lowercase name: index lines
	files    map[string][]byte   // "name/vers": .crate
	config   string
	down     atomic.Bool
	status   func(r *http.Request) int
	requests []string
}

func newUpIndex(t *testing.T) *upIndex {
	u := &upIndex{t: t, lines: map[string][]string{}, files: map[string][]byte{}}
	u.Server = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.Close)
	u.config = `{"dl": "` + u.URL + `/files/{lowerprefix}/{crate}/{crate}-{version}.crate", "api": "` + u.URL + `/web"}`
	return u
}

// add publishes c upstream, with its .crate file's checksum unless
// cksum is given.
func (u *upIndex) add(c crate, cksum ...string) {
	sum := c.sha256()
	if len(cksum) > 0 {
		sum = cksum[0]
	}
	l := map[string]any{"name": c.name(), "vers": c.vers(), "deps": []any{}, "cksum": sum, "features": map[string]any{}, "yanked": false}
	b, _ := json.Marshal(l)
	u.mu.Lock()
	defer u.mu.Unlock()
	n := strings.ToLower(c.name())
	u.lines[n] = append(u.lines[n], string(b))
	u.files[c.name()+"/"+c.vers()] = c.body
}

func (u *upIndex) setStatus(f func(r *http.Request) int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status = f
}

// count returns how many requests had a path containing substr.
func (u *upIndex) count(substr string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, r := range u.requests {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

func (u *upIndex) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.requests = append(u.requests, r.URL.Path)
	status := u.status
	u.mu.Unlock()
	if u.down.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if status != nil {
		if s := status(r); s != 0 {
			w.WriteHeader(s)
			return
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	p := r.URL.Path
	switch {
	case p == "/index/config.json":
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, u.config)
	case strings.HasPrefix(p, "/index/"):
		name, ok := parseIndexPath(strings.TrimPrefix(p, "/index/"))
		lines := u.lines[name]
		if !ok || len(lines) == 0 {
			http.NotFound(w, r)
			return
		}
		body := strings.Join(lines, "\n") + "\n"
		sum := sha256.Sum256([]byte(body))
		etag := `"` + hex.EncodeToString(sum[:8]) + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		io.WriteString(w, body)
	case strings.HasPrefix(p, "/files/"):
		parts := strings.Split(strings.TrimPrefix(p, "/files/"), "/")
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		name := parts[len(parts)-2]
		vers := strings.TrimSuffix(strings.TrimPrefix(parts[len(parts)-1], name+"-"), ".crate")
		b, ok := u.files[name+"/"+vers]
		if want := strings.ToLower(prefixOf(name)); strings.Join(parts[:len(parts)-2], "/") != want || !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Write(b)
	case p == "/web/api/v1/crates":
		q := r.URL.Query().Get("q")
		var crates []map[string]any
		for name, lines := range u.lines {
			if strings.Contains(name, q) {
				var l struct{ Name, Vers string }
				json.Unmarshal([]byte(lines[len(lines)-1]), &l)
				crates = append(crates, map[string]any{"name": l.Name, "max_version": l.Vers, "description": nil, "downloads": 7})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"crates": crates, "meta": map[string]any{"total": len(crates) + 5}})
	default:
		http.NotFound(w, r)
	}
}
