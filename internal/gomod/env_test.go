package gomod

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// module is a module version a fake upstream serves.
type module struct {
	path, version string
	mod           []byte
	zip           []byte
	time          string
}

// newModule returns a module version with a go.mod file and one source
// file.
func newModule(t *testing.T, path, version string) *module {
	t.Helper()
	m := &module{path: path, version: version, time: "2026-01-02T03:04:05Z"}
	m.build(t, "module "+path+"\n\ngo 1.22\n", "package x // "+version+"\n")
	return m
}

// build sets the module's go.mod file, and its zip with that and one
// source file.
func (m *module) build(t *testing.T, mod, src string) {
	t.Helper()
	m.mod = []byte(mod)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string][]byte{"go.mod": m.mod, "x.go": []byte(src)} {
		w, err := zw.Create(m.path + "@" + m.version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	m.zip = buf.Bytes()
}

func (m *module) info() string {
	return fmt.Sprintf(`{"Version":%q,"Time":%q}`, m.version, m.time)
}

// goProxy is a fake upstream module proxy.
type goProxy struct {
	*httptest.Server
	t *testing.T

	mu       sync.Mutex
	modules  map[string][]*module // by module path
	queries  map[string]string    // "<path>@<query>" to a version
	latest   map[string]string    // by module path
	gone     map[string]bool      // module paths answered 410
	corrupt  map[string]bool      // "<path>@<version>.<ext>" served with a flipped byte
	down     bool
	requests []string
}

func newGoProxy(t *testing.T) *goProxy {
	p := &goProxy{t: t, modules: map[string][]*module{}, queries: map[string]string{}, latest: map[string]string{},
		gone: map[string]bool{}, corrupt: map[string]bool{}}
	p.Server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.Close)
	return p
}

func (p *goProxy) add(ms ...*module) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range ms {
		p.modules[m.path] = append(p.modules[m.path], m)
		p.latest[m.path] = m.version
	}
}

func (p *goProxy) set(f func(p *goProxy)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

func (p *goProxy) took() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.requests
	p.requests = nil
	return r
}

func (p *goProxy) find(path, version string) *module {
	for _, m := range p.modules[path] {
		if m.version == version {
			return m
		}
	}
	return nil
}

func (p *goProxy) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, r.URL.Path)
	if p.down {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/")
	var escPath, file string
	if m, ok := strings.CutSuffix(rest, "/@latest"); ok {
		escPath, file = m, "@latest"
	} else if m, f, ok := strings.Cut(rest, "/@v/"); ok {
		escPath, file = m, f
	}
	path, _ := unescape(escPath)
	if p.gone[path] {
		w.WriteHeader(http.StatusGone)
		return
	}
	ms := p.modules[path]
	if len(ms) == 0 {
		http.NotFound(w, r)
		return
	}
	if file == "list" {
		for _, m := range ms {
			if strings.Count(m.version, "-") < 2 { // not a pseudo-version
				fmt.Fprintln(w, m.version)
			}
		}
		return
	}
	if file == "@latest" {
		io.WriteString(w, p.find(path, p.latest[path]).info())
		return
	}
	dot := strings.LastIndexByte(file, '.')
	if dot < 0 {
		http.NotFound(w, r)
		return
	}
	ver, _ := unescape(file[:dot])
	ext := file[dot+1:]
	if q, ok := p.queries[path+"@"+ver]; ok && ext == "info" {
		if q == "garbage" {
			io.WriteString(w, "<html>not an answer</html>")
			return
		}
		ver = q
	}
	m := p.find(path, ver)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	var b []byte
	switch ext {
	case "info":
		b = []byte(m.info())
	case "mod":
		b = m.mod
	case "zip":
		b = m.zip
	default:
		http.NotFound(w, r)
		return
	}
	if p.corrupt[path+"@"+ver+"."+ext] {
		b = append(bytes.Clone(b[:len(b)-1]), b[len(b)-1]^1)
	}
	w.Write(b)
}

// sumDB is a fake checksum database, signing with its own key: its log
// is a Merkle tree of its records, in order, built as RFC 6962 says, and
// it serves the tiles of the tree.
type sumDB struct {
	*httptest.Server
	name string
	key  string // the public key, "<name>+<hash>+<key>"
	priv ed25519.PrivateKey

	mu       sync.Mutex
	records  map[string]string // "<path>@<version>" to the record's text
	order    []string
	forge    map[string]bool   // lookups answered with another key's signature
	lie      map[string]string // lookups answered with this record's text instead
	tiles    map[string][]byte // tiles served instead of the tree's
	down     bool
	requests []string
}

func newSumDB(t *testing.T, name string) *sumDB {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte{1}, pub...)
	h := sha256.Sum256(append([]byte(name+"\n"), raw...))
	db := &sumDB{name: name, priv: priv, records: map[string]string{}, forge: map[string]bool{}, lie: map[string]string{},
		tiles: map[string][]byte{},
		key:   fmt.Sprintf("%s+%08x+%s", name, binary.BigEndian.Uint32(h[:]), base64.StdEncoding.EncodeToString(raw))}
	db.Server = httptest.NewServer(http.HandlerFunc(db.serve))
	t.Cleanup(db.Close)
	return db
}

// add records the hashes of module versions.
func (db *sumDB) add(ms ...*module) {
	db.mu.Lock()
	defer db.mu.Unlock()
	for _, m := range ms {
		k := m.path + "@" + m.version
		db.records[k] = m.record()
		db.order = append(db.order, k)
	}
}

// record returns the checksum database's record of the module version.
func (m *module) record() string {
	zh, err := upstream.GoZipH1(bytes.NewReader(m.zip), int64(len(m.zip)))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n", m.path, m.version, zh, m.path, m.version, upstream.GoModH1(m.mod))
}

// hash returns the hash of records [lo, hi) of the log, as RFC 6962
// defines it.
func (db *sumDB) hash(lo, hi int) [32]byte {
	if hi-lo == 1 {
		return sha256.Sum256(append([]byte{0}, db.records[db.order[lo]]...))
	}
	k := 1
	for 2*k < hi-lo {
		k *= 2
	}
	l, r := db.hash(lo, lo+k), db.hash(lo+k, hi)
	return sha256.Sum256(append(append([]byte{1}, l[:]...), r[:]...))
}

// tile returns the tile at path below "tile/", such as "8/0/000.p/3", or
// false if the tree has no such tile.
func (db *sumDB) tile(path string) ([]byte, bool) {
	var level, w int
	lv, rest, _ := strings.Cut(strings.TrimPrefix(path, "8/"), "/")
	if _, err := fmt.Sscan(lv, &level); err != nil {
		return nil, false
	}
	idx, ws, partial := strings.Cut(rest, ".p/")
	w = 256
	if partial {
		fmt.Sscan(ws, &w)
	}
	var i int
	fmt.Sscan(strings.ReplaceAll(strings.ReplaceAll(idx, "x", ""), "/", ""), &i)
	size := 1 << (8 * level)
	var b []byte
	for j := i * 256; j < i*256+w; j++ {
		if (j+1)*size > len(db.order) {
			return nil, false
		}
		h := db.hash(j*size, (j+1)*size)
		b = append(b, h[:]...)
	}
	return b, true
}

func (db *sumDB) set(f func(db *sumDB)) {
	db.mu.Lock()
	defer db.mu.Unlock()
	f(db)
}

func (db *sumDB) took() []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	r := db.requests
	db.requests = nil
	return r
}

// tree returns the signed tree head of the records so far, signed with
// priv as name.
func (db *sumDB) tree(name string, priv ed25519.PrivateKey) string {
	var root [32]byte
	if len(db.order) > 0 {
		root = db.hash(0, len(db.order))
	}
	text := fmt.Sprintf("go.sum database tree\n%d\n%s\n", len(db.order), base64.StdEncoding.EncodeToString(root[:]))
	raw := append([]byte{1}, priv.Public().(ed25519.PublicKey)...)
	h := sha256.Sum256(append([]byte(name+"\n"), raw...))
	sig := append(h[:4:4], ed25519.Sign(priv, []byte(text))...)
	return text + "\n— " + name + " " + base64.StdEncoding.EncodeToString(sig) + "\n"
}

func (db *sumDB) serve(w http.ResponseWriter, r *http.Request) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.requests = append(db.requests, r.URL.Path)
	switch p := r.URL.Path; {
	case db.down:
		w.WriteHeader(http.StatusBadGateway)
	case p == "/latest":
		io.WriteString(w, db.tree(db.name, db.priv))
	case strings.HasPrefix(p, "/lookup/"):
		escPath, escVer, _ := strings.Cut(strings.TrimPrefix(p, "/lookup/"), "@")
		path, _ := unescape(escPath)
		ver, _ := unescape(escVer)
		k := path + "@" + ver
		text, ok := db.records[k]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		id := 0
		for i, o := range db.order {
			if o == k {
				id = i
			}
		}
		priv := db.priv
		if db.forge[k] {
			_, priv, _ = ed25519.GenerateKey(rand.Reader)
		}
		if lie, ok := db.lie[k]; ok {
			text = lie
		}
		fmt.Fprintf(w, "%d\n%s\n%s", id, text, db.tree(db.name, priv))
	case strings.HasPrefix(p, "/tile/"):
		b, ok := db.tiles[strings.TrimPrefix(p, "/tile/")]
		if !ok {
			b, ok = db.tile(strings.TrimPrefix(p, "/tile/"))
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

// testAuth records authorization calls and allows them, unless deny.
type testAuth struct {
	mu    sync.Mutex
	calls []string
	deny  bool
}

func (a *testAuth) Authorize(w http.ResponseWriter, _ *http.Request, repo string, actions ...string) bool {
	return a.record(w, repo+":"+strings.Join(actions, ","))
}

func (a *testAuth) AuthorizeVirtual(w http.ResponseWriter, _ *http.Request, virtual, publishTo string, actions ...string) bool {
	return a.record(w, "virtual "+virtual+" "+publishTo+":"+strings.Join(actions, ","))
}

func (a *testAuth) record(w http.ResponseWriter, call string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, call)
	if a.deny {
		w.Header().Set("WWW-Authenticate", `Basic realm="flint"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
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
//	goproxy  proxy of the fake module proxy up, verified against the fake checksum database db
//	second   proxy of the fake module proxy up2, verified against db
//	corp     proxy of up2 with noSumCheck for corp.example.com/*
//	small    proxy of up with a size limit, one upstream request at a time
//	go-all   virtual: goproxy except corp.example.com/*, second
//	corp-all virtual: corp for corp.example.com/* only, goproxy for everything else
type env struct {
	t     *testing.T
	fs    *fsys.Mem
	meta  meta.Store
	blobs blob.Store
	auth  *testAuth
	up    *goProxy
	up2   *goProxy
	db    *sumDB
	h     *Handler
	reg   *metrics.Registry
	pm    *upstream.Metrics
	paths *upstream.PathCache
	fetch *upstream.Fetcher

	mu    sync.Mutex
	clock time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, fs: fsys.NewMem(), auth: &testAuth{}, up: newGoProxy(t), up2: newGoProxy(t), db: newSumDB(t, "sum.example.com"),
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

// repos returns the configured repositories.
func (e *env) repos() []config.Repository {
	sum := &config.Go{SumDB: &config.GoSumDB{Key: e.db.key, URL: e.db.URL}}
	window := config.Duration{Duration: testWindow}
	return []config.Repository{
		{Name: "goproxy", Format: config.FormatGo, Type: config.TypeProxy, Go: sum,
			Proxy: &config.Proxy{URL: e.up.URL, RevalidateAfter: window}},
		{Name: "second", Format: config.FormatGo, Type: config.TypeProxy, Go: sum,
			Proxy: &config.Proxy{URL: e.up2.URL + "/", RevalidateAfter: window}},
		{Name: "corp", Format: config.FormatGo, Type: config.TypeProxy,
			Go:    &config.Go{SumDB: sum.SumDB, NoSumCheck: []string{"corp.example.com/*"}},
			Proxy: &config.Proxy{URL: e.up2.URL, RevalidateAfter: window}},
		{Name: "small", Format: config.FormatGo, Type: config.TypeProxy, Go: sum,
			Proxy: &config.Proxy{URL: e.up.URL, RevalidateAfter: window, SizeLimit: config.ByteSize{Bytes: 1 << 20}, MaxConcurrent: 1}},
		{Name: "go-all", Format: config.FormatGo, Type: config.TypeVirtual, Virtual: &config.Virtual{Members: []config.VirtualMember{
			{Name: "goproxy", Exclude: []string{"corp.example.com/*"}}, {Name: "second"}}}},
		{Name: "corp-all", Format: config.FormatGo, Type: config.TypeVirtual, Virtual: &config.Virtual{Members: []config.VirtualMember{
			{Name: "corp", Include: []string{"corp.example.com/*"}}, {Name: "goproxy", Exclude: []string{"corp.example.com/*"}}}}},
		{Name: "pypi", Format: config.FormatPyPI, Type: config.TypeHosted},
	}
}

// restart builds a new Handler over the same stores, as a restart would.
func (e *env) restart() {
	e.t.Helper()
	e.reg = metrics.NewRegistry()
	e.fetch = upstream.NewFetcher(e.blobs, 0)
	e.pm = upstream.NewMetrics(e.reg, e.fetch, nil)
	docs := upstream.NewDocCache(upstream.DocCacheOptions{Meta: e.meta, Blobs: e.blobs, Metrics: e.pm, Logger: quiet, Now: e.now})
	e.paths = upstream.NewPathCache(upstream.PathCacheOptions{Meta: e.meta, Blobs: e.blobs, Fetcher: e.fetch, Docs: docs,
		Metrics: e.pm, Logger: quiet, Now: e.now})
	h, err := New(Options{Repositories: e.repos(), Authorizer: e.auth, Paths: e.paths, Docs: docs, ProxyMetrics: e.pm,
		Metrics: e.reg, Logger: quiet, Upstream: upstream.Options{Now: e.now, Backoff: time.Millisecond}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.h = h
}

// aborted is the status do reports for a response the handler cut off,
// as it does with content that fails verification while it streams.
const aborted = -1

// do serves a request.
func (e *env) do(method, path string) (w *httptest.ResponseRecorder) {
	e.t.Helper()
	w = httptest.NewRecorder()
	defer func() {
		if v := recover(); v != nil {
			if v != http.ErrAbortHandler {
				panic(v)
			}
			w.Code = aborted
		}
	}()
	e.h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

// get requests path and checks the status and, if body is not "", the
// body.
func (e *env) get(path string, status int, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	w := e.do(http.MethodGet, path)
	if w.Code != status || body != "" && w.Body.String() != body {
		e.t.Fatalf("GET %s = %d %q, want %d %q", path, w.Code, w.Body, status, body)
	}
	return w
}

// settle waits until fetches in progress have linked their content.
func (e *env) settle() {
	deadline := time.Now().Add(5 * time.Second)
	for e.fetch.Active() > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
}

// metric returns the value of a metric sample, or "".
func (e *env) metric(sample string) string {
	var b bytes.Buffer
	e.reg.WriteTo(&b)
	for _, line := range strings.Split(b.String(), "\n") {
		if v, ok := strings.CutPrefix(line, sample+" "); ok {
			return v
		}
	}
	return ""
}

var ctx = context.Background()
