package npm

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"github.com/terrabyteian/flint/internal/server"
	"github.com/terrabyteian/flint/internal/upstream"
)

var quiet = slog.New(slog.DiscardHandler)

const testWindow = time.Minute

// testAuth records Authorize calls and refuses the actions in deny with
// the status given, by default 403; a request with the header
// "X-Test-Anonymous" has no credentials and gets 401 instead. The user it
// admits requests as is in "X-Test-User", or "alice".
type testAuth struct {
	mu    sync.Mutex
	calls []string
	deny  map[string]bool
}

func (a *testAuth) Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, repo+":"+strings.Join(actions, ","))
	if r.Header.Get("X-Test-Anonymous") != "" {
		WriteError(w, r, http.StatusUnauthorized, "authentication required")
		return false
	}
	for _, act := range actions {
		if a.deny[act] {
			WriteError(w, r, http.StatusForbidden, "access denied")
			return false
		}
	}
	return true
}

func (a *testAuth) AuthorizeVirtual(w http.ResponseWriter, r *http.Request, virtual, publishTo string, actions ...string) bool {
	a.mu.Lock()
	a.calls = append(a.calls, virtual+">"+publishTo+":"+strings.Join(actions, ","))
	deny := a.deny
	a.mu.Unlock()
	if r.Header.Get("X-Test-Anonymous") != "" {
		WriteError(w, r, http.StatusUnauthorized, "authentication required")
		return false
	}
	for _, act := range actions {
		if deny[act] {
			WriteError(w, r, http.StatusForbidden, "access denied")
			return false
		}
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

func (a *testAuth) setDeny(actions ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deny = map[string]bool{}
	for _, act := range actions {
		a.deny[act] = true
	}
}

func testUser(r *http.Request) string {
	if r.Header.Get("X-Test-Anonymous") != "" {
		return ""
	}
	if u := r.Header.Get("X-Test-User"); u != "" {
		return u
	}
	return "alice"
}

// env is a Handler over in-memory stores, behind a server with the public
// URL https://registry.example, with these repositories:
//
//	local     hosted
//	open      hosted, with anonymous pull
//	oci       a hosted OCI repository
//	remote    proxy of the fake upstream registry up
//	quiet     proxy of up, with forwardAudit off and anonymous pull
//	small     proxy of up with a size limit
//	all       virtual: local, remote; publishes to local
//	exposed   virtual: local, remote, without dependency-confusion protection
//	scoped    virtual: local, remote except @acme/*; publishes to local
//	acme      virtual: local for @acme/* only, open; publishes to local
//	plain     virtual: local, open, without publishTo
//	capped    virtual: remote, local, without dependency-confusion
//	          protection, merging at most 4KiB
//	pair      virtual: quiet, remote, without dependency-confusion
//	          protection
type env struct {
	t     *testing.T
	fs    *fsys.Mem
	meta  meta.Store
	blobs blob.Store
	auth  *testAuth
	up    *upRegistry
	h     *Handler
	reg   *metrics.Registry
	srv   http.Handler
	login func(*http.Request, string, string, string) (string, error)
	// deriveBudget, if set, is the budget of the document cache's derived
	// documents.
	deriveBudget int64

	mu    sync.Mutex
	clock time.Time
}

const testBase = "https://registry.example"

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, fs: fsys.NewMem(), auth: &testAuth{}, up: newUpRegistry(t), clock: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
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
	e.login = func(_ *http.Request, user, pw, client string) (string, error) {
		if user == "alice" && pw == "alice-password" && client == "npm" {
			return "flint_minted", nil
		}
		return "", ErrInvalidLogin
	}
	e.restart()
	return e
}

// restart builds a new Handler over the same stores, as a restart would.
func (e *env) restart() {
	e.t.Helper()
	off := false
	window := config.Duration{Duration: testWindow}
	repos := []config.Repository{
		{Name: "local", Format: config.FormatNPM, Type: config.TypeHosted},
		{Name: "open", Format: config.FormatNPM, Type: config.TypeHosted, AnonymousPull: true},
		{Name: "oci", Format: config.FormatOCI, Type: config.TypeHosted},
		{Name: "remote", Format: config.FormatNPM, Type: config.TypeProxy,
			Proxy: &config.Proxy{URL: e.up.URL + "/registry", RevalidateAfter: window}},
		{Name: "quiet", Format: config.FormatNPM, Type: config.TypeProxy, AnonymousPull: true, NPM: &config.NPM{ForwardAudit: &off},
			Proxy: &config.Proxy{URL: e.up.URL + "/registry/", RevalidateAfter: window}},
		{Name: "small", Format: config.FormatNPM, Type: config.TypeProxy,
			Proxy: &config.Proxy{URL: e.up.URL + "/registry/", RevalidateAfter: window, SizeLimit: config.ByteSize{Bytes: 100}}},
		{Name: "all", Format: config.FormatNPM, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("local", "remote"), PublishTo: "local"}},
		{Name: "exposed", Format: config.FormatNPM, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("local", "remote"), DependencyConfusionProtection: &off}},
		{Name: "scoped", Format: config.FormatNPM, Type: config.TypeVirtual, Virtual: &config.Virtual{PublishTo: "local",
			Members: []config.VirtualMember{{Name: "local"}, {Name: "remote", Exclude: []string{"@acme/*"}}}}},
		{Name: "acme", Format: config.FormatNPM, Type: config.TypeVirtual, Virtual: &config.Virtual{PublishTo: "local",
			Members: []config.VirtualMember{{Name: "local", Include: []string{"@acme/*"}}, {Name: "open"}}}},
		{Name: "plain", Format: config.FormatNPM, Type: config.TypeVirtual, Virtual: &config.Virtual{Members: config.Members("local", "open")}},
		{Name: "capped", Format: config.FormatNPM, Type: config.TypeVirtual, NPM: &config.NPM{MergeLimit: config.ByteSize{Bytes: 4 << 10}},
			Virtual: &config.Virtual{Members: config.Members("remote", "local"), DependencyConfusionProtection: &off}},
		{Name: "pair", Format: config.FormatNPM, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("quiet", "remote"), DependencyConfusionProtection: &off}},
	}
	e.reg = metrics.NewRegistry()
	var docs *upstream.DocCache
	if e.deriveBudget > 0 {
		docs = upstream.NewDocCache(upstream.DocCacheOptions{Meta: e.meta, Blobs: e.blobs, Logger: quiet, Now: e.now,
			DeriveBudget: e.deriveBudget})
	}
	h, err := New(Options{Meta: e.meta, Blobs: e.blobs, Repositories: repos, Authorizer: e.auth, Logger: quiet,
		Metrics: e.reg, Now: e.now, User: testUser, Login: e.login, Docs: docs,
		Upstream: upstream.Options{Attempts: 2, Backoff: time.Millisecond}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.h = h
	srv, err := server.New(server.Options{PublicURL: testBase + "/", Logger: quiet})
	if err != nil {
		e.t.Fatal(err)
	}
	h.Register(srv)
	e.srv = srv.Handler()
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

// has reports whether the metadata store has key k.
func (e *env) has(k []byte) bool {
	v := e.meta.View()
	defer v.Release()
	_, ok := v.Get(k)
	return ok
}

// expect serves a request and checks the status.
func (e *env) expect(method, path string, body io.Reader, status int, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	w := e.do(method, path, body, hdr...)
	if w.Code != status {
		e.t.Fatalf("%s %s: %d %s, want %d", method, path, w.Code, w.Body, status)
	}
	return w
}

// jsonOf decodes a response body.
func jsonOf[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("response %q: %v", w.Body, err)
	}
	return v
}

// errorOf returns the message of an npm error response.
func errorOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	return jsonOf[struct {
		Error string `json:"error"`
	}](t, w).Error
}

// pkg is a package version to publish, as npm sends it.
type pkg struct {
	name, version string
	tarball       []byte
	tags          []string          // default "latest"
	manifest      map[string]any    // extra manifest fields
	attachments   map[string]string // extra attachments: name to data
	readme        string
}

func newPkg(name, version string) *pkg {
	return &pkg{name: name, version: version, tarball: []byte(fmt.Sprintf("tarball of %s@%s", name, version))}
}

func (p *pkg) integrity() string {
	sum := sha512.Sum512(p.tarball)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func (p *pkg) shasum() string {
	sum := sha1.Sum(p.tarball)
	return hex.EncodeToString(sum[:])
}

// body returns the PUT body npm publish sends, built as libnpmpublish
// builds it.
func (p *pkg) body() []byte {
	m := map[string]any{
		"name": p.name, "version": p.version, "description": "the " + p.name + " package",
		"_id": p.name + "@" + p.version, "main": "index.js",
		"dist": map[string]any{"integrity": p.integrity(), "shasum": p.shasum(),
			"tarball": "http://registry.example/" + p.name + "/-/" + p.name + "-" + p.version + ".tgz"},
	}
	if p.readme != "" {
		m["readme"], m["readmeFilename"] = p.readme, "README.md"
	}
	for k, v := range p.manifest {
		m[k] = v
	}
	tags := map[string]string{}
	for _, t := range p.tags {
		tags[t] = p.version
	}
	if len(p.tags) == 0 {
		tags["latest"] = p.version
	}
	att := map[string]any{p.name + "-" + p.version + ".tgz": map[string]any{
		"content_type": "application/octet-stream", "data": base64.StdEncoding.EncodeToString(p.tarball), "length": len(p.tarball)}}
	for k, v := range p.attachments {
		att[k] = map[string]any{"content_type": "application/json", "data": v, "length": len(v)}
	}
	b, _ := json.Marshal(map[string]any{
		"_id": p.name, "name": p.name, "description": "the " + p.name + " package",
		"dist-tags": tags, "versions": map[string]any{p.version: m}, "access": nil, "_attachments": att,
	})
	return b
}

// publish publishes p to repo and checks the status.
func (e *env) publish(repo string, p *pkg, status int) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.expect("PUT", "/npm/"+repo+"/"+escapeName(p.name), bytes.NewReader(p.body()), status,
		"Content-Type", "application/json")
}

// packument is a full packument as clients read it.
type testPackument struct {
	ID       string                    `json:"_id"`
	Rev      string                    `json:"_rev"`
	Name     string                    `json:"name"`
	Tags     map[string]string         `json:"dist-tags"`
	Versions map[string]map[string]any `json:"versions"`
	Time     map[string]string         `json:"time"`
	Readme   string                    `json:"readme"`
	Modified string                    `json:"modified"`
}

// packument fetches a packument; abbreviated asks for the abbreviated
// form.
func (e *env) packument(repo, name string, abbreviated bool) testPackument {
	e.t.Helper()
	hdr := []string{"Accept", "application/json"}
	if abbreviated {
		hdr = []string{"Accept", "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"}
	}
	return jsonOf[testPackument](e.t, e.expect("GET", "/npm/"+repo+"/"+escapeName(name), nil, http.StatusOK, hdr...))
}

// rawPackument fetches the full packument with ?write=true, as npm does
// before it edits a package.
func (e *env) rawPackument(repo, name string) map[string]any {
	e.t.Helper()
	return jsonOf[map[string]any](e.t, e.expect("GET", "/npm/"+repo+"/"+escapeName(name)+"?write=true", nil, http.StatusOK))
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

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
