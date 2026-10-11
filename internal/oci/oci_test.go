package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
)

var quiet = slog.New(slog.DiscardHandler)

// testAuth is an Authorizer that records its calls and denies those deny
// matches with a 401 challenge.
type testAuth struct {
	mu    sync.Mutex
	calls []authCall
	deny  func(repo string, actions []string) bool
}

type authCall struct {
	repo    string
	actions string
}

func (a *testAuth) Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool {
	a.mu.Lock()
	a.calls = append(a.calls, authCall{repo, strings.Join(actions, ",")})
	deny := a.deny
	a.mu.Unlock()
	if deny != nil && deny(repo, actions) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="test",scope="repository:`+repo+`:`+strings.Join(actions, ",")+`"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *testAuth) reset() []authCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.calls
	a.calls = nil
	return c
}

// catalogAuth adds the CatalogAuthorizer extension to testAuth.
type catalogAuth struct {
	testAuth
	visible func(string) bool
}

func (a *catalogAuth) AuthorizeCatalog(w http.ResponseWriter, r *http.Request) (func(string) bool, bool) {
	if a.visible == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	return a.visible, true
}

// env is a Handler over in-memory stores.
type env struct {
	t     *testing.T
	h     *Handler
	meta  meta.Store
	blobs blob.Store
	auth  *catalogAuth
	reg   *metrics.Registry
	now   time.Time
}

var testRepos = []config.Repository{
	{Name: "hosted", Format: config.FormatOCI, Type: config.TypeHosted},
	{Name: "frozen", Format: config.FormatOCI, Type: config.TypeHosted, ImmutableTags: true, HelmIndex: true},
	{Name: "other", Format: config.FormatOCI, Type: config.TypeHosted},
	{Name: "charts", Format: config.FormatOCI, Type: config.TypeHosted, HelmIndex: true},
}

func newEnv(t *testing.T) *env {
	t.Helper()
	fs := fsys.NewMem()
	return newEnvFS(t, fs, "/data")
}

func newEnvFS(t *testing.T, fs fsys.FS, dir string) *env {
	t.Helper()
	ms, err := meta.Open(dir+"/meta", meta.Options{FS: fs, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	bs, err := blob.NewFS(dir, blob.Options{FS: fs})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, meta: ms, blobs: bs, auth: &catalogAuth{visible: func(string) bool { return true }},
		reg: metrics.NewRegistry(), now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	e.h, err = New(Options{Meta: ms, Blobs: bs, Repositories: testRepos, Authorizer: e.auth,
		Logger: quiet, Metrics: e.reg, Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// do serves one request. hdr is a list of header name, value pairs.
func (e *env) do(method, path string, body []byte, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rd)
	for i := 0; i < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// want checks a response's status and, for errors, its error code.
func want(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d; body %s", w.Code, status, w.Body)
	}
	if code == "" {
		return
	}
	var body struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Errors) != 1 {
		t.Fatalf("error body %q: %v", w.Body, err)
	}
	if body.Errors[0].Code != code {
		t.Fatalf("error code = %s, want %s (%s)", body.Errors[0].Code, code, body.Errors[0].Message)
	}
	if body.Errors[0].Message == "" {
		t.Fatalf("error %s has no message", code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("error Content-Type = %q", ct)
	}
}

// pushBlob uploads content to name in one request and returns its digest.
func (e *env) pushBlob(name string, content []byte) blob.Digest {
	e.t.Helper()
	d := blob.FromBytes(content)
	w := e.do("POST", "/v2/"+name+"/blobs/uploads/?digest="+d.String(), content)
	want(e.t, w, http.StatusCreated, "")
	return d
}

// image is a manifest with its config and layers.
type image struct {
	config, layer []byte
	manifest      []byte
	digest        blob.Digest
}

func desc(mt string, b []byte) map[string]any {
	return map[string]any{"mediaType": mt, "digest": blob.FromBytes(b).String(), "size": len(b)}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// newImage builds a distinct OCI image manifest from seed.
func newImage(seed string, extra map[string]any) image {
	img := image{config: []byte(`{"seed":"` + seed + `"}`), layer: []byte("layer " + seed)}
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIManifest,
		"config":        desc("application/vnd.oci.image.config.v1+json", img.config),
		"layers":        []any{desc("application/vnd.oci.image.layer.v1.tar+gzip", img.layer)},
	}
	for k, v := range extra {
		m[k] = v
	}
	img.manifest = mustJSON(m)
	img.digest = blob.FromBytes(img.manifest)
	return img
}

// pushImage pushes an image's blobs and its manifest under ref.
func (e *env) pushImage(name, ref string, img image) *httptest.ResponseRecorder {
	e.t.Helper()
	e.pushBlob(name, img.config)
	e.pushBlob(name, img.layer)
	return e.do("PUT", "/v2/"+name+"/manifests/"+ref, img.manifest, "Content-Type", mtOCIManifest)
}

func TestNewRequiresStoresAndAuthorizer(t *testing.T) {
	e := newEnv(t)
	for _, opts := range []Options{
		{Blobs: e.blobs, Authorizer: AllowAll{}},
		{Meta: e.meta, Authorizer: AllowAll{}},
		{Meta: e.meta, Blobs: e.blobs},
	} {
		if _, err := New(opts); err == nil {
			t.Errorf("New(%+v) succeeded", opts)
		}
	}
}

func TestBase(t *testing.T) {
	e := newEnv(t)
	w := e.do("GET", "/v2/", nil)
	want(t, w, 200, "")
	if w.Body.String() != "{}" || w.Header().Get("Docker-Distribution-API-Version") != "registry/2.0" {
		t.Errorf("base = %q, headers %v", w.Body, w.Header())
	}
	if calls := e.auth.reset(); !slices.Equal(calls, []authCall{{"", ""}}) {
		t.Errorf("base check authorized as %v, want an empty repo and no actions", calls)
	}
	w = e.do("HEAD", "/v2/", nil)
	want(t, w, 200, "")
	if w.Body.Len() != 0 {
		t.Errorf("HEAD body %q", w.Body)
	}
	w = e.do("POST", "/v2/", nil)
	want(t, w, 405, codeUnsupported)
	if got := w.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q", got)
	}

	e.auth.deny = func(string, []string) bool { return true }
	w = e.do("GET", "/v2/", nil)
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("denied base check = %d %v", w.Code, w.Header())
	}
}

func TestNames(t *testing.T) {
	e := newEnv(t)
	d := blob.FromBytes(nil).String()
	tests := []struct {
		path   string
		status int
		code   string
	}{
		{"/v2/hosted/App/tags/list", 400, codeNameInvalid},
		{"/v2/hosted/a--/tags/list", 400, codeNameInvalid},
		{"/v2/hosted//a/tags/list", 400, codeNameInvalid},
		{"/v2/" + strings.Repeat("a/", 128) + "b/tags/list", 400, codeNameInvalid},
		{"/v2/nope/app/tags/list", 404, codeNameUnknown},
		{"/v2/hosted/tags/list", 404, codeNameUnknown},
		{"/v2/hosted/app/blobs/" + d, 404, codeBlobUnknown},
		{"/v2/hosted/app/whatever", 404, codeUnsupported},
		{"/v2/hosted", 404, codeUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			want(t, e.do("GET", tt.path, nil), tt.status, tt.code)
		})
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		path string
		name string
		ep   endpoint
		arg  string
	}{
		{"r/a/blobs/sha256:x", "r/a", epBlob, "sha256:x"},
		{"r/a/b/c/blobs/uploads/", "r/a/b/c", epUploadStart, ""},
		{"r/a/blobs/uploads", "r/a", epUploadStart, ""},
		{"r/a/blobs/uploads/abc", "r/a", epUpload, "abc"},
		{"r/a/manifests/latest", "r/a", epManifest, "latest"},
		{"r/a/tags/list", "r/a", epTags, ""},
		{"r/a/referrers/sha256:x", "r/a", epReferrers, "sha256:x"},
		{"r/blobs/blobs/sha256:x", "r/blobs", epBlob, "sha256:x"},
		{"r/manifests/manifests/v1", "r/manifests", epManifest, "v1"},
		{"r/blobs/uploads/blobs/uploads/", "r/blobs/uploads", epUploadStart, ""},
	}
	for _, tt := range tests {
		name, ep, arg, ok := splitPath(tt.path)
		if !ok || name != tt.name || ep != tt.ep || arg != tt.arg {
			t.Errorf("splitPath(%q) = %q %d %q %v, want %q %d %q", tt.path, name, ep, arg, ok, tt.name, tt.ep, tt.arg)
		}
	}
	for _, p := range []string{"", "r", "r/a", "r/a/tags", "blobs/x", "r/a/unknown/x"} {
		if name, ep, _, ok := splitPath(p); ok {
			t.Errorf("splitPath(%q) = %q %d, want no match", p, name, ep)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, s := range []string{"a", "a/b", "a0/b.c", "a_b", "a__b", "a-b", "a---b", "hosted/team/app.v2"} {
		if !validName(s) {
			t.Errorf("validName(%q) = false", s)
		}
	}
	for _, s := range []string{"", "A", "a/", "/a", "a//b", "-a", "a-", "a.", "a..b", "a___b", "a.-b", "a b", "a/B",
		strings.Repeat("a", 256)} {
		if validName(s) {
			t.Errorf("validName(%q) = true", s)
		}
	}
}

func TestValidTag(t *testing.T) {
	for _, s := range []string{"latest", "v1.0.0", "_x", "A-b_c.d", strings.Repeat("a", 128)} {
		if !validTag(s) {
			t.Errorf("validTag(%q) = false", s)
		}
	}
	for _, s := range []string{"", ".x", "-x", "a:b", "a/b", strings.Repeat("a", 129)} {
		if validTag(s) {
			t.Errorf("validTag(%q) = true", s)
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	e := newEnv(t)
	d := blob.FromBytes(nil).String()
	tests := []struct {
		method, path, allow string
	}{
		{"POST", "/v2/hosted/a/blobs/" + d, "GET, HEAD, DELETE"},
		{"GET", "/v2/hosted/a/blobs/uploads/", "POST"},
		{"POST", "/v2/hosted/a/blobs/uploads/x", "GET, PUT, PATCH, DELETE"},
		{"POST", "/v2/hosted/a/manifests/v1", "GET, HEAD, PUT, DELETE"},
		{"DELETE", "/v2/hosted/a/tags/list", "GET"},
		{"PUT", "/v2/hosted/a/referrers/" + d, "GET"},
		{"POST", "/v2/_catalog", "GET"},
	}
	for _, tt := range tests {
		w := e.do(tt.method, tt.path, nil)
		want(t, w, 405, codeUnsupported)
		if got := w.Header().Get("Allow"); got != tt.allow {
			t.Errorf("%s %s: Allow = %q, want %q", tt.method, tt.path, got, tt.allow)
		}
	}
	if calls := e.auth.reset(); len(calls) != 0 {
		t.Errorf("405s consulted the authorizer: %v", calls)
	}
}

// TestAuthorization checks the repository and actions each endpoint asks
// the Authorizer for, and that a denied request does nothing.
func TestAuthorization(t *testing.T) {
	e := newEnv(t)
	img := newImage("a", nil)
	want(t, e.pushImage("hosted/app", "v1", img), 201, "")
	d := blob.FromBytes(img.layer).String()
	e.auth.reset()

	tests := []struct {
		method, path string
		actions      string
	}{
		{"GET", "/v2/hosted/app/blobs/" + d, "pull"},
		{"HEAD", "/v2/hosted/app/blobs/" + d, "pull"},
		{"DELETE", "/v2/hosted/app/blobs/" + d, "delete"},
		{"POST", "/v2/hosted/app/blobs/uploads/", "pull,push"},
		{"GET", "/v2/hosted/app/blobs/uploads/x", "pull,push"},
		{"PATCH", "/v2/hosted/app/blobs/uploads/x", "pull,push"},
		{"PUT", "/v2/hosted/app/blobs/uploads/x", "pull,push"},
		{"DELETE", "/v2/hosted/app/blobs/uploads/x", "pull,push"},
		{"GET", "/v2/hosted/app/manifests/v1", "pull"},
		{"HEAD", "/v2/hosted/app/manifests/v1", "pull"},
		{"PUT", "/v2/hosted/app/manifests/v1", "pull,push"},
		{"DELETE", "/v2/hosted/app/manifests/v1", "delete"},
		{"GET", "/v2/hosted/app/tags/list", "pull"},
		{"GET", "/v2/hosted/app/referrers/" + d, "pull"},
	}
	e.auth.deny = func(string, []string) bool { return true }
	for _, tt := range tests {
		w := e.do(tt.method, tt.path, []byte("x"))
		if w.Code != 401 {
			t.Errorf("%s %s denied: status %d", tt.method, tt.path, w.Code)
		}
		calls := e.auth.reset()
		if !slices.Equal(calls, []authCall{{"hosted/app", tt.actions}}) {
			t.Errorf("%s %s authorized as %v, want hosted/app %s", tt.method, tt.path, calls, tt.actions)
		}
	}
	// Nothing changed.
	e.auth.deny = nil
	want(t, e.do("GET", "/v2/hosted/app/blobs/"+d, nil), 200, "")
	want(t, e.do("GET", "/v2/hosted/app/manifests/v1", nil), 200, "")
}

func TestCatalogAuthorization(t *testing.T) {
	e := newEnv(t)
	want(t, e.pushImage("hosted/a", "v1", newImage("a", nil)), 201, "")
	want(t, e.pushImage("other/b", "v1", newImage("b", nil)), 201, "")

	e.auth.visible = func(repo string) bool { return strings.HasPrefix(repo, "other/") }
	w := e.do("GET", "/v2/_catalog", nil)
	want(t, w, 200, "")
	if got := w.Body.String(); got != `{"repositories":["other/b"]}` {
		t.Errorf("filtered catalog = %s", got)
	}
	e.auth.visible = nil
	if w := e.do("GET", "/v2/_catalog", nil); w.Code != 401 {
		t.Errorf("denied catalog = %d", w.Code)
	}

	// An Authorizer without the extension does not serve the catalog.
	h, err := New(Options{Meta: e.meta, Blobs: e.blobs, Repositories: testRepos, Authorizer: &e.auth.testAuth, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v2/_catalog", nil))
	want(t, rec, 404, codeUnsupported)
}

func TestAllowAll(t *testing.T) {
	var a AllowAll
	if !a.Authorize(nil, nil, "x", ActionDelete) {
		t.Error("AllowAll denied")
	}
	if f, ok := a.AuthorizeCatalog(nil, nil); !ok || !f("x") {
		t.Error("AllowAll hid the catalog")
	}
}

func TestRegister(t *testing.T) {
	e := newEnv(t)
	mux := http.NewServeMux()
	e.h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v2/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("GET /v2/ via the mux = %d", resp.StatusCode)
	}
}

// TestActor checks that batch origins name the request's principal.
func TestActor(t *testing.T) {
	e := newEnv(t)
	e.h.actor = func(*http.Request) string { return "alice" }
	seq := e.meta.Stats().Seq
	e.pushBlob("hosted/a", []byte("x"))
	var origins []meta.Origin
	if err := e.meta.ReadLog(context.Background(), seq, func(en meta.Entry) error {
		origins = append(origins, en.Origin)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(origins) != 1 || origins[0].Actor != "alice" || origins[0].Action != "oci.blob.push" {
		t.Errorf("origins = %+v", origins)
	}
	r := httptest.NewRequest("GET", "/", nil)
	if got := clientActor(r); got != "anonymous" {
		t.Errorf("clientActor without server info = %q", got)
	}
}
