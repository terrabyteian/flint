package npm

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/upstream"
)

// abbreviatedAccept is the Accept header npm sends for packuments.
const abbreviatedAccept = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"

// dist returns a version's dist object of a packument.
func dist(t *testing.T, doc testPackument, version string) map[string]any {
	t.Helper()
	v, ok := doc.Versions[version]
	if !ok {
		t.Fatalf("the packument has no version %s: %v", version, doc.Versions)
	}
	d, _ := v["dist"].(map[string]any)
	return d
}

func TestProxyPackument(t *testing.T) {
	e := newEnv(t)
	e.up.add("left-pad", "1.0.0", nil)
	e.up.add("left-pad", "1.1.0", map[string]any{"dist": map[string]any{"integrity": "sha512-x", "tarball": "https://elsewhere.example/x.tgz",
		"attestations": map[string]any{"url": "https://elsewhere.example/att", "provenance": map[string]any{"predicateType": "p"}}}})
	e.up.add("@acme/lib", "2.0.0", nil)

	doc := e.packument("remote", "left-pad", false)
	if doc.Name != "left-pad" || doc.Tags["latest"] != "1.1.0" || doc.Readme != "# upstream" || doc.Time["1.0.0"] == "" {
		t.Errorf("full packument %+v", doc)
	}
	d := dist(t, doc, "1.0.0")
	if d["tarball"] != testBase+"/npm/remote/left-pad/-/left-pad-1.0.0.tgz" {
		t.Errorf("tarball URL %v", d["tarball"])
	}
	if sigs, _ := d["signatures"].([]any); len(sigs) != 1 {
		t.Errorf("signatures %v, want the upstream's", d["signatures"])
	}
	d = dist(t, doc, "1.1.0")
	att, _ := d["attestations"].(map[string]any)
	if d["tarball"] != testBase+"/npm/remote/left-pad/-/left-pad-1.1.0.tgz" ||
		att["url"] != testBase+"/npm/remote/-/npm/v1/attestations/left-pad@1.1.0" || att["provenance"] == nil {
		t.Errorf("rewritten dist %v", d)
	}

	w := e.expect("GET", "/npm/remote/@acme%2flib", nil, http.StatusOK, "Accept", abbreviatedAccept)
	if ct := w.Header().Get("Content-Type"); ct != mtAbbreviated {
		t.Errorf("abbreviated Content-Type %q", ct)
	}
	abbr := jsonOf[testPackument](t, w)
	if abbr.Modified == "" || abbr.Readme != "" ||
		dist(t, abbr, "2.0.0")["tarball"] != testBase+"/npm/remote/@acme/lib/-/lib-2.0.0.tgz" {
		t.Errorf("abbreviated packument %+v", abbr)
	}
	// The plain spelling of a scoped name is the same package.
	e.packument("remote", "@acme/lib", true)

	// Within the window, served from the cache, the full and the
	// abbreviated form each fetched once; an ETag answers 304.
	etag := e.expect("GET", "/npm/remote/left-pad", nil, http.StatusOK).Header().Get("ETag")
	e.expect("GET", "/npm/remote/left-pad", nil, http.StatusNotModified, "If-None-Match", etag)
	e.packument("remote", "left-pad", true)
	e.packument("remote", "left-pad", true)
	if n := e.up.count("GET /registry/left-pad"); n != 2 {
		t.Errorf("%d upstream packument requests within the window, want 2", n)
	}
	// After the window, revalidated with the upstream's ETag: the same
	// document, the same ETag.
	e.advance(2 * testWindow)
	if got := e.expect("GET", "/npm/remote/left-pad", nil, http.StatusOK).Header().Get("ETag"); got != etag {
		t.Errorf("ETag after revalidation %q, want %q", got, etag)
	}
	if n := e.up.count("GET /registry/left-pad"); n != 3 {
		t.Errorf("%d upstream packument requests after the window, want 3", n)
	}
	// The public URL is not part of the stored document: the URLs follow
	// the request's base.
	if v := e.metric(`flint_proxy_requests_total{repository="remote",result="revalidated"}`); v != "1" {
		t.Errorf("revalidated requests %q", v)
	}
}

func TestProxyTarball(t *testing.T) {
	e := newEnv(t)
	e.up.add("left-pad", "1.0.0", nil)
	e.up.add("left-pad", "2.0.0", nil)
	path := "/npm/remote/left-pad/-/left-pad-1.0.0.tgz"
	w := e.expect("GET", path, nil, http.StatusOK)
	if !bytes.Equal(w.Body.Bytes(), tarballOf("left-pad", "1.0.0")) {
		t.Fatalf("tarball %q", w.Body)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") || !strings.HasPrefix(cc, "private") {
		t.Errorf("Cache-Control %q", cc)
	}
	e.settle()
	if !e.has(upstream.FileKey("remote", "left-pad/-/left-pad-1.0.0.tgz")) {
		t.Fatal("the tarball is not cached")
	}
	e.expect("GET", path, nil, http.StatusOK)
	if n := e.up.count("/files/"); n != 1 {
		t.Errorf("%d upstream tarball requests", n)
	}
	// Scoped tarballs, and HEAD.
	e.up.add("@acme/lib", "1.0.0", nil)
	e.expect("HEAD", "/npm/remote/@acme/lib/-/lib-1.0.0.tgz", nil, http.StatusOK)
	if w := e.expect("GET", "/npm/remote/@acme%2flib/-/lib-1.0.0.tgz", nil, http.StatusOK); !bytes.Equal(w.Body.Bytes(), tarballOf("@acme/lib", "1.0.0")) {
		t.Errorf("scoped tarball %q", w.Body)
	}

	// With the upstream down, the cached packument and tarball are
	// served; what is not cached fails.
	e.up.down.Store(true)
	e.advance(2 * testWindow)
	e.expect("GET", path, nil, http.StatusOK)
	e.packument("remote", "left-pad", true)
	e.expect("GET", "/npm/remote/left-pad/-/left-pad-2.0.0.tgz", nil, http.StatusServiceUnavailable)
	e.expect("GET", "/npm/remote/nothing", nil, http.StatusServiceUnavailable)
	e.up.down.Store(false)
	e.expect("GET", "/npm/remote/left-pad/-/left-pad-9.0.0.tgz", nil, http.StatusNotFound)
	e.expect("GET", "/npm/remote/left-pad/-/other-1.0.0.tgz", nil, http.StatusNotFound)
	e.expect("GET", "/npm/remote/nothing/-/nothing-1.0.0.tgz", nil, http.StatusNotFound)
	if v := e.metric(`flint_proxy_requests_total{repository="remote",result="stale"}`); v == "" || v == "0" {
		t.Errorf("stale requests %q", v)
	}
}

// TestProxyRemovedUpstream checks that a version the upstream removes
// leaves the packument, which follows the upstream, but that its cached
// tarball keeps being served; and that a package the upstream no longer
// has is answered 404, even though it is cached.
func TestProxyRemovedUpstream(t *testing.T) {
	e := newEnv(t)
	e.up.add("evil", "1.0.0", nil)
	e.up.add("evil", "1.0.1", nil)
	e.expect("GET", "/npm/remote/evil/-/evil-1.0.1.tgz", nil, http.StatusOK)
	e.settle()
	e.up.remove("evil", "1.0.1")
	e.advance(2 * testWindow)
	doc := e.packument("remote", "evil", true)
	if _, ok := doc.Versions["1.0.1"]; ok || doc.Tags["latest"] == "1.0.1" {
		t.Errorf("the removed version is listed: %+v", doc)
	}
	e.expect("GET", "/npm/remote/evil/-/evil-1.0.1.tgz", nil, http.StatusOK)

	e.up.setStatus(func(r *http.Request) int {
		if strings.HasPrefix(r.URL.Path, "/registry/evil") {
			return http.StatusNotFound
		}
		return 0
	})
	e.advance(2 * testWindow)
	if w := e.expect("GET", "/npm/remote/evil", nil, http.StatusNotFound); !strings.Contains(errorOf(t, w), "evil is not found") {
		t.Errorf("404 message %q", errorOf(t, w))
	}
	if !e.has(upstream.DocKey("remote", packumentKey("evil", true))) {
		t.Error("the cached packument was deleted")
	}
	// Denied is not found too.
	e.up.setStatus(func(*http.Request) int { return http.StatusForbidden })
	e.expect("GET", "/npm/remote/other", nil, http.StatusNotFound)
}

func TestProxyVerifies(t *testing.T) {
	e := newEnv(t)
	e.up.add("p", "1.0.0", map[string]any{"dist": map[string]any{
		"integrity": "sha512-" + strings.Repeat("A", 86) + "==", "tarball": e.up.URL + "/files/p/-/p-1.0.0.tgz"}})
	w := e.do("GET", "/npm/remote/p/-/p-1.0.0.tgz", nil)
	if w.Code != aborted && w.Code != http.StatusBadGateway || bytes.Equal(w.Body.Bytes(), tarballOf("p", "1.0.0")) {
		t.Errorf("a tarball that does not match its integrity: %d, served whole", w.Code)
	}
	e.settle()
	if e.has(upstream.FileKey("remote", "p/-/p-1.0.0.tgz")) {
		t.Error("a tarball that does not match its integrity was cached")
	}

	// A version too old to have an integrity is verified by its shasum.
	sum := tarballSHA1("q", "1.0.0")
	e.up.add("q", "1.0.0", map[string]any{"dist": map[string]any{"shasum": sum, "tarball": e.up.URL + "/files/q/-/q-1.0.0.tgz"}})
	e.expect("GET", "/npm/remote/q/-/q-1.0.0.tgz", nil, http.StatusOK)
	e.up.add("q", "1.0.1", map[string]any{"dist": map[string]any{"shasum": sum, "tarball": e.up.URL + "/files/q/-/q-1.0.1.tgz"}})
	e.advance(2 * testWindow)
	if w := e.do("GET", "/npm/remote/q/-/q-1.0.1.tgz", nil); w.Code != aborted && w.Code != http.StatusBadGateway {
		t.Errorf("a tarball that does not match its shasum: %d", w.Code)
	}
	// Without either, a tarball cannot be verified and is not served.
	e.up.add("r", "1.0.0", map[string]any{"dist": map[string]any{"tarball": e.up.URL + "/files/r/-/r-1.0.0.tgz"}})
	e.expect("GET", "/npm/remote/r/-/r-1.0.0.tgz", nil, http.StatusBadGateway)
	// A tarball on a host the fetch policy does not allow is not fetched.
	e.up.add("s", "1.0.0", map[string]any{"dist": map[string]any{"shasum": sum, "tarball": "https://elsewhere.example/s.tgz"}})
	e.expect("GET", "/npm/remote/s/-/s-1.0.0.tgz", nil, http.StatusBadGateway)
}

func tarballSHA1(name, version string) string {
	return (&pkg{tarball: tarballOf(name, version)}).shasum()
}

// TestProxyInvalidPackument checks that a document flint cannot read, or
// that names another package, never replaces the cached packument.
func TestProxyInvalidPackument(t *testing.T) {
	e := newEnv(t)
	e.up.add("p", "1.0.0", nil)
	e.packument("remote", "p", false)
	e.up.add("p", "1.0.1", map[string]any{"name": "p"})
	e.up.mu.Lock()
	e.up.pkgs["p"].name = "other"
	e.up.mu.Unlock()
	e.advance(2 * testWindow)
	if doc := e.packument("remote", "p", false); doc.Tags["latest"] != "1.0.0" {
		t.Errorf("a packument of another package replaced the cached one: %+v", doc.Tags)
	}
	// Nothing cached: the document cannot be served.
	e.up.mu.Lock()
	e.up.pkgs["x"] = e.up.pkgs["p"]
	e.up.mu.Unlock()
	e.expect("GET", "/npm/remote/x", nil, http.StatusBadGateway)
}

// TestProxyLargePackument checks that a packument larger than the derive
// budget allows to hold is streamed through the rewriter.
func TestProxyLargePackument(t *testing.T) {
	e := newEnv(t)
	e.deriveBudget = 4 << 10
	e.restart()
	for i := range 40 {
		e.up.add("big", fmt.Sprintf("1.0.%d", i), map[string]any{"padding": strings.Repeat("x", 200)})
	}
	w := e.expect("GET", "/npm/remote/big", nil, http.StatusOK)
	if w.Header().Get("ETag") != "" || len(w.Body.Bytes()) < 8<<10 {
		t.Errorf("a large packument was held: ETag %q, %d bytes", w.Header().Get("ETag"), w.Body.Len())
	}
	doc := jsonOf[testPackument](t, w)
	if len(doc.Versions) != 40 || dist(t, doc, "1.0.7")["tarball"] != testBase+"/npm/remote/big/-/big-1.0.7.tgz" {
		t.Errorf("streamed packument: %d versions, %v", len(doc.Versions), dist(t, doc, "1.0.7"))
	}
	e.expect("HEAD", "/npm/remote/big", nil, http.StatusOK)
}

func TestProxyVersionAndDistTags(t *testing.T) {
	e := newEnv(t)
	e.up.add("p", "1.0.0", nil)
	e.up.add("p", "2.0.0", nil)
	e.up.mu.Lock()
	e.up.pkgs["p"].tags["next"] = "1.0.0"
	e.up.mu.Unlock()
	for spec, want := range map[string]string{"1.0.0": "1.0.0", "latest": "2.0.0", "next": "1.0.0"} {
		m := jsonOf[map[string]any](t, e.expect("GET", "/npm/remote/p/"+spec, nil, http.StatusOK))
		d, _ := m["dist"].(map[string]any)
		if m["version"] != want || d["tarball"] != testBase+"/npm/remote/p/-/p-"+want+".tgz" {
			t.Errorf("%s: %v", spec, m)
		}
	}
	e.expect("GET", "/npm/remote/p/3.0.0", nil, http.StatusNotFound)
	tags := jsonOf[map[string]string](t, e.expect("GET", "/npm/remote/-/package/p/dist-tags", nil, http.StatusOK))
	if tags["latest"] != "2.0.0" || tags["next"] != "1.0.0" {
		t.Errorf("dist-tags %v", tags)
	}
	e.expect("GET", "/npm/remote/-/package/nope/dist-tags", nil, http.StatusNotFound)
}

// TestProxyReadOnly checks that a proxy repository refuses every change.
func TestProxyReadOnly(t *testing.T) {
	e := newEnv(t)
	e.up.add("p", "1.0.0", nil)
	for _, req := range []struct{ method, path, body string }{
		{"PUT", "/npm/remote/p", string(newPkg("p", "2.0.0").body())},
		{"PUT", "/npm/remote/p/-rev/1-x", "{}"},
		{"DELETE", "/npm/remote/p/-rev/1-x", ""},
		{"DELETE", "/npm/remote/p/-/p-1.0.0.tgz/-rev/1-x", ""},
		{"PUT", "/npm/remote/-/package/p/dist-tags/beta", `"1.0.0"`},
		{"DELETE", "/npm/remote/-/package/p/dist-tags/beta", ""},
	} {
		w := e.do(req.method, req.path, strings.NewReader(req.body), "Content-Type", "application/json")
		if w.Code != http.StatusMethodNotAllowed || !strings.Contains(errorOf(t, w), "read-only proxy") {
			t.Errorf("%s %s: %d %s", req.method, req.path, w.Code, w.Body)
		}
	}
	if n := e.up.count("PUT"); n != 0 {
		t.Errorf("%d changes sent upstream", n)
	}
}

// TestProxyForwarded checks search, audit, the signing keys, and
// attestations of a proxy repository.
func TestProxyForwarded(t *testing.T) {
	e := newEnv(t)
	e.up.add("left-pad", "1.0.0", nil)
	e.up.add("@acme/lib", "1.0.0", nil)
	res := jsonOf[struct {
		Objects []map[string]any `json:"objects"`
		Total   int              `json:"total"`
	}](t, e.expect("GET", "/npm/remote/-/v1/search?text=pad&size=5", nil, http.StatusOK))
	if len(res.Objects) != 1 || res.Total != 1 {
		t.Errorf("search %+v", res)
	}

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`{"left-pad": ["1.0.0"]}`))
	zw.Close()
	adv := jsonOf[map[string][]map[string]any](t, e.expect("POST", "/npm/remote/-/npm/v1/security/advisories/bulk",
		bytes.NewReader(gz.Bytes()), http.StatusOK, "Content-Type", "application/json", "Content-Encoding", "gzip"))
	if len(adv["left-pad"]) != 1 {
		t.Errorf("advisories %v", adv)
	}
	if len(e.up.audits) != 1 || e.up.audits[0]["left-pad"] == nil {
		t.Errorf("audits sent upstream %v", e.up.audits)
	}
	// With forwardAudit off, nothing is sent.
	adv = jsonOf[map[string][]map[string]any](t, e.expect("POST", "/npm/quiet/-/npm/v1/security/advisories/bulk",
		strings.NewReader(`{"left-pad": ["1.0.0"]}`), http.StatusOK))
	if len(adv) != 0 || len(e.up.audits) != 1 {
		t.Errorf("quiet: advisories %v, %d audits sent upstream", adv, len(e.up.audits))
	}

	keys := jsonOf[map[string][]map[string]any](t, e.expect("GET", "/npm/remote/-/npm/v1/keys", nil, http.StatusOK))
	if len(keys["keys"]) != 1 || keys["keys"][0]["keyid"] != "SHA256:up" {
		t.Errorf("keys %v", keys)
	}
	att := jsonOf[map[string][]map[string]any](t, e.expect("GET", "/npm/remote/-/npm/v1/attestations/@acme/lib@1.0.0", nil, http.StatusOK))
	if b, _ := att["attestations"][0]["bundle"].(map[string]any); b["of"] != "@acme/lib@1.0.0" {
		t.Errorf("attestations %v", att)
	}
	// Cached: served with the upstream down.
	e.up.down.Store(true)
	e.advance(2 * testWindow)
	e.expect("GET", "/npm/remote/-/npm/v1/keys", nil, http.StatusOK)
	e.expect("GET", "/npm/remote/-/npm/v1/attestations/@acme/lib@1.0.0", nil, http.StatusOK)
	e.expect("GET", "/npm/remote/-/v1/search?text=pad", nil, http.StatusServiceUnavailable)
	// An upstream without signing keys has none.
	e.up.down.Store(false)
	e.up.setStatus(func(r *http.Request) int {
		if strings.HasSuffix(r.URL.Path, "/keys") {
			return http.StatusNotFound
		}
		return 0
	})
	if keys := jsonOf[map[string][]any](t, e.expect("GET", "/npm/quiet/-/npm/v1/keys", nil, http.StatusOK)); len(keys["keys"]) != 0 {
		t.Errorf("keys of an upstream without them %v", keys)
	}
}

// TestProxyCredentials checks that a proxy repository sends its
// credentials with every upstream request: a token alone as a bearer
// token.
func TestProxyCredentials(t *testing.T) {
	e := newEnv(t)
	e.up.add("p", "1.0.0", nil)
	pw := filepath.Join(t.TempDir(), "token")
	os.WriteFile(pw, []byte("upstream-token\n"), 0o600)
	h, err := New(Options{Meta: e.meta, Blobs: e.blobs, Authorizer: AllowAll{}, Logger: quiet, Repositories: []config.Repository{
		{Name: "private", Format: config.FormatNPM, Type: config.TypeProxy, Proxy: &config.Proxy{URL: e.up.URL + "/registry/", PasswordFile: pw}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/npm/private/p", "/npm/private/p/-/p-1.0.0.tgz"} {
		w := httptestDo(h, "GET", path)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body)
		}
		e.up.mu.Lock()
		got := e.up.auth
		e.up.mu.Unlock()
		if got != "Bearer upstream-token" {
			t.Errorf("GET %s sent Authorization %q", path, got)
		}
	}
}

// TestRewritePackument checks the streaming rewriter on documents of
// every shape it must keep: fields after versions, empty and null
// versions, and escapes.
func TestRewritePackument(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"name":"a","versions":{"1.0.0":{"dist":{"tarball":"https://up/a.tgz","shasum":"x"},"v":"<"}},"time":{}}`,
			`{"name":"a","versions":{"1.0.0":{"dist":{"tarball":"B/a/-/a-1.0.0.tgz","shasum":"x"},"v":"<"}},"time":{}}`},
		{`{"versions":{},"name":"a"}`, `{"versions":{},"name":"a"}`},
		{`{"versions":null}`, `{"versions":null}`},
		{` { "name" : "a" } `, `{"name":"a"}`},
		{`{"versions":{"1":{"dist":"odd"}}}`, `{"versions":{"1":{"dist":"odd"}}}`},
	} {
		var out bytes.Buffer
		if err := rewritePackument(&out, strings.NewReader(tc.in), "a", "B/"); err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if out.String() != tc.want {
			t.Errorf("%s: got\n%s\nwant\n%s", tc.in, out.String(), tc.want)
		}
	}
	for _, bad := range []string{``, `[]`, `{"versions":[]}`, `{"versions":{"1":2}}`, `{"a":1} {}`, `{"a":`} {
		if err := rewritePackument(&bytes.Buffer{}, strings.NewReader(bad), "a", "B/"); err == nil {
			t.Errorf("%q rewrites", bad)
		}
	}
}

func TestParseIntegrity(t *testing.T) {
	s512, s1 := parseIntegrity("sha1-" + "AAAAAAAAAAAAAAAAAAAAAAAAAAA=" + " sha512-" + strings.Repeat("A", 86) + "==?opt")
	if len(s512) != 64 || len(s1) != 20 {
		t.Errorf("sha512 %d bytes, sha1 %d", len(s512), len(s1))
	}
	if a, b := parseIntegrity("md5-xyz sha512-short"); a != nil || b != nil {
		t.Error("an unusable integrity parsed")
	}
}

func TestVersionIn(t *testing.T) {
	doc := `{"versions":{"1.0.0":{"v":1},"2.0.0":{"v":2}},"dist-tags":{"latest":"2.0.0","1.0.0":"2.0.0"}}`
	for spec, want := range map[string]string{"latest": `{"v":2}`, "1.0.0": `{"v":1}`, "3.0.0": ""} {
		got, err := versionIn(strings.NewReader(doc), spec)
		if err != nil || string(got) != want {
			t.Errorf("%s: %s, %v", spec, got, err)
		}
	}
}

// httptestDo serves a request of h directly.
func httptestDo(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}
