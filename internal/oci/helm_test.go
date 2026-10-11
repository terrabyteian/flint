package oci

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
)

// chart is a Helm chart as helm push stores it.
type chart struct {
	config, tgz, prov []byte
	manifest          []byte
	digest            blob.Digest
}

// newChart builds the manifest helm push writes for chart name at
// version, with a provenance layer if prov is set. extra adds metadata.
func newChart(name, version string, prov bool, extra map[string]any) chart {
	md := map[string]any{"apiVersion": "v2", "name": name, "version": version, "description": "the " + name + " chart"}
	for k, v := range extra {
		md[k] = v
	}
	c := chart{config: mustJSON(md), tgz: []byte("chart archive " + name + " " + version)}
	layers := []any{desc(mtHelmChart, c.tgz)}
	if prov {
		c.prov = []byte("-----BEGIN PGP SIGNED MESSAGE-----\n" + name + " " + version)
		layers = append(layers, desc(mtHelmProvenance, c.prov))
	}
	c.manifest = mustJSON(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIManifest,
		"config":        desc(mtHelmConfig, c.config),
		"layers":        layers,
	})
	c.digest = blob.FromBytes(c.manifest)
	return c
}

// pushChart pushes a chart to name, tagged as helm push tags it.
func (e *env) pushChart(name string, c chart, tags ...string) {
	e.t.Helper()
	e.pushBlob(name, c.config)
	e.pushBlob(name, c.tgz)
	if c.prov != nil {
		e.pushBlob(name, c.prov)
	}
	var md struct{ Version string }
	json.Unmarshal(c.config, &md)
	if len(tags) == 0 {
		tags = []string{strings.ReplaceAll(md.Version, "+", "_")}
	}
	for _, tag := range tags {
		w := e.do("PUT", "/v2/"+name+"/manifests/"+tag, c.manifest, "Content-Type", mtOCIManifest)
		want(e.t, w, http.StatusCreated, "")
	}
}

// helm serves one request to the Helm view.
func (e *env) helm(method, path string, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	mux := http.NewServeMux()
	e.h.Register(mux)
	r := httptest.NewRequest(method, path, nil)
	for i := 0; i < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// helmIndex is the part of an index the tests read.
type helmIndex struct {
	APIVersion string                      `json:"apiVersion"`
	Entries    map[string][]map[string]any `json:"entries"`
	Generated  time.Time                   `json:"generated"`
}

func (e *env) helmIndex(path string) (helmIndex, string) {
	e.t.Helper()
	w := e.helm("GET", path)
	if w.Code != http.StatusOK {
		e.t.Fatalf("GET %s = %d %s", path, w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		e.t.Errorf("index Content-Type = %q", ct)
	}
	var idx helmIndex
	if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil {
		e.t.Fatalf("index %s: %v", w.Body, err)
	}
	return idx, w.Header().Get("ETag")
}

func versions(idx helmIndex, name string) []string {
	var vs []string
	for _, cv := range idx.Entries[name] {
		vs = append(vs, cv["version"].(string))
	}
	return vs
}

func TestHelmIndex(t *testing.T) {
	e := newEnv(t)
	app := map[string]chart{}
	for _, v := range []string{"1.0.0", "1.10.0", "1.2.0-rc.1", "2.0.0+build.1", "1.2.0"} {
		app[v] = newChart("app", v, false, map[string]any{"appVersion": "v" + v, "keywords": []string{"a", "b"}})
		e.pushChart("charts/app", app[v])
	}
	web := newChart("web", "0.1.0", true, nil)
	e.pushChart("charts/web", web, "0.1.0", "stable") // a second tag does not list it twice
	e.pushImage("charts/app", "latest", newImage("not a chart", nil))
	e.pushChart("charts/other", newChart("app", "9.9.9", false, nil)) // named unlike its image
	e.pushChart("charts/team/api", newChart("api", "1.0.0", false, nil))
	e.pushChart("charts/app", newChart("app", "7.0.0", false, nil), "seven") // tagged unlike its version

	idx, etag := e.helmIndex("/helm/charts/index.yaml")
	if idx.APIVersion != "v1" || !idx.Generated.Equal(e.now) || etag == "" {
		t.Errorf("index header = %q %v, ETag %q", idx.APIVersion, idx.Generated, etag)
	}
	if got := versions(idx, "app"); !slices.Equal(got, []string{"1.0.0", "1.10.0", "1.2.0", "1.2.0-rc.1", "2.0.0+build.1"}) {
		t.Errorf("app versions = %v", got)
	}
	if len(idx.Entries) != 2 || len(idx.Entries["web"]) != 1 {
		t.Errorf("entries = %v", idx.Entries)
	}
	cv := idx.Entries["app"][1]
	wantEntry := map[string]any{
		"apiVersion": "v2", "name": "app", "version": "1.10.0", "description": "the app chart",
		"appVersion": "v1.10.0", "keywords": []any{"a", "b"},
		"urls":    []any{"charts/app-1.10.0.tgz"},
		"digest":  blob.FromBytes(app["1.10.0"].tgz).Hex(),
		"created": e.now.Format(time.RFC3339),
	}
	if !jsonEqual(cv, wantEntry) {
		t.Errorf("entry = %v, want %v", cv, wantEntry)
	}

	sub, _ := e.helmIndex("/helm/charts/team/index.yaml")
	if got := versions(sub, "api"); len(sub.Entries) != 1 || !slices.Equal(got, []string{"1.0.0"}) {
		t.Errorf("charts/team entries = %v", sub.Entries)
	}

	// Chart and provenance files.
	for _, c := range []struct {
		path string
		body []byte
		ct   string
	}{
		{"/helm/charts/charts/app-2.0.0+build.1.tgz", app["2.0.0+build.1"].tgz, "application/gzip"},
		{"/helm/charts/charts/web-0.1.0.tgz", web.tgz, "application/gzip"},
		{"/helm/charts/charts/web-0.1.0.tgz.prov", web.prov, "application/octet-stream"},
		{"/helm/charts/team/charts/api-1.0.0.tgz", newChart("api", "1.0.0", false, nil).tgz, "application/gzip"},
	} {
		w := e.helm("GET", c.path)
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), c.body) || w.Header().Get("Content-Type") != c.ct ||
			w.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("GET %s = %d %q %v", c.path, w.Code, w.Body, w.Header())
		}
		w = e.helm("HEAD", c.path)
		if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") != itoa(len(c.body)) {
			t.Errorf("HEAD %s = %d %v", c.path, w.Code, w.Header())
		}
	}
	w := e.helm("GET", "/helm/charts/charts/web-0.1.0.tgz", "Range", "bytes=6-")
	if w.Code != http.StatusPartialContent || w.Body.String() != string(web.tgz[6:]) {
		t.Errorf("range request = %d %q", w.Code, w.Body)
	}
	for _, p := range []string{
		"/helm/charts/charts/app-1.0.0.tgz.prov", // no provenance pushed
		"/helm/charts/charts/app-7.0.0.tgz",
		"/helm/charts/charts/app-9.9.9.tgz",
		"/helm/charts/charts/api-1.0.0.tgz", // in charts/team
		"/helm/charts/team/charts/app-1.0.0.tgz",
		"/helm/charts/charts/app-2.0.0_build.1.tgz",
	} {
		if w := e.helm("GET", p); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, w.Code)
		}
	}
}

func jsonEqual(a, b any) bool {
	return bytes.Equal(mustJSON(a), mustJSON(b))
}

func itoa(n int) string { return strings.TrimSpace(string(mustJSON(n))) }

func TestHelmIndexCaching(t *testing.T) {
	e := newEnv(t)
	e.pushChart("charts/app", newChart("app", "1.0.0", false, nil))
	_, etag := e.helmIndex("/helm/charts/index.yaml")
	view := e.h.helmViews["charts\x00"]
	if view == nil {
		t.Fatal("the view was not cached")
	}

	// Unchanged tags serve the cached view, and a client that has it
	// gets 304.
	e.now = e.now.Add(time.Hour)
	if _, again := e.helmIndex("/helm/charts/index.yaml"); again != etag || e.h.helmViews["charts\x00"] != view {
		t.Errorf("an unchanged view was rebuilt: ETag %s, then %s", etag, again)
	}
	if w := e.helm("GET", "/helm/charts/index.yaml", "If-None-Match", etag); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Errorf("conditional GET = %d %q", w.Code, w.Body)
	}
	// A push elsewhere does not change the view.
	e.pushImage("hosted/app", "1", newImage("x", nil))
	e.pushChart("charts/team/api", newChart("api", "1.0.0", false, nil))
	if _, again := e.helmIndex("/helm/charts/index.yaml"); again != etag || e.h.helmViews["charts\x00"] != view {
		t.Error("a push outside the view rebuilt it")
	}

	// A new version changes it.
	e.pushChart("charts/app", newChart("app", "1.1.0", false, nil))
	idx, etag2 := e.helmIndex("/helm/charts/index.yaml")
	if etag2 == etag || !slices.Equal(versions(idx, "app"), []string{"1.0.0", "1.1.0"}) {
		t.Errorf("after a push: ETag %s, versions %v", etag2, versions(idx, "app"))
	}
	if w := e.helm("GET", "/helm/charts/index.yaml", "If-None-Match", etag); w.Code != http.StatusOK {
		t.Errorf("conditional GET with the old ETag = %d", w.Code)
	}
	if created := idx.Entries["app"][1]["created"]; created != e.now.Format(time.RFC3339) {
		t.Errorf("created = %v, want the push time %v", created, e.now)
	}

	// So does deleting one, and the old chart file goes with it. The
	// view has the tags it first had, so it has their ETag again.
	want(t, e.do("DELETE", "/v2/charts/app/manifests/1.1.0", nil), http.StatusAccepted, "")
	idx, etag3 := e.helmIndex("/helm/charts/index.yaml")
	if etag3 != etag || !slices.Equal(versions(idx, "app"), []string{"1.0.0"}) {
		t.Errorf("after a delete: ETag %s, versions %v", etag3, versions(idx, "app"))
	}
	if w := e.helm("GET", "/helm/charts/charts/app-1.1.0.tgz"); w.Code != http.StatusNotFound {
		t.Errorf("deleted chart = %d", w.Code)
	}

	// Re-pushing a version to a repository with mutable tags replaces it.
	changed := newChart("app", "1.0.0", false, map[string]any{"description": "changed"})
	e.pushChart("charts/app", changed)
	idx, _ = e.helmIndex("/helm/charts/index.yaml")
	if cv := idx.Entries["app"][0]; cv["description"] != "changed" || cv["digest"] != blob.FromBytes(changed.tgz).Hex() {
		t.Errorf("re-pushed entry = %v", cv)
	}
	if w := e.helm("GET", "/helm/charts/charts/app-1.0.0.tgz"); !bytes.Equal(w.Body.Bytes(), changed.tgz) {
		t.Errorf("re-pushed chart = %q", w.Body)
	}

	// An empty view is served but not kept.
	empty, _ := e.helmIndex("/helm/charts/nothing/here/index.yaml")
	if empty.APIVersion != "v1" || empty.Entries == nil || len(empty.Entries) != 0 {
		t.Errorf("empty index = %+v", empty)
	}
	if _, ok := e.h.helmViews["charts\x00nothing/here"]; ok || len(e.h.helmViews) != 1 {
		t.Errorf("cached views: %v", e.h.helmViews)
	}
}

func TestHelmImmutable(t *testing.T) {
	e := newEnv(t)
	c := newChart("app", "1.0.0", false, nil)
	e.pushChart("frozen/app", c)
	idx, _ := e.helmIndex("/helm/frozen/index.yaml")
	if !slices.Equal(versions(idx, "app"), []string{"1.0.0"}) {
		t.Errorf("versions = %v", versions(idx, "app"))
	}
	w := e.helm("GET", "/helm/frozen/charts/app-1.0.0.tgz")
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "max-age=31536000" {
		t.Errorf("immutable chart = %d %v", w.Code, w.Header())
	}
	other := newChart("app", "1.0.0", false, map[string]any{"description": "other"})
	e.pushBlob("frozen/app", other.config)
	e.pushBlob("frozen/app", other.tgz)
	want(t, e.do("PUT", "/v2/frozen/app/manifests/1.0.0", other.manifest, "Content-Type", mtOCIManifest), http.StatusConflict, codeDenied)

	// Pushing the same chart again keeps its push time, after the view
	// is rebuilt too.
	pushed := e.now
	e.now = e.now.Add(time.Hour)
	e.pushChart("frozen/app", c)
	e.pushChart("frozen/app", newChart("app", "1.1.0", false, nil))
	idx, _ = e.helmIndex("/helm/frozen/index.yaml")
	if created := idx.Entries["app"][0]["created"]; created != pushed.Format(time.RFC3339) {
		t.Errorf("created = %v after a re-push, want %v", created, pushed)
	}
}

// TestHelmChartReadOnce checks that a rebuilt view reads only the charts
// it has not read before.
func TestHelmChartReadOnce(t *testing.T) {
	e := newEnv(t)
	c := newChart("app", "1.0.0", false, nil)
	e.pushChart("charts/app", c)
	e.helmIndex("/helm/charts/index.yaml")
	// Losing the blobs no longer matters: the chart was read.
	if err := e.blobs.Delete(t.Context(), blob.FromBytes(c.config)); err != nil {
		t.Fatal(err)
	}
	e.pushChart("charts/app", newChart("app", "1.1.0", false, nil))
	idx, _ := e.helmIndex("/helm/charts/index.yaml")
	if !slices.Equal(versions(idx, "app"), []string{"1.0.0", "1.1.0"}) {
		t.Errorf("versions = %v", versions(idx, "app"))
	}
}

// TestHelmChartMissing checks that a chart whose blob is missing is left
// out of the view but read again when the view is rebuilt.
func TestHelmChartMissing(t *testing.T) {
	e := newEnv(t)
	c := newChart("app", "1.0.0", false, nil)
	e.pushChart("charts/app", c)
	if err := e.blobs.Delete(t.Context(), blob.FromBytes(c.config)); err != nil {
		t.Fatal(err)
	}
	e.pushChart("charts/app", newChart("app", "1.1.0", false, nil))
	if idx, _ := e.helmIndex("/helm/charts/index.yaml"); !slices.Equal(versions(idx, "app"), []string{"1.1.0"}) {
		t.Errorf("versions with a blob missing = %v", versions(idx, "app"))
	}
	e.pushChart("charts/app", c)
	if idx, _ := e.helmIndex("/helm/charts/index.yaml"); !slices.Equal(versions(idx, "app"), []string{"1.0.0", "1.1.0"}) {
		t.Errorf("versions after the chart was pushed again = %v", versions(idx, "app"))
	}
}

// basicAuth adds the BasicAuthorizer extension to testAuth.
type basicAuth struct {
	testAuth
	basic []authCall
}

func (a *basicAuth) AuthorizeBasic(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool {
	a.basic = append(a.basic, authCall{repo, strings.Join(actions, ",")})
	if repo == "charts/secret" {
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func TestHelmAuthorization(t *testing.T) {
	e := newEnv(t)
	e.pushChart("charts/app", newChart("app", "1.0.0", false, nil))
	e.auth.reset()

	// With an Authorizer that has no Basic variant, the view uses Authorize.
	e.auth.deny = func(repo string, _ []string) bool { return repo == "charts" }
	if w := e.helm("GET", "/helm/charts/index.yaml"); w.Code != http.StatusUnauthorized {
		t.Errorf("denied index = %d", w.Code)
	}
	if w := e.helm("GET", "/helm/charts/charts/app-1.0.0.tgz"); w.Code != http.StatusUnauthorized {
		t.Errorf("denied chart = %d", w.Code)
	}
	if calls := e.auth.reset(); !slices.Equal(calls, []authCall{{"charts", "pull"}, {"charts", "pull"}}) {
		t.Errorf("Authorize calls = %v", calls)
	}

	ba := &basicAuth{}
	e.h.auth = ba
	e.helm("GET", "/helm/charts/team/index.yaml")
	e.helm("GET", "/helm/charts/team/charts/api-1.0.0.tgz")
	if w := e.helm("GET", "/helm/charts/secret/index.yaml"); w.Code != http.StatusUnauthorized ||
		w.Header().Get("WWW-Authenticate") != `Basic realm="test"` {
		t.Errorf("denied index = %d %v", w.Code, w.Header())
	}
	if !slices.Equal(ba.basic, []authCall{{"charts/team", "pull"}, {"charts/team", "pull"}, {"charts/secret", "pull"}}) ||
		len(ba.calls) != 0 {
		t.Errorf("AuthorizeBasic calls = %v, Authorize calls = %v", ba.basic, ba.calls)
	}

	// Requests that address no view are refused before authorization.
	ba.basic = nil
	for _, p := range []string{"/helm/hosted/index.yaml", "/helm/nope/index.yaml", "/helm/", "/helm/charts/",
		"/helm/charts/app-1.0.0.tgz", "/helm/charts/charts/x.zip", "/helm/charts/Bad/index.yaml"} {
		if w := e.helm("GET", p); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, w.Code)
		}
	}
	if w := e.helm("POST", "/helm/charts/index.yaml"); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST = %d %v", w.Code, w.Header())
	}
	if len(ba.basic) != 0 {
		t.Errorf("AuthorizeBasic calls = %v", ba.basic)
	}
}
