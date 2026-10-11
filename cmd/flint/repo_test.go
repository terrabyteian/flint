package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/gc/gctest"
	"github.com/terrabyteian/flint/internal/meta"
)

// TestRepositoryCore runs the repository core through flint serve's
// wiring: every format is served only under its own path, absolute URLs
// in served metadata use publicURL, a virtual repository's member filters
// keep an excluded upstream name out and its publishTo member receives
// uploads, and after OCI, PyPI, generic files, auth, and
// garbage-collection records are written, every key flint wrote is under
// a prefix registered with the garbage collector.
func TestRepositoryCore(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dl/tool.sh" {
			io.WriteString(w, "#!/bin/sh\n")
			return
		}
		project, ok := strings.CutPrefix(r.URL.Path, "/simple/")
		if !ok || (project != "acme-lib/" && project != "requests/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimSuffix(project, "/")
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<!DOCTYPE html><html><body><a href="/files/`+name+`-1.0.tar.gz">`+name+`-1.0.tar.gz</a></body></html>`)
	}))
	defer up.Close()
	pwFile := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(pwFile, []byte("admin-password-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := fsys.NewMem()
	store, err := meta.Open("/data/meta", meta.Options{FS: m, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	blobs, err := blob.NewFS("/data", blob.Options{FS: m})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(`{"dataDir": "/data", "publicURL": "https://flint.example.com/",
		"auth": {"bootstrapAdmin": {"passwordFile": "` + pwFile + `"}},
		"repositories": [
			{"name": "docker-local", "format": "oci", "type": "hosted"},
			{"name": "pypi-local", "format": "pypi", "type": "hosted"},
			{"name": "pypi-remote", "format": "pypi", "type": "proxy", "proxy": {"url": "` + up.URL + `/simple/"}},
			{"name": "pypi-all", "format": "pypi", "type": "virtual", "virtual": {"publishTo": "pypi-local",
				"members": ["pypi-local", {"name": "pypi-remote", "exclude": ["acme-*"]}]}},
			{"name": "files", "format": "generic", "type": "hosted"},
			{"name": "files-remote", "format": "generic", "type": "proxy", "proxy": {"url": "` + up.URL + `/dl/"}},
			{"name": "files-all", "format": "generic", "type": "virtual", "virtual": {"publishTo": "files",
				"members": ["files", "files-remote"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	a, err := newServer(context.Background(), cfg, slog.New(slog.DiscardHandler), m, store, blobs)
	if err != nil {
		t.Fatal(err)
	}
	defer a.audit.Close()
	defer a.gc.Close()
	h := a.srv.Handler()
	call := func(method, path string, body io.Reader, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, body)
		r.SetBasicAuth("admin", "admin-password-123")
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	expect := func(method, path string, body io.Reader, contentType string, status int) *httptest.ResponseRecorder {
		t.Helper()
		w := call(method, path, body, contentType)
		if w.Code != status {
			t.Fatalf("%s %s = %d %s, want %d", method, path, w.Code, w.Body, status)
		}
		return w
	}

	// OCI records.
	img := newRegistryImage("core", "layer")
	for _, b := range img.blobs {
		expect("POST", "/v2/docker-local/app/blobs/uploads/?digest="+sha(b), strings.NewReader(string(b)), "", http.StatusCreated)
	}
	expect("PUT", "/v2/docker-local/app/manifests/1", strings.NewReader(string(img.manifest)),
		"application/vnd.oci.image.manifest.v1+json", http.StatusCreated)

	// A repository is served only under its own format's path.
	expect("GET", "/pypi/docker-local/simple/", nil, "", http.StatusNotFound)
	expect("GET", "/v2/pypi-local/app/tags/list", nil, "", http.StatusNotFound)

	// An upload to the virtual repository goes to its publishTo member.
	_, body, ct := pypiWheel("1.0", "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n")
	expect("POST", "/pypi/pypi-all/legacy/", strings.NewReader(string(body)), ct, http.StatusOK)
	expect("GET", "/pypi/pypi-local/simple/pkg/", nil, "", http.StatusOK)

	// The JSON API's absolute URLs use the public URL.
	var doc struct {
		URLs []struct {
			URL string `json:"url"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(expect("GET", "/pypi/pypi-all/pypi/pkg/json", nil, "", http.StatusOK).Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	const want = "https://flint.example.com/pypi/pypi-all/files/pkg/pkg-1.0-py3-none-any.whl"
	if len(doc.URLs) != 1 || doc.URLs[0].URL != want {
		t.Errorf("JSON API URLs %+v, want %s", doc.URLs, want)
	}

	// The filter keeps the upstream's acme-lib out of the virtual
	// repository; the proxy itself still serves it, and other names come
	// through.
	expect("GET", "/pypi/pypi-all/simple/acme-lib/", nil, "", http.StatusNotFound)
	expect("GET", "/pypi/pypi-remote/simple/acme-lib/", nil, "", http.StatusOK)
	expect("GET", "/pypi/pypi-all/simple/requests/", nil, "", http.StatusOK)

	// A deleted file leaves a tombstone, and its name cannot be used again.
	expect("DELETE", "/api/v1/pypi/pypi-local/projects/pkg/files/pkg-1.0-py3-none-any.whl", nil, "", http.StatusOK)
	if w := call("POST", "/pypi/pypi-local/legacy/", strings.NewReader(string(body)), ct); w.Code < 400 {
		t.Errorf("re-upload after delete = %d %s", w.Code, w.Body)
	}

	// Generic files: an upload through the virtual repository goes to its
	// publishTo member, a proxied file comes through it, and a deleted
	// file leaves a tombstone.
	expect("PUT", "/generic/files-all/dir/a.txt", strings.NewReader("a"), "", http.StatusCreated)
	expect("GET", "/generic/files/dir/a.txt", nil, "", http.StatusOK)
	expect("GET", "/generic/files-all/tool.sh", nil, "", http.StatusOK)
	expect("PUT", "/generic/files/dir/b.txt", strings.NewReader("b"), "", http.StatusCreated)
	expect("DELETE", "/generic/files/dir/b.txt", nil, "", http.StatusNoContent)
	expect("GET", "/generic/docker-local/dir/a.txt", nil, "", http.StatusNotFound)
	expect("GET", "/v2/files/dir/tags/list", nil, "", http.StatusNotFound)
	// curl and wget get a Basic challenge.
	anon := httptest.NewRecorder()
	h.ServeHTTP(anon, httptest.NewRequest("GET", "/generic/files/dir/a.txt", nil))
	if anon.Code != http.StatusUnauthorized || anon.Header().Get("WWW-Authenticate") != `Basic realm="flint"` {
		t.Errorf("anonymous generic download = %d, WWW-Authenticate %q", anon.Code, anon.Header().Get("WWW-Authenticate"))
	}

	// Auth records.
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(expect("POST", "/api/v1/tokens", strings.NewReader(`{"name": "ci"}`), "application/json",
		http.StatusCreated).Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	// An API token works as a bearer token, as curl -H and scripts send it.
	r := httptest.NewRequest("GET", "/generic/files/dir/a.txt", nil)
	r.Header.Set("Authorization", "Bearer "+tok.Token)
	bearer := httptest.NewRecorder()
	h.ServeHTTP(bearer, r)
	if bearer.Code != http.StatusOK || bearer.Body.String() != "a" {
		t.Errorf("generic download with a bearer token = %d %s", bearer.Code, bearer.Body)
	}

	// Garbage-collection records: a run's report.
	if rep, err := a.gc.Run(context.Background(), gc.RunOptions{}); err != nil || rep.State != gc.StateSucceeded {
		t.Fatalf("gc run = %+v, %v", rep, err)
	}
	gctest.CheckStored(t, store, blobs, gcMarkers()...)
}
