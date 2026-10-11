package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/terrabyteian/flint/internal/meta"
)

// TestGoRepositories runs Go repositories through flint serve's wiring:
// the go command's credentials (basic, or an API token as a bearer token
// from a GOAUTH command) are accepted, a request without them gets the
// Basic challenge, a virtual repository serves its member's modules, and
// garbage collection covers what the proxy cached.
func TestGoRepositories(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("example.com/m@v1.0.0/go.mod")
	io.WriteString(f, "module example.com/m\n")
	zw.Close()
	modZip := buf.Bytes()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.com/m/@v/list":
			io.WriteString(w, "v1.0.0\n")
		case "/example.com/m/@v/v1.0.0.info":
			io.WriteString(w, `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
		case "/example.com/m/@v/v1.0.0.zip":
			w.Write(modZip)
		default:
			http.NotFound(w, r)
		}
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
	// The upstream's modules skip the checksum database, which the test
	// cannot reach.
	cfg, err := config.Parse([]byte(`{"dataDir": "/data",
		"auth": {"bootstrapAdmin": {"passwordFile": "` + pwFile + `"}},
		"repositories": [
			{"name": "goproxy", "format": "go", "type": "proxy", "proxy": {"url": "` + up.URL + `"},
			 "go": {"noSumCheck": ["*"]}},
			{"name": "go-all", "format": "go", "type": "virtual", "anonymousPull": true, "virtual": {"members": ["goproxy"]}}]}`))
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
	call := func(method, path, authz string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		if authz != "" {
			r.Header.Set("Authorization", authz)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin-password-123"))

	w := call("GET", "/go/goproxy/example.com/m/@v/list", "")
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != `Basic realm="flint"` {
		t.Errorf("anonymous request = %d, challenge %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w := call("GET", "/go/goproxy/example.com/m/@v/list", basic); w.Code != http.StatusOK || w.Body.String() != "v1.0.0\n" {
		t.Errorf("list = %d %q", w.Code, w.Body)
	}
	r := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader(`{"name": "goauth"}`))
	r.Header.Set("Authorization", basic)
	tw := httptest.NewRecorder()
	h.ServeHTTP(tw, r)
	var created struct{ Token string }
	if err := json.Unmarshal(tw.Body.Bytes(), &created); err != nil || created.Token == "" {
		t.Fatalf("creating a token = %d %s", tw.Code, tw.Body)
	}
	if w := call("GET", "/go/goproxy/example.com/m/@v/v1.0.0.zip", "Bearer "+created.Token); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), modZip) {
		t.Errorf("zip with a bearer token = %d", w.Code)
	}
	// The virtual repository allows anonymous pulls; its member does not.
	if w := call("GET", "/go/go-all/example.com/m/@v/v1.0.0.zip", ""); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), modZip) {
		t.Errorf("zip through the virtual repository = %d %s", w.Code, w.Body)
	}
	if w := call("GET", "/v2/goproxy/example.com/tags/list", basic); w.Code != http.StatusNotFound {
		t.Errorf("a Go repository under /v2/ = %d", w.Code)
	}

	rep, err := a.gc.Run(context.Background(), gc.RunOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != gc.StateSucceeded {
		t.Errorf("run = %s, refused %q", rep.State, rep.Refused)
	}
}
