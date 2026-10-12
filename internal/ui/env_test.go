package ui

import (
	"context"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/auth"
	"github.com/terrabyteian/flint/internal/backup"
	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/server"
)

var quiet = slog.New(slog.DiscardHandler)

// testConfig declares a repository of every kind the UI browses:
//
//	oci-local     hosted OCI; alice has write
//	public        hosted OCI with anonymous pull
//	oci-all       virtual OCI of oci-local and secret; alice has read on it only
//	pypi-local    hosted PyPI; alice has read
//	pypi-remote   proxy PyPI
//	npm-local     hosted npm, maven-local hosted Maven, cargo-local hosted Cargo
//	files         hosted generic; alice has read
//	go-remote     proxy Go, whose cache alice may read
//	secret        hosted OCI nobody but administrators reads
//	broken        hosted generic whose view fails
const testConfig = `{
  "dataDir": "/data",
  "repositories": [
    {"name": "oci-local", "format": "oci", "type": "hosted", "helmIndex": true},
    {"name": "public", "format": "oci", "type": "hosted", "anonymousPull": true},
    {"name": "secret", "format": "oci", "type": "hosted"},
    {"name": "oci-all", "format": "oci", "type": "virtual", "virtual": {"members": ["oci-local", "secret"], "publishTo": "oci-local"}},
    {"name": "pypi-local", "format": "pypi", "type": "hosted"},
    {"name": "pypi-remote", "format": "pypi", "type": "proxy", "proxy": {"url": "https://pypi.org/simple/"}},
    {"name": "npm-local", "format": "npm", "type": "hosted"},
    {"name": "maven-local", "format": "maven", "type": "hosted"},
    {"name": "cargo-local", "format": "cargo", "type": "hosted"},
    {"name": "files", "format": "generic", "type": "hosted"},
    {"name": "broken", "format": "generic", "type": "hosted"},
    {"name": "go-remote", "format": "go", "type": "proxy", "proxy": {"url": "https://proxy.golang.org"}}
  ],
  "auth": {
    "sessionTTL": "1h",
    "permissions": [
      {"repositories": ["oci-local"], "role": "write", "users": ["alice"]},
      {"repositories": ["oci-all", "pypi-*", "npm-local", "maven-local", "cargo-local", "files", "go-remote", "broken"], "role": "read", "users": ["alice"]}
    ]
  }
}`

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeImages is a browse.Images with one image, team/app, in oci-local
// and public.
type fakeImages struct{}

const (
	indexDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	amdDigest   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	sigDigest   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	layerDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

func (fakeImages) ListImages(repo string, q browse.Query) ([]browse.Image, bool, error) {
	if repo != "oci-local" && repo != "public" && repo != "secret" {
		return nil, false, browse.ErrNotFound
	}
	var out []browse.Image
	for _, n := range []string{"team/app", "tools/web"} {
		if q.Match(n) && n > q.After {
			out = append(out, browse.Image{Name: n, Tags: 1, Manifests: 3})
		}
	}
	if q.Limit > 0 && len(out) > q.Limit {
		return out[:q.Limit], true, nil
	}
	return out, false, nil
}

func (fakeImages) Image(repo, name string) (*browse.ImageDetail, error) {
	if name != "team/app" {
		return nil, browse.ErrNotFound
	}
	return &browse.ImageDetail{Name: name, Tags: []browse.ImageTag{{Name: "v1", Digest: indexDigest}},
		Manifests: []browse.ManifestSummary{
			{Digest: indexDigest, MediaType: "application/vnd.oci.image.index.v1+json", Index: true, Tags: []string{"v1"}},
			{Digest: amdDigest, MediaType: "application/vnd.oci.image.manifest.v1+json", Size: 500},
			{Digest: sigDigest, ArtifactType: "application/vnd.dev.cosign.artifact.sig.v1+json", Subject: indexDigest},
		}}, nil
}

func (fakeImages) Manifest(_ context.Context, repo, name, digest string) (*browse.Manifest, error) {
	switch {
	case name != "team/app":
		return nil, browse.ErrNotFound
	case digest == indexDigest:
		return &browse.Manifest{
			ManifestSummary: browse.ManifestSummary{Digest: indexDigest, MediaType: "application/vnd.oci.image.index.v1+json",
				Index: true, Tags: []string{"v1"}},
			Manifests: []browse.Descriptor{{Digest: amdDigest, Platform: "linux/amd64", Size: 500, Stored: true},
				{Digest: layerDigest, Platform: "linux/s390x"}},
			Referrers: []browse.Descriptor{{Digest: sigDigest, ArtifactType: "application/vnd.dev.cosign.artifact.sig.v1+json"}},
		}, nil
	case digest == amdDigest:
		return &browse.Manifest{
			ManifestSummary: browse.ManifestSummary{Digest: amdDigest, MediaType: "application/vnd.oci.image.manifest.v1+json"},
			Config:          &browse.Descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: amdDigest, Size: 10},
			Layers:          []browse.Descriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: layerDigest, Size: 3 << 20}},
		}, nil
	}
	return nil, browse.ErrNotFound
}

// fakePackages is a browse.Packages with the package "acme-lib".
type fakePackages struct{ format string }

func (f fakePackages) ListPackages(repo string, q browse.Query) ([]browse.Package, bool, error) {
	if !strings.HasPrefix(repo, f.format) {
		return nil, false, browse.ErrNotFound
	}
	return []browse.Package{{Name: "acme-lib", Latest: "2.0", Versions: 2, Summary: "The acme library"}}, false, nil
}

func (f fakePackages) Package(_ context.Context, repo, name string) (*browse.PackageDetail, error) {
	if name != "acme-lib" && name != "@acme/lib" {
		return nil, browse.ErrNotFound
	}
	return &browse.PackageDetail{Name: name, Summary: "The acme library", Tags: []browse.Tag{{Name: "latest", Version: "2.0"}},
		Versions: []browse.Version{
			{Version: "2.0", Files: []browse.File{{Name: "acme_lib-2.0.tar.gz", Size: 2048, Digest: layerDigest, URL: "/pypi/x/files/acme-lib/acme_lib-2.0.tar.gz"}}},
			{Version: "1.0", Notes: []string{"yanked: broken"}},
		}}, nil
}

// fakeFiles is a browse.Files with a directory "tools/" and a file.
type fakeFiles struct{}

var errBroken = errors.New("the view is broken")

func (fakeFiles) ListFiles(repo, dir string, q browse.Query) ([]browse.Entry, bool, error) {
	switch {
	case repo == "broken":
		return nil, false, errBroken
	case dir == "":
		return []browse.Entry{{Name: "tools/", Dir: true}, {Name: "notes.txt", Size: 5, Digest: layerDigest, URL: "/generic/files/notes.txt"}}, false, nil
	case dir == "tools/":
		return []browse.Entry{{Name: "tool-1.0.tar.gz", Size: 12, Digest: layerDigest, URL: "/generic/files/tools/tool-1.0.tar.gz"}}, false, nil
	}
	return nil, false, browse.ErrNotFound
}

// env is a UI over an auth service with an in-memory store, served by a
// test server, with the users root (an administrator), alice, and bob.
type env struct {
	t     *testing.T
	auth  *auth.Service
	h     *Handler
	srv   *httptest.Server
	clock *clock
	cfg   *config.Config
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	m := fsys.NewMem()
	store, err := meta.Open("/data/meta", meta.Options{FS: m, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	e := &env{t: t, cfg: cfg, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}}
	e.auth, err = auth.New(auth.Options{Store: store, KeyDir: "/data/auth", FS: m, Config: cfg, Logger: quiet,
		Now: e.clock.Now, PasswordIterations: 1000})
	if err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(t.TempDir(), "root")
	if err := os.WriteFile(pw, []byte("root-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.Bootstrap(context.Background(), "root", pw); err != nil {
		t.Fatal(err)
	}
	e.h, err = New(Options{
		Auth: e.auth, Config: cfg, Images: fakeImages{},
		Packages: map[string]browse.Packages{config.FormatPyPI: fakePackages{"pypi"}, config.FormatNPM: fakePackages{"npm"},
			config.FormatMaven: fakePackages{"maven"}, config.FormatCargo: fakePackages{"cargo"}},
		Files: map[string]browse.Files{config.FormatGeneric: fakeFiles{}},
		Cache: fakeFiles{},
		Status: Status{
			GC: func() gc.Status {
				return gc.Status{GracePeriod: "24h0m0s", Last: &gc.Report{State: "succeeded", Actor: "system"}}
			},
			Backup: func() (backup.Status, bool) {
				return backup.Status{Directory: "/backups"}, true
			},
			Space: fakeSpace{},
		},
		Version: "test",
		Logger:  quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The sign-in endpoints and the admin API are served beside the UI,
	// as flint serves them.
	srv, err := server.New(server.Options{Addr: "127.0.0.1:0", Logger: quiet, Metrics: metrics.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	e.auth.Register(srv)
	e.h.Register(srv)
	e.srv = httptest.NewServer(srv.Handler())
	t.Cleanup(e.srv.Close)
	e.addUser("alice", "alice-password")
	e.addUser("bob", "bob-password")
	return e
}

type fakeSpace struct{}

func (fakeSpace) Free() uint64   { return 5 << 30 }
func (fakeSpace) Pressure() bool { return true }

// addUser creates a user through the admin API, as root.
func (e *env) addUser(name, password string) {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/users",
		strings.NewReader(`{"name": "`+name+`", "password": "`+password+`"}`))
	req.SetBasicAuth("root", "root-password")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		e.t.Fatalf("creating %s: %d", name, resp.StatusCode)
	}
}

// browser is a client with its own cookies that does not follow
// redirects.
type browser struct {
	e      *env
	client *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{e: e, client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

// response is a response with its body read.
type response struct {
	*http.Response
	body string
}

func (b *browser) do(method, path string, form url.Values, hdr ...string) response {
	b.e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, b.e.srv.URL+path, body)
	if err != nil {
		b.e.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	bb, _ := io.ReadAll(resp.Body)
	return response{Response: resp, body: string(bb)}
}

func (b *browser) get(path string) response { return b.do("GET", path, nil) }

// expect fetches path and checks the status.
func (b *browser) expect(path string, status int) response {
	b.e.t.Helper()
	r := b.get(path)
	if r.StatusCode != status {
		b.e.t.Fatalf("GET %s: %d, want %d\n%s", path, r.StatusCode, status, r.body)
	}
	return r
}

// post submits a form.
func (b *browser) post(path string, form url.Values) response {
	b.e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	return b.do("POST", path, form)
}

// signIn signs a user in on the sign-in page.
func (b *browser) signIn(user, password string) {
	b.e.t.Helper()
	r := b.post(auth.SignInPath, url.Values{"username": {user}, "password": {password}, "return": {"/ui/"}})
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/ui/" {
		b.e.t.Fatalf("signing in %s: %d to %q\n%s", user, r.StatusCode, r.Header.Get("Location"), r.body)
	}
}

func (r response) has(t *testing.T, ss ...string) {
	t.Helper()
	for _, s := range ss {
		if !strings.Contains(r.body, s) && !strings.Contains(html.UnescapeString(r.body), s) {
			t.Errorf("%s: the page lacks %q", r.Request.URL.Path, s)
		}
	}
}

func (r response) lacks(t *testing.T, ss ...string) {
	t.Helper()
	for _, s := range ss {
		if strings.Contains(r.body, s) || strings.Contains(html.UnescapeString(r.body), s) {
			t.Errorf("%s: the page shows %q", r.Request.URL.Path, s)
		}
	}
}
