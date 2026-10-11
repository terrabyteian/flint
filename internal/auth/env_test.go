package auth

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/server"
)

var quiet = slog.New(slog.DiscardHandler)

// testIterations keeps password hashing fast in tests.
const testIterations = 1000

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

// env is a Service over an in-memory store, served by a real server with
// a protected test route standing in for a format package:
//
//	GET /test/base             Authorize(repo "", no actions)
//	GET /test/{action}/{repo...} Authorize(repo, action), "pull,push" for several
type env struct {
	t     *testing.T
	svc   *Service
	store meta.Store
	fs    *fsys.Mem
	clock *clock
	reg   *metrics.Registry
	srv   *httptest.Server
	cfg   *config.Config
}

const testConfig = `{
  "dataDir": "/data",
  "repositories": [
    {"name": "docker-local", "format": "oci", "type": "hosted"},
    {"name": "public", "format": "oci", "type": "hosted", "anonymousPull": true}
  ],
  "auth": {
    "permissions": [
      {"repositories": ["docker-local"], "role": "write", "groups": ["ci"]},
      {"repositories": ["team-a-*"], "role": "delete", "users": ["alice"]},
      {"repositories": ["docker-local", "public"], "role": "read", "users": ["bob"]}
    ]
  }
}`

func newEnv(t *testing.T, cfgJSON string) *env {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	m := fsys.NewMem()
	store, err := meta.Open("/data/meta", meta.Options{FS: m, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	e := &env{t: t, store: store, fs: m, cfg: cfg, clock: &clock{t: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}}
	e.svc = e.newService()
	return e
}

func (e *env) newService() *Service {
	e.t.Helper()
	e.reg = metrics.NewRegistry()
	svc, err := New(Options{
		Store:              e.store,
		KeyDir:             "/data/auth",
		FS:                 e.fs,
		Config:             e.cfg,
		Logger:             quiet,
		Metrics:            e.reg,
		Now:                e.clock.Now,
		PasswordIterations: testIterations,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return svc
}

// serve starts an HTTP server with the service's routes and the test route.
func (e *env) serve() *httptest.Server {
	e.t.Helper()
	if e.srv != nil {
		return e.srv
	}
	srv, err := server.New(server.Options{Addr: "127.0.0.1:0", Logger: quiet, Metrics: metrics.NewRegistry()})
	if err != nil {
		e.t.Fatal(err)
	}
	e.svc.Register(srv)
	srv.HandleFunc("GET /test/base", func(w http.ResponseWriter, r *http.Request) {
		if e.svc.Authorize(w, r, "") {
			io.WriteString(w, "ok")
		}
	})
	srv.HandleFunc("GET /test/{action}/{repo...}", func(w http.ResponseWriter, r *http.Request) {
		if e.svc.Authorize(w, r, r.PathValue("repo"), strings.Split(r.PathValue("action"), ",")...) {
			io.WriteString(w, "ok")
		}
	})
	e.srv = httptest.NewServer(srv.Handler())
	e.t.Cleanup(e.srv.Close)
	return e.srv
}

func (e *env) addUser(name, password string, admin bool, groups ...string) {
	e.t.Helper()
	if _, err := e.svc.createUser(context.Background(), nil, name, password, admin, groups); err != nil {
		e.t.Fatalf("createUser %s: %v", name, err)
	}
}

// addToken creates a token for a user, as a password-authenticated client.
func (e *env) addToken(owner string, admin bool, expires time.Time, scopes ...Scope) string {
	e.t.Helper()
	p, err := e.principal(owner)
	if err != nil {
		e.t.Fatal(err)
	}
	if len(scopes) == 0 {
		scopes = []Scope{{Repositories: []string{"*"}, Role: RoleAdmin}}
	}
	_, secret, err := e.svc.createToken(context.Background(), p, "test", expires, admin, scopes)
	if err != nil {
		e.t.Fatalf("createToken: %v", err)
	}
	return secret
}

func (e *env) principal(name string) (*Principal, error) {
	u, err := e.svc.getUser(name)
	if err != nil {
		return nil, err
	}
	p := userPrincipal(u)
	p.Password = true
	return p, nil
}

// request is an HTTP request to the test server.
type request struct {
	method, path string
	user, pass   string // basic credentials, if user or pass is set
	bearer       string
	body         string
	form         map[string][]string
}

type response struct {
	status int
	header http.Header
	body   string
}

func (e *env) do(req request) response {
	e.t.Helper()
	srv := e.serve()
	method := req.method
	if method == "" {
		method = "GET"
	}
	var body io.Reader
	if req.body != "" {
		body = strings.NewReader(req.body)
	}
	if req.form != nil {
		vals := make([]string, 0)
		for k, vs := range req.form {
			for _, v := range vs {
				vals = append(vals, urlEscape(k)+"="+urlEscape(v))
			}
		}
		body = strings.NewReader(strings.Join(vals, "&"))
	}
	r, err := http.NewRequest(method, srv.URL+req.path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if req.form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if req.user != "" || req.pass != "" {
		r.SetBasicAuth(req.user, req.pass)
	}
	if req.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+req.bearer)
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

var urlEscape = url.QueryEscape

// token fetches a bearer token from the token endpoint.
func (e *env) token(user, pass string, scopes ...string) string {
	e.t.Helper()
	path := TokenPath + "?service=flint"
	for _, s := range scopes {
		path += "&scope=" + urlEscape(s)
	}
	resp := e.do(request{path: path, user: user, pass: pass})
	if resp.status != http.StatusOK {
		e.t.Fatalf("token request: %d %s", resp.status, resp.body)
	}
	var tr tokenResponse
	if err := json.Unmarshal([]byte(resp.body), &tr); err != nil {
		e.t.Fatal(err)
	}
	return tr.Token
}

// claimsOf decodes a token's claims without verifying it.
func claimsOf(t *testing.T, tok string) claims {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q has %d parts", tok, len(parts))
	}
	var c claims
	if err := decodeSegment(parts[1], &c); err != nil {
		t.Fatal(err)
	}
	return c
}
