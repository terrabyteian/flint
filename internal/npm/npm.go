// Package npm serves npm repositories: hosted repositories that npm,
// pnpm, Yarn, and Bun install from and npm publishes to, through the npm
// registry API.
//
// Each repository is served under /npm/<repo>/, which is the registry URL
// clients are configured with:
//
//	GET    /npm/<repo>/<name>                                packument, full or abbreviated
//	GET    /npm/<repo>/<name>/<version or dist-tag>          one version's manifest
//	GET    /npm/<repo>/<name>/-/<file>.tgz                   tarball
//	PUT    /npm/<repo>/<name>                                publish, or deprecate
//	PUT    /npm/<repo>/<name>/-rev/<rev>                     unpublish versions, or deprecate
//	DELETE /npm/<repo>/<name>/-rev/<rev>                     unpublish the package
//	DELETE /npm/<repo>/<name>/-/<file>.tgz/-rev/<rev>        unpublish a version by its tarball
//	GET    /npm/<repo>/-/package/<name>/dist-tags            dist-tags
//	PUT    /npm/<repo>/-/package/<name>/dist-tags/<tag>      set a dist-tag
//	DELETE /npm/<repo>/-/package/<name>/dist-tags/<tag>      remove a dist-tag
//	PUT    /npm/<repo>/-/user/org.couchdb.user:<user>        legacy login: mints an API token
//	GET    /npm/<repo>/-/whoami                              the user a token belongs to
//	GET    /npm/<repo>/-/ping                                ping
//	GET    /npm/<repo>/-/v1/search                           search package names
//	POST   /npm/<repo>/-/npm/v1/security/advisories/bulk     audit
//	GET    /npm/<repo>/-/npm/v1/keys                         registry signing keys
//	GET    /npm/<repo>/-/npm/v1/attestations/<name>@<ver>    provenance
//
// A scoped name is accepted encoded, "@scope%2fname" as npm sends it, and
// plain, "@scope/name". Packuments are assembled from the metadata store
// when served, with tarball URLs under the repository's registry URL, so
// npm sends the registry's credentials with tarball requests too; they
// are absolute URLs, built from the public URL, so lockfiles record one
// stable URL.
//
// Tarballs, version manifests, readmes, and provenance bundles live in
// the blob store; the metadata store records which repository has which
// package and version (see records.go). Every request is authorized
// through an Authorizer, which answers refusals as npm expects: 401
// without a challenge, after which npm tells the user to log in.
package npm

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/server"
)

// Actions passed to Authorizer.Authorize.
const (
	ActionPull   = "pull"
	ActionPush   = "push"
	ActionDelete = "delete"
)

// Authorizer decides whether a request may act on a repository.
type Authorizer interface {
	// Authorize reports whether the request may perform every action on
	// repository repo; with repo empty and no actions, whether it carries
	// valid credentials. When it returns false it has written the
	// response: 401 or 403, or 500. When it returns true, it records the
	// principal in r's context, for Options.User and Options.Actor.
	Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool
}

// AllowAll is an Authorizer that allows every request, for tests.
type AllowAll struct{}

// Authorize allows the request.
func (AllowAll) Authorize(http.ResponseWriter, *http.Request, string, ...string) bool { return true }

// ErrInvalidLogin is what Options.Login returns for a user name and
// password that do not authenticate.
var ErrInvalidLogin = errors.New("npm: incorrect user name or password")

// Options configures a Handler.
type Options struct {
	// Meta and Blobs are the stores. Required.
	Meta  meta.Store
	Blobs blob.Store
	// Repositories are the configured repositories; those with format
	// "npm" are served.
	Repositories []config.Repository
	// Authorizer authorizes every request. Required.
	Authorizer Authorizer
	// Login serves npm's legacy login: it verifies a user name and
	// password and returns a new API token for the user, named after
	// client, or ErrInvalidLogin. Nil refuses logins.
	Login func(r *http.Request, username, password, client string) (string, error)
	// User names the user the Authorizer admitted a request as, or "" for
	// an anonymous client, for npm whoami. Nil knows no user.
	User func(*http.Request) string
	// Actor names the principal behind a request in the origin of the
	// metadata batches it writes; nil names the client address.
	Actor func(*http.Request) string
	// Logger receives failures; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the npm metrics.
	Metrics *metrics.Registry
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// RenderBudget bounds the bytes of rendered packuments kept in
	// memory; zero means DefaultRenderBudget.
	RenderBudget int64
}

// repository is a configured npm repository.
type repository struct {
	name      string
	typ       string // config.TypeHosted
	anonymous bool   // anyone may pull
}

// Handler serves npm repositories.
type Handler struct {
	meta  meta.Store
	blobs blob.Store
	repos map[string]*repository
	auth  Authorizer
	login func(*http.Request, string, string, string) (string, error)
	user  func(*http.Request) string
	actor func(*http.Request) string
	log   *slog.Logger
	now   func() time.Time

	renders *renderCache

	publishes    *metrics.Counter
	publishBytes *metrics.Counter
}

// New returns a Handler.
func New(opts Options) (*Handler, error) {
	if opts.Meta == nil || opts.Blobs == nil {
		return nil, errors.New("npm: Meta and Blobs are required")
	}
	if opts.Authorizer == nil {
		return nil, errors.New("npm: an Authorizer is required")
	}
	h := &Handler{
		meta:    opts.Meta,
		blobs:   opts.Blobs,
		repos:   map[string]*repository{},
		auth:    opts.Authorizer,
		login:   opts.Login,
		user:    opts.User,
		actor:   opts.Actor,
		log:     opts.Logger,
		now:     opts.Now,
		renders: newRenderCache(opts.RenderBudget),
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.actor == nil {
		h.actor = clientActor
	}
	if h.user == nil {
		h.user = func(*http.Request) string { return "" }
	}
	for _, rc := range opts.Repositories {
		if rc.Format != config.FormatNPM {
			continue
		}
		if rc.Type != config.TypeHosted {
			return nil, fmt.Errorf("npm: repository %s has unsupported type %q", rc.Name, rc.Type)
		}
		h.repos[rc.Name] = &repository{name: rc.Name, typ: rc.Type, anonymous: rc.AnonymousPull}
	}
	reg := opts.Metrics
	if reg == nil {
		reg = metrics.NewRegistry() // unexposed; keeps the counters usable
	}
	h.publishes = reg.Counter("flint_npm_publishes_total",
		"Package versions published to hosted npm repositories, by repository.", "repository")
	h.publishBytes = reg.Counter("flint_npm_publish_bytes_total",
		"Bytes of package tarballs published to hosted npm repositories, by repository.", "repository")
	return h, nil
}

// Register mounts the handler at /npm/ on a server.
func (h *Handler) Register(s interface{ Handle(string, http.Handler) }) {
	s.Handle(repo.Prefix(config.FormatNPM), h)
}

// ServeHTTP routes an /npm/ request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, sub, slash, _ := repo.Split(config.FormatNPM, r.URL.Path)
	rp := h.repos[name]
	if rp == nil {
		// Repositories of other formats are not found here either.
		server.SetRoute(ctx, "npm.unknown")
		writeError(w, http.StatusNotFound, "%q is not an npm repository on this server", abbrev(name))
		return
	}
	server.LogAttrs(ctx, slog.String("repository", name))
	switch {
	case !slash:
		server.SetRoute(ctx, "npm.root")
		if allow(w, r, http.MethodGet, http.MethodHead) {
			http.Redirect(w, r, repo.Path(config.FormatNPM, name), http.StatusMovedPermanently)
		}
	case sub == "":
		server.SetRoute(ctx, "npm.root")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.permit(w, r, rp, ActionPull) {
			writeJSON(w, http.StatusOK, struct{}{})
		}
	case strings.HasPrefix(sub, "-/"):
		h.serveSpecial(w, r, rp, strings.TrimPrefix(sub, "-/"))
	default:
		h.servePackage(w, r, rp, sub)
	}
}

// servePackage serves the paths below a package name.
func (h *Handler) servePackage(w http.ResponseWriter, r *http.Request, rp *repository, sub string) {
	ctx := r.Context()
	if r.Method == http.MethodDelete {
		if name, file, rev, ok := tarballDeletePath(sub); ok {
			server.SetRoute(ctx, "npm.unpublish")
			h.serveTarballDelete(w, r, rp, name, file, rev)
			return
		}
	}
	name, rest, ok := splitName(sub)
	switch {
	case ok && !ValidName(name) && rest == "" && r.Method == http.MethodPut:
		server.SetRoute(ctx, "npm.publish")
		writeError(w, http.StatusBadRequest, "%s", invalidName(name))
		return
	case !ok || !ValidName(name):
		server.SetRoute(ctx, "npm.unknown")
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	server.LogAttrs(ctx, slog.String("package", name))
	switch {
	case rest == "":
		switch r.Method {
		case http.MethodPut:
			server.SetRoute(ctx, "npm.publish")
			h.servePut(w, r, rp, name, "")
		default:
			server.SetRoute(ctx, "npm.packument")
			if allow(w, r, http.MethodGet, http.MethodHead, http.MethodPut) && h.permit(w, r, rp, ActionPull) {
				h.servePackument(w, r, rp, name)
			}
		}
	case strings.HasPrefix(rest, "-rev/") && !strings.Contains(rest[len("-rev/"):], "/"):
		rev := strings.TrimPrefix(rest, "-rev/")
		switch r.Method {
		case http.MethodPut:
			server.SetRoute(ctx, "npm.publish")
			h.servePut(w, r, rp, name, rev)
		default:
			server.SetRoute(ctx, "npm.unpublish")
			if allow(w, r, http.MethodPut, http.MethodDelete) {
				h.serveUnpublishAll(w, r, rp, name, rev)
			}
		}
	case strings.HasPrefix(rest, "-/") && !strings.Contains(rest[len("-/"):], "/"):
		server.SetRoute(ctx, "npm.tarball")
		file := strings.TrimPrefix(rest, "-/")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.permit(w, r, rp, ActionPull) {
			h.serveTarball(w, r, rp, name, file)
		}
	case !strings.Contains(rest, "/"):
		server.SetRoute(ctx, "npm.version")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.permit(w, r, rp, ActionPull) {
			h.serveVersion(w, r, rp, name, rest)
		}
	default:
		server.SetRoute(ctx, "npm.unknown")
		writeError(w, http.StatusNotFound, "not found")
	}
}

// serveSpecial serves the registry's own endpoints, under /-/.
func (h *Handler) serveSpecial(w http.ResponseWriter, r *http.Request, rp *repository, sub string) {
	ctx := r.Context()
	switch {
	case sub == "ping":
		server.SetRoute(ctx, "npm.ping")
		if allow(w, r, http.MethodGet, http.MethodHead) {
			writeJSON(w, http.StatusOK, struct{}{})
		}
	case sub == "whoami":
		server.SetRoute(ctx, "npm.whoami")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.auth.Authorize(w, r, "") {
			h.serveWhoami(w, r)
		}
	case strings.HasPrefix(sub, "user/org.couchdb.user:"):
		server.SetRoute(ctx, "npm.login")
		if allow(w, r, http.MethodPut) {
			h.serveLogin(w, r, strings.TrimPrefix(sub, "user/org.couchdb.user:"))
		}
	case sub == "v1/search":
		server.SetRoute(ctx, "npm.search")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.permit(w, r, rp, ActionPull) {
			h.serveSearch(w, r, rp)
		}
	case strings.HasPrefix(sub, "package/"):
		server.SetRoute(ctx, "npm.dist-tags")
		h.serveDistTags(w, r, rp, strings.TrimPrefix(sub, "package/"))
	case sub == "npm/v1/security/advisories/bulk":
		server.SetRoute(ctx, "npm.audit")
		if allow(w, r, http.MethodPost) && h.permit(w, r, rp, ActionPull) {
			h.serveAdvisories(w, r, rp)
		}
	case sub == "npm/v1/keys":
		server.SetRoute(ctx, "npm.keys")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.permit(w, r, rp, ActionPull) {
			writeJSON(w, http.StatusOK, map[string][]any{"keys": {}})
		}
	case strings.HasPrefix(sub, "npm/v1/attestations/"):
		server.SetRoute(ctx, "npm.attestations")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.permit(w, r, rp, ActionPull) {
			h.serveAttestations(w, r, rp, strings.TrimPrefix(sub, "npm/v1/attestations/"))
		}
	default:
		// Includes the web login, /-/v1/login, whose 404 makes npm login
		// fall back to the legacy login.
		server.SetRoute(ctx, "npm.unknown")
		writeError(w, http.StatusNotFound, "not found")
	}
}

// splitName splits the path below a repository into a package name, one
// segment or, for a scoped name, two, and the rest after the "/" that
// follows it.
func splitName(p string) (name, rest string, ok bool) {
	n := 1
	if strings.HasPrefix(p, "@") {
		n = 2
	}
	end := 0
	for i := 0; i < n; i++ {
		j := strings.IndexByte(p[end:], '/')
		if j < 0 {
			if i == n-1 {
				return p, "", true
			}
			return "", "", false
		}
		end += j + 1
	}
	return p[:end-1], p[end:], true
}

// tarballDeletePath parses the path npm unpublish deletes a tarball at:
// the tarball's path below the registry URL followed by "/-rev/<rev>".
// npm derives it from the tarball URL's path, which it then resolves
// against the registry URL, so it may also repeat the registry URL's own
// path, as in "npm/<repo>/<name>/-/<file>/-rev/<rev>"; whatever precedes
// the package name is ignored.
func tarballDeletePath(p string) (name, file, rev string, ok bool) {
	i := strings.LastIndex(p, "/-rev/")
	if i < 0 {
		return "", "", "", false
	}
	p, rev = p[:i], p[i+len("/-rev/"):]
	i = strings.LastIndex(p, "/-/")
	if i < 0 || rev == "" || strings.Contains(rev, "/") {
		return "", "", "", false
	}
	p, file = p[:i], p[i+len("/-/"):]
	if strings.Contains(file, "/") {
		return "", "", "", false
	}
	segs := strings.Split(p, "/")
	name = segs[len(segs)-1]
	if len(segs) > 1 && strings.HasPrefix(segs[len(segs)-2], "@") {
		name = segs[len(segs)-2] + "/" + name
	}
	return name, file, rev, ValidName(name)
}

// permit authorizes the request for actions on rp, writing the response
// when it is refused.
func (h *Handler) permit(w http.ResponseWriter, r *http.Request, rp *repository, actions ...string) bool {
	return h.auth.Authorize(w, r, rp.name, actions...)
}

// allow reports whether the request's method is one of methods, and
// answers 405 if it is not.
func allow(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method %s is not allowed here", r.Method)
	return false
}

// WriteError writes an error as the npm registry does, a JSON object with
// the message in "error", which npm shows. It is the auth.Challenge
// WriteError of npm's routes.
func WriteError(w http.ResponseWriter, _ *http.Request, status int, msg string) {
	writeError(w, status, "%s", msg)
}

// writeError writes an npm error response.
func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	h := w.Header()
	h.Del("Content-Length")
	h.Del("ETag")
	h.Set("Cache-Control", "no-store")
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{fmt.Sprintf(format, args...)})
}

// writeJSON writes v as a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// httpError is an error with the response to answer it with.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func errorf(status int, format string, args ...any) error {
	return &httpError{status: status, msg: fmt.Sprintf(format, args...)}
}

// fail answers a request with err: its own response for an *httpError,
// nothing for a cancelled request, and 500 otherwise.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpError
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &he):
		writeError(w, he.status, "%s", he.msg)
	case errors.As(err, &mbe):
		writeError(w, http.StatusRequestEntityTooLarge, "the request body is too large")
	case r.Context().Err() != nil:
		// The client went away.
	case errors.Is(err, meta.ErrPoisoned), errors.Is(err, meta.ErrClosed):
		writeError(w, http.StatusServiceUnavailable, "the registry cannot accept writes now")
	default:
		h.log.ErrorContext(r.Context(), "npm request failed", "path", r.URL.Path, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// clientActor names a request's principal by its client address.
func clientActor(r *http.Request) string {
	if ip := server.Info(r.Context()).ClientIP; ip.IsValid() {
		return "client " + ip.String()
	}
	return meta.ActorAnonymous
}

func (h *Handler) origin(r *http.Request, action, target string) meta.Origin {
	return meta.Origin{Actor: h.actor(r), Action: action, Target: target}
}

// abbrev shortens s for messages.
func abbrev(s string) string {
	const max = 100
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func notFound(name string) error {
	return errorf(http.StatusNotFound, "package %s is not found", name)
}
