// Package pypi serves PyPI repositories: hosted repositories that twine
// and uv publish to, proxy repositories that cache an upstream index such
// as pypi.org, and virtual repositories that merge hosted and proxy
// repositories into one index with dependency-confusion protection.
//
// Each repository is served under /pypi/<repo>/:
//
//	GET  /pypi/<repo>/simple/                              root index (PEP 503, PEP 691)
//	GET  /pypi/<repo>/simple/<project>/                    project page (PEP 503, 691, 592, 658, 700)
//	GET  /pypi/<repo>/files/<project>/<filename>           distribution file
//	GET  /pypi/<repo>/files/<project>/<filename>.metadata  core-metadata file (PEP 658, PEP 714)
//	POST /pypi/<repo>/legacy/                              upload (the legacy API of twine and uv publish)
//	GET  /pypi/<repo>/pypi/<project>/json                  JSON API
//	GET  /pypi/<repo>/pypi/<project>/<version>/json        JSON API for one version
//
// and the admin API adds yanking and deletes (see admin.go). Project
// pages and the root index are served as HTML or JSON by content
// negotiation; their links to files are relative, so the pages do not
// depend on the host name clients use.
//
// File bytes live once in the blob store, keyed by their sha256 digest;
// the metadata store records which repository has which file (see
// records.go). Every request is authorized through an Authorizer, with
// HTTP basic credentials as PyPI clients send them.
package pypi

import (
	"context"
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
	"github.com/terrabyteian/flint/internal/upstream"
)

// Actions passed to Authorizer.Permit.
const (
	ActionPull   = "pull"
	ActionPush   = "push"
	ActionDelete = "delete"
)

// Authorizer decides whether a request may act on a repository.
type Authorizer interface {
	// Permit reports, as an HTTP status, whether the request's HTTP basic
	// credentials, or their absence, allow every action on repository
	// repo: http.StatusOK; StatusUnauthorized if the request has no
	// valid credentials and needs some; StatusForbidden if its
	// credentials lack the permission; or StatusInternalServerError.
	// With StatusOK it records the principal in r's context, for Actor.
	Permit(r *http.Request, repo string, actions ...string) int
}

// AllowAll is an Authorizer that allows every request, for tests.
type AllowAll struct{}

// Permit allows the request.
func (AllowAll) Permit(*http.Request, string, ...string) int { return http.StatusOK }

// Options configures a Handler.
type Options struct {
	// Meta and Blobs are the stores. Required.
	Meta  meta.Store
	Blobs blob.Store
	// Repositories are the configured repositories; those with format
	// "pypi" are served.
	Repositories []config.Repository
	// Authorizer authorizes every request. Required.
	Authorizer Authorizer
	// Upstream holds the defaults for proxy repositories' upstream
	// clients, such as the user agent.
	Upstream upstream.Options
	// Space, if set, watches the data directory's free space, so proxy
	// repositories stop caching new content when it runs low.
	Space *upstream.Space
	// Fetcher fetches files into the cache, shared with other formats'
	// proxy repositories; nil means a new one with FetchIdleTimeout.
	Fetcher          *upstream.Fetcher
	FetchIdleTimeout time.Duration
	// ProxyMetrics are the proxy metrics shared with other formats; nil
	// registers them on Metrics.
	ProxyMetrics *upstream.Metrics
	// Docs caches project pages, shared with other formats' proxy
	// repositories; nil means a new one, which RunProxy prunes.
	Docs *upstream.DocCache
	// Logger receives failures; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the PyPI metrics.
	Metrics *metrics.Registry
	// Actor names the principal behind a request in the origin of the
	// metadata batches it writes; nil names the client address.
	Actor func(*http.Request) string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// repository is a configured PyPI repository.
type repository struct {
	name      string
	typ       string        // config.TypeHosted, TypeProxy, or TypeVirtual
	anonymous bool          // anyone may pull
	proxy     *proxyRepo    // for a proxy repository
	virtual   *repo.Virtual // for a virtual repository
}

// Handler serves PyPI repositories.
type Handler struct {
	meta  meta.Store
	blobs blob.Store
	repos map[string]*repository
	auth  Authorizer
	log   *slog.Logger
	actor func(*http.Request) string
	now   func() time.Time

	uploads     *metrics.Counter
	uploadBytes *metrics.Counter

	// Proxy repositories.
	hasProxy  bool
	fetcher   *upstream.Fetcher
	space     *upstream.Space
	pm        *upstream.Metrics
	docs      *upstream.DocCache
	ownDocs   bool // docs is this handler's own, which it prunes
	limits    *upstream.Limits
	metaCalls upstream.Group[[]byte]
	pages     pageCache
}

// New returns a Handler.
func New(opts Options) (*Handler, error) {
	if opts.Meta == nil || opts.Blobs == nil {
		return nil, errors.New("pypi: Meta and Blobs are required")
	}
	if opts.Authorizer == nil {
		return nil, errors.New("pypi: an Authorizer is required")
	}
	h := &Handler{
		meta:    opts.Meta,
		blobs:   opts.Blobs,
		repos:   map[string]*repository{},
		auth:    opts.Authorizer,
		log:     opts.Logger,
		actor:   opts.Actor,
		now:     opts.Now,
		fetcher: opts.Fetcher,
		space:   opts.Space,
		docs:    opts.Docs,
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
	if h.fetcher == nil {
		h.fetcher = upstream.NewFetcher(opts.Blobs, opts.FetchIdleTimeout)
	}
	upOpts := opts.Upstream
	if upOpts.Logger == nil {
		upOpts.Logger = h.log
	}
	if upOpts.Now == nil {
		upOpts.Now = h.now
	}
	for _, rc := range opts.Repositories {
		if rc.Format != config.FormatPyPI {
			continue
		}
		r := &repository{name: rc.Name, typ: rc.Type, anonymous: rc.AnonymousPull}
		switch rc.Type {
		case config.TypeHosted:
		case config.TypeProxy:
			if rc.Proxy == nil {
				return nil, fmt.Errorf("pypi: proxy repository %s has no upstream", rc.Name)
			}
			p, err := newProxyRepo(rc, upOpts)
			if err != nil {
				return nil, fmt.Errorf("pypi: proxy repository %s: %w", rc.Name, err)
			}
			r.proxy = p
			h.hasProxy = true
		case config.TypeVirtual:
			v, err := repo.NewVirtual(rc, opts.Repositories)
			if err != nil {
				return nil, err
			}
			r.virtual = v
		default:
			return nil, fmt.Errorf("pypi: repository %s has unsupported type %q", rc.Name, rc.Type)
		}
		h.repos[rc.Name] = r
	}
	reg := opts.Metrics
	if reg == nil {
		reg = metrics.NewRegistry() // unexposed; keeps the counters usable
	}
	h.uploads = reg.Counter("flint_pypi_uploads_total",
		"Distribution files uploaded to hosted PyPI repositories, by repository.", "repository")
	h.uploadBytes = reg.Counter("flint_pypi_upload_bytes_total",
		"Bytes of distribution files uploaded to hosted PyPI repositories, by repository.", "repository")
	h.pm = opts.ProxyMetrics
	if h.pm == nil {
		space := h.space
		if !h.hasProxy {
			space = nil
		}
		h.pm = upstream.NewMetrics(reg, h.fetcher, space)
	}
	if h.docs == nil {
		h.docs = upstream.NewDocCache(upstream.DocCacheOptions{Meta: h.meta, Blobs: h.blobs, Space: h.space,
			Metrics: h.pm, Logger: h.log, Now: h.now})
		h.ownDocs = true
	}
	h.limits = upstream.NewLimits(upstream.LimitsOptions{Meta: h.meta, Metrics: h.pm, Format: "pypi",
		PulledKey: pulledKey, Now: h.now})
	if err := h.dropPageRecords(context.Background()); err != nil {
		return nil, err
	}
	if err := h.loadTrackers(); err != nil {
		return nil, err
	}
	return h, nil
}

// Register mounts the handler at /pypi/ on a server, and adds the admin
// API's PyPI endpoints.
func (h *Handler) Register(s interface{ Handle(string, http.Handler) }) {
	s.Handle("/pypi/", h)
	h.registerAdmin(s)
}

// ServeHTTP routes a /pypi/ request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rest := strings.TrimPrefix(r.URL.Path, "/pypi/")
	name, sub, slash := strings.Cut(rest, "/")
	rp := h.repos[name]
	if rp == nil {
		server.SetRoute(ctx, "pypi.unknown")
		writeError(w, http.StatusNotFound, "%q is not a PyPI repository on this server", abbrev(name))
		return
	}
	server.LogAttrs(ctx, slog.String("repository", name))
	base := "/pypi/" + name + "/"
	switch {
	case !slash || sub == "" || sub == "simple":
		server.SetRoute(ctx, "pypi.index")
		if allow(w, r, http.MethodGet, http.MethodHead) {
			http.Redirect(w, r, base+"simple/", http.StatusMovedPermanently)
		}
	case sub == "simple/":
		server.SetRoute(ctx, "pypi.index")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.permit(w, r, rp, ActionPull) {
			h.serveIndex(w, r, rp)
		}
	case strings.HasPrefix(sub, "simple/"):
		server.SetRoute(ctx, "pypi.project")
		if !allow(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		project, rest, _ := strings.Cut(strings.TrimPrefix(sub, "simple/"), "/")
		switch {
		case rest != "" || !ValidProjectName(project):
			writeError(w, http.StatusNotFound, "not found")
		case Normalize(project) != project || !strings.HasSuffix(sub, "/"):
			// PEP 503: redirect to the normalized name's URL.
			target := base + "simple/" + Normalize(project) + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		case h.permit(w, r, rp, ActionPull):
			h.serveProject(w, r, rp, project)
		}
	case sub == "legacy" || sub == "legacy/":
		server.SetRoute(ctx, "pypi.upload")
		if allow(w, r, http.MethodPost) {
			h.serveUpload(w, r, rp)
		}
	case strings.HasPrefix(sub, "files/"):
		server.SetRoute(ctx, "pypi.file")
		project, filename, ok := strings.Cut(strings.TrimPrefix(sub, "files/"), "/")
		if !ok || !normalizedName(project) || !validFilename(filename) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if !allow(w, r, http.MethodGet, http.MethodHead) || !h.permit(w, r, rp, ActionPull) {
			return
		}
		if stem, ok := strings.CutSuffix(filename, ".metadata"); ok && validFilename(stem) {
			server.SetRoute(ctx, "pypi.metadata")
			h.serveMetadata(w, r, rp, project, stem)
			return
		}
		h.serveFile(w, r, rp, project, filename)
	case strings.HasPrefix(sub, "pypi/"):
		server.SetRoute(ctx, "pypi.json")
		parts := strings.Split(strings.TrimPrefix(sub, "pypi/"), "/")
		var version string
		switch {
		case len(parts) == 2 && parts[1] == "json":
		case len(parts) == 3 && parts[2] == "json" && parts[1] != "":
			version = parts[1]
		default:
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if !ValidProjectName(parts[0]) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if allow(w, r, http.MethodGet, http.MethodHead) && h.permit(w, r, rp, ActionPull) {
			h.serveJSON(w, r, rp, Normalize(parts[0]), version)
		}
	default:
		server.SetRoute(ctx, "pypi.unknown")
		writeError(w, http.StatusNotFound, "not found")
	}
}

// permit authorizes the request for actions on rp, writing the response
// when it is refused.
func (h *Handler) permit(w http.ResponseWriter, r *http.Request, rp *repository, actions ...string) bool {
	switch status := h.auth.Permit(r, rp.name, actions...); status {
	case http.StatusOK:
		return true
	case http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", `Basic realm="flint"`)
		writeError(w, status, "authentication required: use a user name and password, or __token__ and an API token")
	case http.StatusForbidden:
		writeError(w, status, "access to repository %s is denied", rp.name)
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
	return false
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

// writeError writes a plain-text error, which pip, uv, and twine show.
func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, format+"\n", args...)
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
	switch {
	case errors.As(err, &he):
		writeError(w, he.status, "%s", he.msg)
	case r.Context().Err() != nil:
		// The client went away.
	case errors.Is(err, meta.ErrPoisoned), errors.Is(err, meta.ErrClosed):
		writeError(w, http.StatusServiceUnavailable, "the registry cannot accept writes now")
	default:
		h.log.ErrorContext(r.Context(), "pypi request failed", "path", r.URL.Path, "err", err)
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

// view returns a metadata view that the caller must release.
func (h *Handler) view() meta.View { return h.meta.View() }

// projectOf returns the project doc rp serves for project, or a 404 error
// if it has none. For a proxy or virtual repository it may ask the
// upstream.
func (h *Handler) projectOf(ctx context.Context, actor string, rp *repository, project string) (*projectDoc, string, error) {
	switch rp.typ {
	case config.TypeHosted:
		v := h.view()
		defer v.Release()
		p, err := hostedProject(v, rp, project)
		if err == nil && p == nil {
			err = notFound(project)
		}
		return p, upstream.ResultHit, err
	case config.TypeProxy:
		res, err := h.proxyProject(ctx, actor, rp, project)
		if err != nil {
			return nil, "", err
		}
		return res.doc, res.result, nil
	}
	p, err := h.virtualProject(ctx, actor, rp, project)
	return p, "", err
}

func notFound(project string) error {
	return errorf(http.StatusNotFound, "project %s is not found", project)
}
