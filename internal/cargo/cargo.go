// Package cargo serves Cargo repositories over Cargo's sparse registry
// protocol and registry web API: hosted repositories that cargo publishes
// to, proxy repositories that cache an upstream sparse index such as
// crates.io's, and virtual repositories that merge hosted and proxy
// repositories into one index with dependency-confusion protection.
//
// Each repository is served under /cargo/<repo>/, which is its index URL
// for Cargo, sparse+https://<host>/cargo/<repo>/:
//
//	GET    /cargo/<repo>/config.json                              index configuration: dl, api, auth-required
//	GET    /cargo/<repo>/{1,2}/<name>, 3/<c>/<name>, <ab>/<cd>/<name>  a crate's index file
//	PUT    /cargo/<repo>/api/v1/crates/new                        publish
//	DELETE /cargo/<repo>/api/v1/crates/<name>/<version>/yank      yank
//	PUT    /cargo/<repo>/api/v1/crates/<name>/<version>/unyank    unyank
//	GET    /cargo/<repo>/api/v1/crates/<name>/<version>/download  .crate file (config.json's dl)
//	GET    /cargo/<repo>/api/v1/crates?q=<query>                  search
//
// and the admin API adds deleting versions (see admin.go). config.json
// names the repository's own URLs, from the public URL or else the
// request's scheme and host; index lines carry no URLs.
//
// .crate files live once in the blob store, keyed by their sha256 digest,
// which is also the index line's cksum. Every request is authorized
// through an Authorizer with Cargo's challenge, which accepts the API
// token Cargo sends as the raw Authorization header.
package cargo

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

// Actions passed to an Authorizer.
const (
	ActionPull   = "pull"
	ActionPush   = "push"
	ActionDelete = "delete"
)

// Authorizer authorizes requests and answers those it refuses. It is an
// auth.Authorizer with Cargo's challenge for the registry routes, and one
// with a Basic challenge for the admin API.
type Authorizer interface {
	// Authorize reports whether the request may perform every action on
	// repository repo; when it returns false it has written the response.
	Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool
	// AuthorizeVirtual is Authorize for a virtual repository: pulling
	// needs read on the virtual repository, and other actions need their
	// roles on publishTo.
	AuthorizeVirtual(w http.ResponseWriter, r *http.Request, virtual, publishTo string, actions ...string) bool
}

// AllowAll is an Authorizer that allows every request, for tests.
type AllowAll struct{}

// Authorize allows the request.
func (AllowAll) Authorize(http.ResponseWriter, *http.Request, string, ...string) bool { return true }

// AuthorizeVirtual allows the request.
func (AllowAll) AuthorizeVirtual(http.ResponseWriter, *http.Request, string, string, ...string) bool {
	return true
}

// Options configures a Handler.
type Options struct {
	// Meta and Blobs are the stores. Required.
	Meta  meta.Store
	Blobs blob.Store
	// Repositories are the configured repositories; those with format
	// "cargo" are served.
	Repositories []config.Repository
	// Authorizer authorizes the registry routes, with Cargo's challenge.
	// Required.
	Authorizer Authorizer
	// AdminAuthorizer authorizes the admin API's Cargo endpoints, with a
	// Basic challenge; nil means Authorizer.
	AdminAuthorizer Authorizer
	// Upstream holds the defaults for proxy repositories' upstream
	// clients, such as the user agent.
	Upstream upstream.Options
	// Space, if set, watches the data directory's free space, so proxy
	// repositories stop caching new content when it runs low.
	Space *upstream.Space
	// Fetcher, Docs, and Paths are the proxy cache shared with other
	// formats: the fetcher, the document cache, which keeps index files,
	// and the path-cache engine, which keeps .crate files. Nil means new
	// ones of the handler's own, which RunProxy maintains.
	Fetcher *upstream.Fetcher
	Docs    *upstream.DocCache
	Paths   *upstream.PathCache
	// ProxyMetrics are the proxy metrics shared with other formats; nil
	// registers them on Metrics.
	ProxyMetrics *upstream.Metrics
	// VirtualMetrics are the virtual repository metrics shared with other
	// formats; nil registers them on Metrics.
	VirtualMetrics *repo.Metrics
	// Logger receives failures; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the Cargo metrics.
	Metrics *metrics.Registry
	// Actor names the principal behind a request in the origin of the
	// metadata batches it writes; nil names the client address.
	Actor func(*http.Request) string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// repository is a configured Cargo repository.
type repository struct {
	name      string
	typ       string        // config.TypeHosted, TypeProxy, or TypeVirtual
	anonymous bool          // anyone may pull
	proxy     *proxyRepo    // for a proxy repository
	virtual   *repo.Virtual // for a virtual repository
	// local, for a virtual repository, are the index URLs, as registryID
	// forms them, of the registries its proxy members cache: dependencies
	// of hosted crates on them are served as dependencies on the virtual
	// repository itself.
	local []string
}

// Handler serves Cargo repositories.
type Handler struct {
	meta  meta.Store
	blobs blob.Store
	repos map[string]*repository
	auth  Authorizer
	admin Authorizer
	log   *slog.Logger
	actor func(*http.Request) string
	now   func() time.Time

	publishes    *metrics.Counter
	publishBytes *metrics.Counter

	// Proxy repositories.
	hasProxy  bool
	space     *upstream.Space
	fetcher   *upstream.Fetcher
	pm        *upstream.Metrics
	docs      *upstream.DocCache
	paths     *upstream.PathCache
	ownCaches bool // docs and paths are this handler's own, which it runs
	indexes   indexCache
	configs   configCache
}

// New returns a Handler.
func New(opts Options) (*Handler, error) {
	if opts.Meta == nil || opts.Blobs == nil {
		return nil, errors.New("cargo: Meta and Blobs are required")
	}
	if opts.Authorizer == nil {
		return nil, errors.New("cargo: an Authorizer is required")
	}
	h := &Handler{
		meta:  opts.Meta,
		blobs: opts.Blobs,
		repos: map[string]*repository{},
		auth:  opts.Authorizer,
		admin: opts.AdminAuthorizer,
		log:   opts.Logger,
		actor: opts.Actor,
		now:   opts.Now,
		space: opts.Space,
		docs:  opts.Docs,
		paths: opts.Paths,
	}
	if h.admin == nil {
		h.admin = h.auth
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
	upOpts := opts.Upstream
	if upOpts.Logger == nil {
		upOpts.Logger = h.log
	}
	if upOpts.Now == nil {
		upOpts.Now = h.now
	}
	reg := opts.Metrics
	if reg == nil {
		reg = metrics.NewRegistry() // unexposed; keeps the counters usable
	}
	vm := opts.VirtualMetrics
	if vm == nil {
		vm = repo.NewMetrics(reg)
	}
	for _, rc := range opts.Repositories {
		if rc.Format != config.FormatCargo {
			continue
		}
		r := &repository{name: rc.Name, typ: rc.Type, anonymous: rc.AnonymousPull}
		switch rc.Type {
		case config.TypeHosted:
		case config.TypeProxy:
			if rc.Proxy == nil {
				return nil, fmt.Errorf("cargo: proxy repository %s has no upstream", rc.Name)
			}
			p, err := newProxyRepo(rc, upOpts)
			if err != nil {
				return nil, fmt.Errorf("cargo: proxy repository %s: %w", rc.Name, err)
			}
			r.proxy = p
			h.hasProxy = true
		case config.TypeVirtual:
			v, err := repo.NewVirtual(rc, opts.Repositories, repo.VirtualOptions{Normalize: Normalize, Logger: h.log, Metrics: vm})
			if err != nil {
				return nil, err
			}
			r.virtual = v
		default:
			return nil, fmt.Errorf("cargo: repository %s has unsupported type %q", rc.Name, rc.Type)
		}
		h.repos[rc.Name] = r
	}
	for _, r := range h.repos {
		if r.virtual == nil {
			continue
		}
		for _, m := range r.virtual.Members {
			if mr := h.repos[m.Name]; mr != nil && mr.proxy != nil {
				r.local = append(r.local, aliases(mr.proxy.index)...)
			}
		}
	}
	h.publishes = reg.Counter("flint_cargo_publishes_total",
		"Crate versions published to hosted Cargo repositories, by repository.", "repository")
	h.publishBytes = reg.Counter("flint_cargo_publish_bytes_total",
		"Bytes of .crate files published to hosted Cargo repositories, by repository.", "repository")
	h.pm = opts.ProxyMetrics
	h.fetcher = opts.Fetcher
	if h.fetcher == nil {
		h.fetcher = upstream.NewFetcher(opts.Blobs, 0)
	}
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
		h.ownCaches = true
	}
	if h.paths == nil {
		h.paths = upstream.NewPathCache(upstream.PathCacheOptions{Meta: h.meta, Blobs: h.blobs, Fetcher: h.fetcher,
			Docs: h.docs, Space: h.space, Metrics: h.pm, Logger: h.log, Now: h.now})
		h.ownCaches = true
	}
	for _, r := range h.repos {
		if r.proxy == nil {
			continue
		}
		r.proxy.path.WriteError = func(w http.ResponseWriter, _ *http.Request, status int, msg string) {
			writeError(w, status, "%s", msg)
		}
		if err := h.paths.Add(r.proxy.path); err != nil {
			return nil, fmt.Errorf("cargo: loading the cache of proxy repository %s: %w", r.name, err)
		}
	}
	return h, nil
}

// Register mounts the handler at /cargo/ on a server, and adds the admin
// API's Cargo endpoints.
func (h *Handler) Register(s interface{ Handle(string, http.Handler) }) {
	s.Handle(repo.Prefix(config.FormatCargo), h)
	h.registerAdmin(s)
}

// RunProxy runs the proxy repositories' background work until ctx is
// done, if the handler has caches of its own: it persists last-pull
// times, evicts .crate files over size limits, and forgets stale
// confirmations and not-found answers. Shared caches are run by their
// owner.
func (h *Handler) RunProxy(ctx context.Context) {
	if !h.hasProxy || !h.ownCaches {
		return
	}
	var window time.Duration
	for _, rp := range h.repos {
		if rp.proxy != nil {
			window = max(window, rp.proxy.revalidate)
		}
	}
	go h.docs.Run(ctx, window)
	h.paths.Run(ctx)
}

// FlushPullTimes persists the last-pull times recorded since the last
// flush.
func (h *Handler) FlushPullTimes(ctx context.Context) error { return h.paths.FlushPullTimes(ctx) }

// Evict evicts the least recently pulled .crate files of every
// size-limited proxy repository over its limit.
func (h *Handler) Evict(ctx context.Context) error { return h.paths.Evict(ctx) }

// ServeHTTP routes a /cargo/ request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, sub, slash, _ := repo.Split(config.FormatCargo, r.URL.Path)
	rp := h.repos[name]
	if rp == nil {
		// Repositories of other formats are not found here either.
		server.SetRoute(ctx, "cargo.unknown")
		writeError(w, http.StatusNotFound, "%s is not a Cargo repository on this server", quote(name))
		return
	}
	server.LogAttrs(ctx, slog.String("repository", name))
	switch {
	case !slash:
		server.SetRoute(ctx, "cargo.unknown")
		writeError(w, http.StatusNotFound, "not found: the index of repository %s is at %s", name, repo.Path(config.FormatCargo, name))
	case sub == "config.json":
		server.SetRoute(ctx, "cargo.config")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.authorize(w, r, rp, ActionPull) {
			h.serveConfig(w, r, rp)
		}
	case sub == "api/v1/crates":
		server.SetRoute(ctx, "cargo.search")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.authorize(w, r, rp, ActionPull) {
			h.serveSearch(w, r, rp)
		}
	case sub == "api/v1/crates/new":
		server.SetRoute(ctx, "cargo.publish")
		if allow(w, r, http.MethodPut) {
			h.servePublish(w, r, rp)
		}
	case strings.HasPrefix(sub, "api/"):
		h.serveAPI(w, r, rp, sub)
	default:
		server.SetRoute(ctx, "cargo.index")
		crate, ok := parseIndexPath(sub)
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if allow(w, r, http.MethodGet, http.MethodHead) && h.authorize(w, r, rp, ActionPull) {
			h.serveIndex(w, r, rp, crate)
		}
	}
}

// serveAPI routes the web API's requests about one crate.
func (h *Handler) serveAPI(w http.ResponseWriter, r *http.Request, rp *repository, sub string) {
	ctx := r.Context()
	parts := strings.Split(strings.TrimPrefix(sub, "api/v1/crates/"), "/")
	if !strings.HasPrefix(sub, "api/v1/crates/") || !validIndexName(parts[0]) {
		server.SetRoute(ctx, "cargo.unknown")
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	crate := parts[0]
	if len(parts) == 2 && parts[1] == "owners" {
		server.SetRoute(ctx, "cargo.owners")
		writeError(w, http.StatusBadRequest, "flint has no crate owners: who may publish and yank crates in repository %s "+
			"is decided by flint's permission grants on it (write to publish and yank, delete to delete versions)", rp.name)
		return
	}
	if len(parts) != 3 {
		server.SetRoute(ctx, "cargo.unknown")
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	vers := parts[1]
	if _, ok := parseVersion(vers); !ok {
		server.SetRoute(ctx, "cargo.unknown")
		writeError(w, http.StatusNotFound, "%s is not a valid version", quote(vers))
		return
	}
	switch parts[2] {
	case "download":
		server.SetRoute(ctx, "cargo.download")
		if allow(w, r, http.MethodGet, http.MethodHead) && h.authorize(w, r, rp, ActionPull) {
			h.serveDownload(w, r, rp, crate, vers)
		}
	case "yank":
		server.SetRoute(ctx, "cargo.yank")
		if allow(w, r, http.MethodDelete) {
			h.serveYank(w, r, rp, crate, vers, true)
		}
	case "unyank":
		server.SetRoute(ctx, "cargo.unyank")
		if allow(w, r, http.MethodPut) {
			h.serveYank(w, r, rp, crate, vers, false)
		}
	default:
		server.SetRoute(ctx, "cargo.unknown")
		writeError(w, http.StatusNotFound, "not found")
	}
}

// authorize authorizes the request for actions on rp, writing the
// response when it is refused. Pulling through a virtual repository needs
// read on it; other actions through it need their roles on its publishTo
// member.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, rp *repository, actions ...string) bool {
	if rp.typ == config.TypeVirtual {
		return h.auth.AuthorizeVirtual(w, r, rp.name, rp.virtual.PublishTo, actions...)
	}
	return h.auth.Authorize(w, r, rp.name, actions...)
}

// writable returns the hosted repository that receives publishes and
// yanks sent to rp, after authorizing actions on it: rp itself, or a
// virtual repository's publishTo member. It writes the response and
// returns nil if there is none or the request is refused.
func (h *Handler) writable(w http.ResponseWriter, r *http.Request, rp *repository, actions ...string) *repository {
	switch rp.typ {
	case config.TypeProxy:
		if h.authorize(w, r, rp, ActionPull) {
			writeError(w, http.StatusMethodNotAllowed, "repository %s is a read-only proxy of %s; publish to a hosted repository instead",
				rp.name, rp.proxy.index)
		}
		return nil
	case config.TypeVirtual:
		if rp.virtual.PublishTo == "" {
			if h.authorize(w, r, rp, ActionPull) {
				writeError(w, http.StatusMethodNotAllowed, "repository %s is a virtual repository without publishTo; publish to one of its hosted members: %s",
					rp.name, strings.Join(rp.virtual.Hosted(), ", "))
			}
			return nil
		}
	}
	if !h.authorize(w, r, rp, actions...) {
		return nil
	}
	if rp.typ == config.TypeVirtual {
		return h.repos[rp.virtual.PublishTo]
	}
	return rp
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

// writeError writes an error as the web API's JSON errors object, whose
// detail Cargo shows.
func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	hd := w.Header()
	hd.Del("Content-Length")
	hd.Del("ETag")
	hd.Set("Content-Type", "application/json")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	writeJSONTo(w, errorsBody(fmt.Sprintf(format, args...)))
}

type errorDetail struct {
	Detail string `json:"detail"`
}

type errorsObject struct {
	Errors []errorDetail `json:"errors"`
}

func errorsBody(msg string) errorsObject { return errorsObject{[]errorDetail{{msg}}} }

// httpError is an error with the response to answer it with.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func errorf(status int, format string, args ...any) error {
	return &httpError{status: status, msg: fmt.Sprintf(format, args...)}
}

// isNotFound reports whether err is a not-found answer.
func isNotFound(err error) bool {
	var he *httpError
	return errors.As(err, &he) && he.status == http.StatusNotFound
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
		h.log.ErrorContext(r.Context(), "cargo request failed", "path", r.URL.Path, "err", err)
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

// maxLinkAttempts bounds how often a batch is retried after a metadata
// precondition fails.
const maxLinkAttempts = 4

// errRetry means a batch lost a race with garbage collection or another
// writer and the client should retry.
var errRetry = errorf(http.StatusServiceUnavailable, "the registry is busy with this crate; retry the request")
