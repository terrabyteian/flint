// Package generic serves generic files repositories, which store and
// serve arbitrary files by path for curl, wget, and scripts: hosted
// repositories that clients upload to, proxy repositories that cache
// files from any upstream base URL, and virtual repositories that serve
// each path from the first member that has it.
//
// Each repository is served under /generic/<repo>/:
//
//	GET, HEAD  /generic/<repo>/<path>   a file, with Range support
//	GET, HEAD  /generic/<repo>/<dir>/   the files and directories directly below <dir>:
//	                                    JSON with Accept: application/json, HTML otherwise
//	PUT        /generic/<repo>/<path>   upload (hosted, or virtual with publishTo)
//	DELETE     /generic/<repo>/<path>   delete (hosted)
//
// A path is one or more segments separated by "/", none of them empty,
// "." or "..", in UTF-8 without control characters. File bytes live once
// in the blob store, keyed by their sha256 digest; the metadata store
// records which repository has which file at which path (see
// records.go). Files are immutable unless the repository allows
// overwrites: an identical upload succeeds without a change, different
// content is refused, and a deleted path is never usable again.
//
// Every request is authorized through an Authorizer, which accepts HTTP
// basic credentials and API tokens as bearer tokens and challenges with
// Basic, as curl and wget expect.
package generic

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/server"
	"github.com/terrabyteian/flint/internal/upstream"
)

// Actions passed to the Authorizer.
const (
	ActionPull   = "pull"
	ActionPush   = "push"
	ActionDelete = "delete"
)

// Authorizer authorizes requests, writing the response to those it
// refuses: 401 with a challenge, 403, or 500. internal/auth's Authorizer
// implements it.
type Authorizer interface {
	// Authorize reports whether the request may perform every action on
	// repository repo.
	Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool
	// AuthorizeVirtual reports whether the request may perform every
	// action through virtual repository virtual: pulling needs read on
	// it, and other actions what they need on publishTo.
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
	// "generic" are served.
	Repositories []config.Repository
	// Authorizer authorizes every request. Required.
	Authorizer Authorizer
	// Upstream holds the defaults for proxy repositories' upstream
	// clients, such as the user agent.
	Upstream upstream.Options
	// Paths is the path-cache engine proxy repositories serve through,
	// shared with other formats; nil means a new one built from the
	// options below, which RunProxy runs.
	Paths *upstream.PathCache
	// Space, Fetcher, Docs, and ProxyMetrics build a new Paths: the
	// free-space watcher, nil for none; the fetcher, document cache, and
	// proxy metrics shared with other formats, nil for new ones.
	Space        *upstream.Space
	Fetcher      *upstream.Fetcher
	Docs         *upstream.DocCache
	ProxyMetrics *upstream.Metrics
	// VirtualMetrics are the virtual repository metrics shared with other
	// formats; nil registers them on Metrics.
	VirtualMetrics *repo.Metrics
	// Logger receives failures; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the generic files metrics.
	Metrics *metrics.Registry
	// Actor names the principal behind a request in the origin of the
	// metadata batches it writes; nil names the client address.
	Actor func(*http.Request) string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// repository is a configured generic files repository.
type repository struct {
	name      string
	typ       string // config.TypeHosted, TypeProxy, or TypeVirtual
	anonymous bool   // anyone may pull
	overwrite bool   // generic.allowOverwrite, for a hosted repository
	proxy     *proxyRepo
	virtual   *repo.Virtual
}

// Handler serves generic files repositories.
type Handler struct {
	meta  meta.Store
	blobs blob.Store
	repos map[string]*repository
	auth  Authorizer
	log   *slog.Logger
	actor func(*http.Request) string
	now   func() time.Time

	paths    *upstream.PathCache
	ownPaths bool // paths is this handler's own, which RunProxy runs
	docs     *upstream.DocCache
	ownDocs  bool
}

// New returns a Handler.
func New(opts Options) (*Handler, error) {
	if opts.Meta == nil || opts.Blobs == nil {
		return nil, errors.New("generic: Meta and Blobs are required")
	}
	if opts.Authorizer == nil {
		return nil, errors.New("generic: an Authorizer is required")
	}
	h := &Handler{
		meta:  opts.Meta,
		blobs: opts.Blobs,
		repos: map[string]*repository{},
		auth:  opts.Authorizer,
		log:   opts.Logger,
		actor: opts.Actor,
		now:   opts.Now,
		paths: opts.Paths,
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
	reg := opts.Metrics
	if reg == nil {
		reg = metrics.NewRegistry() // unexposed; keeps the counters usable
	}
	if h.paths == nil {
		fetcher := opts.Fetcher
		if fetcher == nil {
			fetcher = upstream.NewFetcher(opts.Blobs, 0)
		}
		pm := opts.ProxyMetrics
		if pm == nil {
			pm = upstream.NewMetrics(reg, fetcher, opts.Space)
		}
		h.docs = opts.Docs
		if h.docs == nil {
			h.docs = upstream.NewDocCache(upstream.DocCacheOptions{Meta: h.meta, Blobs: h.blobs, Space: opts.Space,
				Metrics: pm, Logger: h.log, Now: h.now})
			h.ownDocs = true
		}
		h.paths = upstream.NewPathCache(upstream.PathCacheOptions{Meta: h.meta, Blobs: h.blobs, Fetcher: fetcher,
			Docs: h.docs, Space: opts.Space, Metrics: pm, Logger: h.log, Now: h.now})
		h.ownPaths = true
	}
	upOpts := opts.Upstream
	if upOpts.Logger == nil {
		upOpts.Logger = h.log
	}
	if upOpts.Now == nil {
		upOpts.Now = h.now
	}
	vm := opts.VirtualMetrics
	if vm == nil {
		vm = repo.NewMetrics(reg)
	}
	for _, rc := range opts.Repositories {
		if rc.Format != config.FormatGeneric {
			continue
		}
		r := &repository{name: rc.Name, typ: rc.Type, anonymous: rc.AnonymousPull}
		switch rc.Type {
		case config.TypeHosted:
			r.overwrite = rc.Generic != nil && rc.Generic.AllowOverwrite
		case config.TypeProxy:
			if rc.Proxy == nil {
				return nil, fmt.Errorf("generic: proxy repository %s has no upstream", rc.Name)
			}
			p, err := newProxyRepo(rc, upOpts)
			if err != nil {
				return nil, fmt.Errorf("generic: proxy repository %s: %w", rc.Name, err)
			}
			if err := h.paths.Add(p.path); err != nil {
				return nil, fmt.Errorf("generic: proxy repository %s: %w", rc.Name, err)
			}
			r.proxy = p
		case config.TypeVirtual:
			v, err := repo.NewVirtual(rc, opts.Repositories, repo.VirtualOptions{Logger: h.log, Metrics: vm})
			if err != nil {
				return nil, err
			}
			r.virtual = v
		default:
			return nil, fmt.Errorf("generic: repository %s has unsupported type %q", rc.Name, rc.Type)
		}
		h.repos[rc.Name] = r
	}
	return h, nil
}

// Register mounts the handler at /generic/ on a server.
func (h *Handler) Register(s interface{ Handle(string, http.Handler) }) {
	s.Handle(repo.Prefix(config.FormatGeneric), h)
}

// RunProxy does the proxy repositories' background work until ctx is
// done, if the handler built its own path cache; a shared one is run by
// its owner.
func (h *Handler) RunProxy(ctx context.Context) {
	if !h.ownPaths {
		return
	}
	if h.ownDocs {
		go h.docs.Run(ctx, config.DefaultRevalidateAfter)
	}
	h.paths.Run(ctx)
}

// ServeHTTP routes a /generic/ request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, sub, slash, _ := repo.Split(config.FormatGeneric, r.URL.Path)
	rp := h.repos[name]
	if rp == nil {
		// Repositories of other formats are not found here either.
		server.SetRoute(ctx, "generic.unknown")
		writeError(w, http.StatusNotFound, "%q is not a generic files repository on this server", abbrev(name))
		return
	}
	server.LogAttrs(ctx, slog.String("repository", name))
	if rp.typ != config.TypeHosted && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
		server.SetRoute(ctx, "generic.file")
		writeError(w, http.StatusBadRequest, "query strings are not supported: the path alone names a file")
		return
	}
	switch {
	case !slash:
		server.SetRoute(ctx, "generic.list")
		if allow(w, r, http.MethodGet, http.MethodHead) {
			http.Redirect(w, r, repo.Path(config.FormatGeneric, name), http.StatusMovedPermanently)
		}
	case sub == "" || strings.HasSuffix(sub, "/"):
		server.SetRoute(ctx, "generic.list")
		if sub != "" && !ValidPath(strings.TrimSuffix(sub, "/")) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if allow(w, r, http.MethodGet, http.MethodHead) && h.permit(w, r, rp, ActionPull) {
			h.serveListing(w, r, rp, sub)
		}
	case !ValidPath(sub):
		server.SetRoute(ctx, "generic.file")
		writeError(w, http.StatusNotFound, "%q is not a valid file path: use segments separated by \"/\", none of them empty, \".\", or \"..\"", abbrev(sub))
	default:
		server.SetRoute(ctx, "generic.file")
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			if h.permit(w, r, rp, ActionPull) {
				h.serveFile(w, r, rp, sub)
			}
		case http.MethodPut:
			server.SetRoute(ctx, "generic.upload")
			h.serveUpload(w, r, rp, sub)
		case http.MethodDelete:
			server.SetRoute(ctx, "generic.delete")
			h.serveDelete(w, r, rp, sub)
		default:
			allow(w, r, http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete)
		}
	}
}

// permit authorizes the request for actions on rp, writing the response
// when it is refused. For a virtual repository, actions other than pull
// are authorized on its publishTo member.
func (h *Handler) permit(w http.ResponseWriter, r *http.Request, rp *repository, actions ...string) bool {
	if rp.typ == config.TypeVirtual {
		return h.auth.AuthorizeVirtual(w, r, rp.name, rp.virtual.PublishTo, actions...)
	}
	return h.auth.Authorize(w, r, rp.name, actions...)
}

// maxPath bounds a file path's length in bytes.
const maxPath = 1024

// ValidPath reports whether p is a file path: 1 to 1024 bytes of UTF-8
// without control characters, in segments separated by "/", none of
// them empty, ".", or "..".
func ValidPath(p string) bool {
	if p == "" || len(p) > maxPath || !utf8.ValidString(p) {
		return false
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) {
			return false
		}
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
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

// writeError writes a plain-text error, which curl and wget show.
func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	h := w.Header()
	h.Del("Content-Length")
	h.Del("ETag")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, format+"\n", args...)
}

// writeErrorMsg writes msg as a plain-text error, for the path cache.
func writeErrorMsg(w http.ResponseWriter, _ *http.Request, status int, msg string) {
	writeError(w, status, "%s", msg)
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

// errRetry means a batch lost a race with garbage collection or another
// writer and the client should retry.
var errRetry = errorf(http.StatusServiceUnavailable, "the registry is busy with this content; retry the request")

// fail answers a request with err: its own response for an *httpError,
// nothing for a cancelled request, and 500 otherwise.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpError
	switch {
	case errors.As(err, &he):
		if he.status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "1")
		}
		writeError(w, he.status, "%s", he.msg)
	case r.Context().Err() != nil:
		// The client went away.
	case errors.Is(err, meta.ErrPoisoned), errors.Is(err, meta.ErrClosed):
		writeError(w, http.StatusServiceUnavailable, "the registry cannot accept writes now")
	default:
		h.log.ErrorContext(r.Context(), "generic request failed", "path", r.URL.Path, "err", err)
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
