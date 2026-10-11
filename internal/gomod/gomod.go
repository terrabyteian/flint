// Package gomod serves Go module repositories for the go command, which
// uses one as its GOPROXY: proxy repositories that cache an upstream
// module proxy such as proxy.golang.org, and the Go checksum database
// for clients that cannot reach it, and virtual repositories that merge
// several proxy repositories behind one URL. Hosted Go modules are not
// served: the go command has no publish.
//
// Each repository is served under /go/<repo>/, with the GOPROXY
// protocol's endpoints below it and the checksum database's below
// /go/<repo>/sumdb/<name>/:
//
//	GET /go/<repo>/<module>/@v/list                 the module's known versions
//	GET /go/<repo>/<module>/@v/<version>.info       a version's metadata, or a query's answer
//	GET /go/<repo>/<module>/@v/<version>.mod        a version's go.mod file
//	GET /go/<repo>/<module>/@v/<version>.zip        a version's module zip
//	GET /go/<repo>/<module>/@latest                 the latest version's metadata
//	GET /go/<repo>/sumdb/<name>/supported           200: the checksum database is proxied
//	GET /go/<repo>/sumdb/<name>/latest              the database's signed tree head
//	GET /go/<repo>/sumdb/<name>/lookup/<module>@<version>  a module version's record
//	GET /go/<repo>/sumdb/<name>/tile/...            the database's tiles
//
// Module paths and versions are case-encoded, as the protocol requires.
// Requests are authorized with the Basic challenge style: the go command
// sends credentials from .netrc, or headers from a GOAUTH command, such
// as Authorization: Bearer with an API token, and only over HTTPS.
package gomod

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/auth"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/server"
	"github.com/terrabyteian/flint/internal/upstream"
)

// Authorizer authorizes requests, writing the response to those it
// refuses; *auth.Authorizer implements it.
type Authorizer interface {
	// Authorize reports whether the request may perform every action on
	// repository repo.
	Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool
	// AuthorizeVirtual reports whether the request may perform every
	// action through virtual repository virtual.
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
	// Repositories are the configured repositories; those with format
	// "go" are served.
	Repositories []config.Repository
	// Authorizer authorizes every request. Required.
	Authorizer Authorizer
	// Upstream holds the defaults for proxy repositories' upstream
	// clients, such as the user agent.
	Upstream upstream.Options
	// Paths is the path-cache engine shared with other formats' proxy
	// repositories, and Docs the document cache it uses, through which
	// the handler reads documents; whoever made them runs them. ProxyMetrics
	// are the proxy metrics they count in. Required.
	Paths        *upstream.PathCache
	Docs         *upstream.DocCache
	ProxyMetrics *upstream.Metrics
	// VirtualMetrics are the virtual repository metrics shared with other
	// formats; nil registers them on Metrics.
	VirtualMetrics *repo.Metrics
	// Metrics, if set, receives the metrics registered here.
	Metrics *metrics.Registry
	// Logger receives failures; nil means slog.Default().
	Logger *slog.Logger
	// Actor names the principal behind a request in the origin of the
	// metadata batches it writes; nil names the client address.
	Actor func(*http.Request) string
	// Now is the clock of the upstream clients; nil means time.Now.
	Now func() time.Time
}

// repository is a configured Go repository.
type repository struct {
	name    string
	proxy   *proxyRepo    // for a proxy repository
	virtual *repo.Virtual // for a virtual repository
}

// Handler serves Go repositories.
type Handler struct {
	repos map[string]*repository
	auth  Authorizer
	paths *upstream.PathCache
	docs  *upstream.DocCache
	pm    *upstream.Metrics
	log   *slog.Logger
	actor func(*http.Request) string
}

// New returns a Handler.
func New(opts Options) (*Handler, error) {
	if opts.Authorizer == nil || opts.Paths == nil || opts.Docs == nil || opts.ProxyMetrics == nil {
		return nil, errors.New("gomod: an Authorizer, Paths, Docs, and ProxyMetrics are required")
	}
	h := &Handler{repos: map[string]*repository{}, auth: opts.Authorizer, paths: opts.Paths, docs: opts.Docs,
		pm: opts.ProxyMetrics, log: opts.Logger, actor: opts.Actor}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.actor == nil {
		h.actor = clientActor
	}
	vm := opts.VirtualMetrics
	if vm == nil {
		reg := opts.Metrics
		if reg == nil {
			reg = metrics.NewRegistry() // unexposed; keeps the counters usable
		}
		vm = repo.NewMetrics(reg)
	}
	upOpts := opts.Upstream
	if upOpts.Logger == nil {
		upOpts.Logger = h.log
	}
	if upOpts.Now == nil {
		upOpts.Now = opts.Now
	}
	for _, rc := range opts.Repositories {
		if rc.Format != config.FormatGo {
			continue
		}
		r := &repository{name: rc.Name}
		switch rc.Type {
		case config.TypeProxy:
			p, err := newProxyRepo(rc, upOpts)
			if err != nil {
				return nil, fmt.Errorf("gomod: proxy repository %s: %w", rc.Name, err)
			}
			if err := h.paths.Add(p.path); err != nil {
				return nil, err
			}
			r.proxy = p
		case config.TypeVirtual:
			v, err := repo.NewVirtual(rc, opts.Repositories, repo.VirtualOptions{Logger: h.log, Metrics: vm})
			if err != nil {
				return nil, err
			}
			r.virtual = v
		default:
			return nil, fmt.Errorf("gomod: repository %s has unsupported type %q", rc.Name, rc.Type)
		}
		h.repos[rc.Name] = r
	}
	return h, nil
}

// Register mounts the handler at /go/ on a server.
func (h *Handler) Register(s interface{ Handle(string, http.Handler) }) {
	s.Handle(repo.Prefix(config.FormatGo), h)
}

// request is a parsed request below a repository.
type request struct {
	kind string // kindList and so on
	// mod and ver are the module path and version or query, decoded,
	// and escMod and escVer as the request encoded them.
	mod, ver       string
	escMod, escVer string
	// db is the checksum database's name, and dbPath the path below it,
	// such as "latest" or "tile/8/0/001", for kindSumDB.
	db, dbPath string
}

// Kinds of request, which name their routes in logs as "go.<kind>".
const (
	kindList   = "list"
	kindLatest = "latest"
	kindInfo   = "info"
	kindMod    = "mod"
	kindZip    = "zip"
	kindSumDB  = "sumdb"
)

// parseRequest parses the path below a repository, or reports false if
// it names nothing the repository serves.
func parseRequest(p string) (*request, bool) {
	if rest, ok := strings.CutPrefix(p, "sumdb/"); ok {
		db, sub, ok := strings.Cut(rest, "/")
		if !ok || db == "" || sub == "" {
			return nil, false
		}
		return &request{kind: kindSumDB, db: db, dbPath: sub}, true
	}
	req := &request{}
	if m, ok := strings.CutSuffix(p, "/@latest"); ok {
		req.kind, req.escMod = kindLatest, m
	} else {
		i := strings.LastIndex(p, "/@v/")
		if i < 0 {
			return nil, false
		}
		req.escMod = p[:i]
		file := p[i+len("/@v/"):]
		if file == "list" {
			req.kind = kindList
		} else {
			dot := strings.LastIndexByte(file, '.')
			if dot < 0 {
				return nil, false
			}
			switch ext := file[dot+1:]; ext {
			case "info", "mod", "zip":
				req.kind, req.escVer = ext, file[:dot]
			default:
				return nil, false
			}
			var ok bool
			if req.ver, ok = unescape(req.escVer); !ok || !validVersion(req.ver) {
				return nil, false
			}
			if req.kind != kindInfo && !canonical(req.ver) {
				return nil, false
			}
		}
	}
	var ok bool
	if req.mod, ok = unescape(req.escMod); !ok || !validPath(req.mod) {
		return nil, false
	}
	return req, true
}

// ServeHTTP routes a /go/ request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, rest, slash, _ := repo.Split(config.FormatGo, r.URL.Path)
	rp := h.repos[name]
	if rp == nil {
		// Repositories of other formats are not found here either.
		server.SetRoute(ctx, "go.unknown")
		writeError(w, http.StatusNotFound, "%q is not a Go repository on this server", abbrev(name))
		return
	}
	server.LogAttrs(ctx, slog.String("repository", name))
	req, ok := parseRequest(rest)
	if !slash || !ok {
		server.SetRoute(ctx, "go.unknown")
		writeError(w, http.StatusNotFound, "not found: %s serves the GOPROXY protocol; use %s as GOPROXY",
			name, server.BaseURL(r)+repo.Path(config.FormatGo, name))
		return
	}
	server.SetRoute(ctx, "go."+req.kind)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method %s is not allowed: Go repositories are read-only", r.Method)
		return
	}
	if rp.virtual != nil {
		if h.auth.AuthorizeVirtual(w, r, name, "", auth.ActionPull) {
			h.serveVirtual(w, r, rp, req)
		}
		return
	}
	if h.auth.Authorize(w, r, name, auth.ActionPull) {
		h.serveProxy(w, r, rp.proxy, req)
	}
}

// writeError writes a plain-text error, which the go command shows.
func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, format+"\n", args...)
}

// clientActor names a request's principal by its client address.
func clientActor(r *http.Request) string {
	if ip := server.Info(r.Context()).ClientIP; ip.IsValid() {
		return "client " + ip.String()
	}
	return meta.ActorAnonymous
}

// abbrev shortens s for messages.
func abbrev(s string) string {
	const max = 100
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
