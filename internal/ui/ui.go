// Package ui serves flint's web UI at /ui/: server-rendered pages, from
// html/template and the embedded templates and static assets, to browse
// repositories, images, packages, and their files, and to manage one's
// own password and API tokens. Administration stays in the admin API and
// the configuration; administrators get a read-only status page.
//
// # Sessions
//
// Users sign in on the auth package's sign-in page, auth.SignInPath,
// with a password or through an OIDC provider, and get the sign-in
// session that auth keeps in its cookie; the UI reads that session and
// sends users there to sign in and out. Anonymous visitors see the
// repositories that allow anonymous pulls.
//
// # Requests
//
// Every page answers with a strict Content-Security-Policy that allows
// only the UI's own scripts, styles, and images, so the pages hold no
// inline script or style. Every form that changes state is a POST, which
// is refused when the browser says it comes from another origin
// (auth.Service.CheckCrossOrigin), the protection every request
// authenticated with a sign-in session gets. Pages are never cached.
//
// Every page checks the permission model as the package routes do: a
// repository is shown to those who may read it, a virtual repository
// needs read on itself only, and the status page needs the global admin
// role. A repository the client may not read is not found, or, for an
// anonymous client, asks it to sign in.
package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/auth"
	"github.com/terrabyteian/flint/internal/backup"
	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/server"
)

// Prefix is the path the UI is served under.
const Prefix = "/ui/"

// contentSecurityPolicy allows only the UI's own scripts, styles, and
// images, forms that post to the UI, and no framing.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

//go:embed templates static
var assets embed.FS

// Status is what the administrators' status page shows of the server's
// background work. Every field is optional.
type Status struct {
	// GC returns the garbage collector's status.
	GC func() gc.Status
	// Backup returns the backup manager's status, or false if backups are
	// not configured.
	Backup func() (backup.Status, bool)
	// Space reports the free space of the data directory's filesystem
	// that proxy repositories watch, and whether it is below their
	// minimum, so they stopped caching.
	Space interface {
		Free() uint64
		Pressure() bool
	}
}

// Options configures a Handler.
type Options struct {
	// Auth authenticates users and holds their sessions and tokens.
	// Required.
	Auth *auth.Service
	// Config supplies the repositories and permission grants. Required.
	Config *config.Config
	// Images shows OCI repositories.
	Images browse.Images
	// Packages show the hosted repositories of each format whose
	// packages are named and versioned, by format, and PyPI proxy
	// repositories.
	Packages map[string]browse.Packages
	// Files show the hosted repositories of each format that are trees of
	// paths, by format.
	Files map[string]browse.Files
	// Cache shows what proxy repositories of path-addressed formats
	// cached.
	Cache browse.Files
	// Status feeds the administrators' status page.
	Status Status
	// Version is flint's version, shown in the footer.
	Version string
	// Logger receives errors; nil means slog.Default().
	Logger *slog.Logger
}

// Handler serves the web UI.
type Handler struct {
	opts   Options
	auth   *auth.Service
	repos  []config.Repository
	byName map[string]*config.Repository
	log    *slog.Logger
	pages  map[string]*template.Template
	static map[string]staticFile
	// assetVersion is a hash of the static files, appended to their URLs
	// so browsers may cache them indefinitely.
	assetVersion string
}

type staticFile struct {
	body        []byte
	contentType string
}

// New returns a Handler, parsing the embedded templates.
func New(opts Options) (*Handler, error) {
	if opts.Auth == nil || opts.Config == nil {
		return nil, errors.New("ui: Options.Auth and Options.Config are required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	h := &Handler{opts: opts, auth: opts.Auth, repos: opts.Config.Repositories, byName: map[string]*config.Repository{},
		log: opts.Logger, pages: map[string]*template.Template{}, static: map[string]staticFile{}}
	for i := range h.repos {
		h.byName[h.repos[i].Name] = &h.repos[i]
	}
	sum := sha256.New()
	err := fs.WalkDir(assets, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := assets.ReadFile(p)
		if err != nil {
			return err
		}
		ct := mime.TypeByExtension(path.Ext(p))
		if ct == "" {
			ct = "application/octet-stream"
		}
		name := strings.TrimPrefix(p, "static/")
		h.static[name] = staticFile{body: b, contentType: ct}
		sum.Write([]byte(name))
		sum.Write(b)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ui: reading static assets: %w", err)
	}
	h.assetVersion = hex.EncodeToString(sum.Sum(nil))[:12]

	pages, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, p := range pages {
		name := strings.TrimSuffix(path.Base(p), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New(name).Funcs(h.funcs()).ParseFS(assets, "templates/layout.html", p)
		if err != nil {
			return nil, fmt.Errorf("ui: parsing template %s: %w", p, err)
		}
		h.pages[name] = t
	}
	return h, nil
}

// Register adds the UI's routes to srv, and redirects the server's root
// to the UI.
func (h *Handler) Register(srv interface{ Handle(string, http.Handler) }) {
	for pattern, f := range map[string]func(*request){
		"GET /ui/{$}":                                              h.home,
		"GET /ui/repositories/{repo}":                              h.repository,
		"GET /ui/repositories/{repo}/packages/{name...}":           h.packagePage,
		"GET /ui/repositories/{repo}/images/{name...}":             h.imagePage,
		"GET /ui/repositories/{repo}/manifests/{digest}/{name...}": h.manifestPage,
		"GET /ui/account":                                          h.account,
		"POST /ui/account/password":                                h.changePassword,
		"POST /ui/account/tokens":                                  h.createToken,
		"POST /ui/account/tokens/{id}/revoke":                      h.revokeToken,
		"GET /ui/admin":                                            h.admin,
		"/ui/":                                                     h.notFoundPage,
	} {
		srv.Handle(pattern, h.wrap(f))
	}
	srv.Handle("GET /ui/static/{file}", http.HandlerFunc(h.serveStatic))
	srv.Handle("GET /{$}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, basePath(r)+Prefix, http.StatusFound)
	}))
}

// basePath returns the path a reverse proxy serves flint under, the path
// of its public URL, such as "/flint", or "". Every URL the UI writes is
// this path followed by a path from the server's root.
func basePath(r *http.Request) string {
	u, err := url.Parse(server.BaseURL(r))
	if err != nil {
		return ""
	}
	return strings.TrimRight(u.EscapedPath(), "/")
}

// request is a UI request with its principal.
type request struct {
	w http.ResponseWriter
	r *http.Request
	h *Handler
	// p is the signed-in principal, or an anonymous one.
	p *auth.Principal
	// base is the request's basePath.
	base string
}

func (rq *request) signedIn() bool { return rq.p.User != "" }

// wrap serves f with the UI's headers, the client's session, and, for a
// POST, the cross-site checks.
func (h *Handler) wrap(f func(*request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Content-Security-Policy", contentSecurityPolicy)
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "same-origin")
		hdr.Set("Cache-Control", "no-store")
		rq := &request{w: w, r: r, h: h, p: &auth.Principal{}, base: basePath(r)}
		switch p, err := h.auth.SessionPrincipal(r); {
		case err == nil && p != nil:
			rq.p = p
		case err != nil && !errors.Is(err, auth.ErrInvalidCredentials):
			// An ended or expired session is the same as none.
			h.serverError(rq, err)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if h.auth.CheckCrossOrigin(r) != nil {
				rq.render(http.StatusForbidden, "error", "Request refused", errorData{
					Heading: "Request refused",
					Message: "The form came from another site. Go back to flint's own page and try again."})
				return
			}
			if err := r.ParseForm(); err != nil {
				rq.render(http.StatusBadRequest, "error", "Bad request", errorData{
					Heading: "Bad request", Message: "The form could not be read."})
				return
			}
		}
		f(rq)
	})
}

// serveStatic serves an embedded static file.
func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request) {
	f, ok := h.static[r.PathValue("file")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", f.contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("v") == h.assetVersion {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("ETag", `"`+h.assetVersion+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.body))
}

// page is what every template receives.
type page struct {
	Title string
	// Base is the basePath that every URL the page writes starts with.
	Base string
	// Nav names the active navigation entry.
	Nav      string
	User     *auth.Principal
	Version  string
	AssetVer string
	// SignIn and SignOut are the sign-in page, returning to this page, and
	// the sign-out endpoint.
	SignIn, SignOut string
	Data            any
}

// render renders template name with data as the page's body.
func (rq *request) render(status int, name, title string, data any) {
	h := rq.h
	t := h.pages[name]
	pg := &page{Title: title, Base: rq.base, User: rq.p, Version: h.opts.Version, AssetVer: h.assetVersion,
		SignIn: rq.signInHref(), SignOut: rq.base + auth.SignOutPath, Data: data}
	if !rq.signedIn() {
		pg.User = nil
	}
	if n, ok := data.(interface{ nav() string }); ok {
		pg.Nav = n.nav()
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", pg); err != nil {
		h.log.Error("rendering a UI page failed", "page", name, "err", err)
		http.Error(rq.w, "internal server error", http.StatusInternalServerError)
		return
	}
	rq.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	rq.w.WriteHeader(status)
	rq.w.Write(buf.Bytes())
}

// errorData is the error page's data.
type errorData struct {
	Heading, Message string
}

func (rq *request) notFound() {
	rq.render(http.StatusNotFound, "error", "Not found", errorData{Heading: "Not found",
		Message: "There is nothing here, or you are not allowed to see it."})
}

// denied answers a request for something the client may not see: an
// anonymous client is asked to sign in, and anyone else is told it is
// not found, so names are not revealed.
func (rq *request) denied() {
	if rq.signedIn() {
		rq.notFound()
		return
	}
	http.Redirect(rq.w, rq.r, rq.signInHref(), http.StatusSeeOther)
}

// signInHref is the sign-in page, which returns to this page after
// signing in.
func (rq *request) signInHref() string {
	return rq.base + auth.SignInPath + "?return=" + url.QueryEscape(rq.base+rq.r.URL.RequestURI())
}

func (h *Handler) serverError(rq *request, err error) {
	h.log.Error("serving a UI page failed", "path", rq.r.URL.Path, "err", err)
	rq.render(http.StatusInternalServerError, "error", "Error", errorData{Heading: "Something went wrong",
		Message: "The server could not show this page. The error is in its log."})
}

func (h *Handler) notFoundPage(rq *request) { rq.notFound() }

// canRead reports whether the client may read repository name.
func (rq *request) canRead(name string) bool {
	return rq.h.auth.Role(rq.p, name) >= auth.RoleRead
}

// readable returns the repository named by the request's {repo}, if the
// client may read it; otherwise it answers the request and returns nil.
func (rq *request) readable() *config.Repository {
	rc := rq.h.byName[rq.r.PathValue("repo")]
	if rc == nil || !rq.canRead(rc.Name) {
		rq.denied()
		return nil
	}
	return rc
}

// browseError answers a failed browse call.
func (rq *request) browseError(err error) {
	if errors.Is(err, browse.ErrNotFound) {
		rq.notFound()
		return
	}
	rq.h.serverError(rq, err)
}

// detach returns a context for work that must finish even if the client
// goes away, such as ending a session.
func detach(ctx context.Context) context.Context { return context.WithoutCancel(ctx) }
