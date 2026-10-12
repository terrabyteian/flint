// Package ui serves flint's web UI at /ui/: server-rendered pages, from
// html/template and the embedded templates and static assets, to browse
// repositories, images, packages, and their files, and to manage one's
// own password and API tokens. Administration stays in the admin API and
// the configuration; administrators get a read-only status page.
//
// # Sessions
//
// Users sign in with their password, or with a sign-in provider that
// another package registers (see SignInProvider and Handler.SignInAs),
// and get a session from the auth package, held in the flint_session
// cookie: HttpOnly, SameSite=Lax, Secure when the client reached flint
// over TLS, and scoped to /ui/, so the API and package routes never see
// it. Anonymous visitors see the repositories that allow anonymous
// pulls.
//
// # Requests
//
// Every page answers with a strict Content-Security-Policy that allows
// only the UI's own scripts, styles, and images, so the pages hold no
// inline script or style. Every form that changes state is a POST that
// must carry a CSRF token, an HMAC keyed by the session's secret (or,
// for the sign-in form, by the flint_csrf cookie's random value), and
// is refused when the browser says it comes from another site. Pages
// are never cached.
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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
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

// Cookie names.
const (
	sessionCookie = "flint_session"
	csrfCookie    = "flint_csrf"
)

// minCSRFCookie is the shortest flint_csrf cookie accepted: the length
// of rand.Text, 128 random bits.
const minCSRFCookie = 26

// contentSecurityPolicy allows only the UI's own scripts, styles, and
// images, forms that post to the UI, and no framing.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

//go:embed templates static
var assets embed.FS

// SignInProvider is a way to sign in besides a password, such as an
// OpenID Connect provider: the sign-in page links to URL with a button
// labeled "Sign in with <Name>". The package serving URL signs the user
// in with Handler.SignInAs.
type SignInProvider struct {
	Name string
	URL  string
}

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
	// SignIn are the sign-in providers besides passwords.
	SignIn []SignInProvider
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
	// csrfKey keys the sign-in form's CSRF tokens before a session
	// exists, with the flint_csrf cookie's value.
	csrfKey []byte
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
	h.csrfKey = make([]byte, 32)
	rand.Read(h.csrfKey)

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
		"GET /ui/{$}":                 h.home,
		"GET /ui/login":               h.loginPage,
		"POST /ui/login":              h.login,
		"POST /ui/logout":             h.logout,
		"GET /ui/repositories/{repo}": h.repository,
		"GET /ui/repositories/{repo}/packages/{name...}":           h.packagePage,
		"GET /ui/repositories/{repo}/images/{name...}":             h.imagePage,
		"GET /ui/repositories/{repo}/manifests/{digest}/{name...}": h.manifestPage,
		"GET /ui/account":                     h.account,
		"POST /ui/account/password":           h.changePassword,
		"POST /ui/account/tokens":             h.createToken,
		"POST /ui/account/tokens/{id}/revoke": h.revokeToken,
		"GET /ui/admin":                       h.admin,
		"/ui/":                                h.notFoundPage,
	} {
		srv.Handle(pattern, h.wrap(f))
	}
	srv.Handle("GET /ui/static/{file}", http.HandlerFunc(h.serveStatic))
	srv.Handle("GET /{$}", http.RedirectHandler(Prefix, http.StatusFound))
}

// request is a UI request with its principal.
type request struct {
	w http.ResponseWriter
	r *http.Request
	h *Handler
	// p is the signed-in principal, or an anonymous one.
	p *auth.Principal
	// secret is the session's secret, "" without a session.
	secret string
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
		rq := &request{w: w, r: r, h: h, p: &auth.Principal{}}
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			p, err := h.auth.SessionPrincipal(c.Value)
			switch {
			case err == nil:
				rq.p, rq.secret = p, c.Value
				server.LogAttrs(r.Context(), slog.String("user", p.User))
			case errors.Is(err, auth.ErrInvalidCredentials):
				h.clearCookie(w, r, sessionCookie)
			default:
				h.serverError(rq, err)
				return
			}
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if !sameOrigin(r) || !h.validCSRF(rq, r.PostFormValue("csrf")) {
				rq.render(http.StatusForbidden, "error", "Request refused", errorData{
					Heading: "Request refused",
					Message: "The form expired or came from another site. Go back, reload the page, and try again."})
				return
			}
		}
		f(rq)
	})
}

// sameOrigin reports whether a browser's request comes from the UI's own
// origin, as Sec-Fetch-Site or else Origin says; a request with neither,
// from a client that is not a browser, passes, and the CSRF token still
// guards it.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return u.Host == r.Host || o == server.Origin(r) || o == server.BaseURL(r)
}

// csrfToken returns the CSRF token for the forms of rq's pages, setting
// the flint_csrf cookie it is keyed by if the client has no session.
func (rq *request) csrfToken() string {
	if rq.secret != "" {
		return mac([]byte(rq.secret), "csrf")
	}
	c, err := rq.r.Cookie(csrfCookie)
	if err != nil || len(c.Value) < minCSRFCookie {
		c = &http.Cookie{Name: csrfCookie, Value: rand.Text()}
		rq.h.setCookie(rq.w, rq.r, c, time.Time{})
		// Later reads in this request see the new value.
		rq.r.AddCookie(c)
	}
	return mac(rq.h.csrfKey, c.Value)
}

// validCSRF checks a form's CSRF token.
func (h *Handler) validCSRF(rq *request, token string) bool {
	var want string
	if rq.secret != "" {
		want = mac([]byte(rq.secret), "csrf")
	} else if c, err := rq.r.Cookie(csrfCookie); err == nil && len(c.Value) >= minCSRFCookie {
		want = mac(h.csrfKey, c.Value)
	}
	return want != "" && hmac.Equal([]byte(token), []byte(want))
}

func mac(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// secure reports whether the client reached flint over TLS.
func secure(r *http.Request) bool {
	if s := server.Info(r.Context()).Scheme; s != "" {
		return s == "https"
	}
	return r.TLS != nil
}

func (h *Handler) setCookie(w http.ResponseWriter, r *http.Request, c *http.Cookie, expires time.Time) {
	c.Path = Prefix
	c.HttpOnly = true
	c.Secure = secure(r)
	c.SameSite = http.SameSiteLaxMode
	c.Expires = expires
	http.SetCookie(w, c)
}

func (h *Handler) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	h.setCookie(w, r, &http.Cookie{Name: name, MaxAge: -1}, time.Time{})
}

// SignInAs signs user in, whom the caller has authenticated, as a sign-in
// provider's callback does: it starts a session, recorded as started by
// method, such as "oidc", and sets its cookie on w. The caller then
// redirects to the UI, such as to Prefix. It returns
// auth.ErrInvalidCredentials if the user does not exist.
func (h *Handler) SignInAs(w http.ResponseWriter, r *http.Request, user, method string) error {
	secret, expires, err := h.auth.StartSession(r.Context(), user, method)
	if err != nil {
		return err
	}
	h.setCookie(w, r, &http.Cookie{Name: sessionCookie, Value: secret}, expires)
	return nil
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
	// Nav names the active navigation entry.
	Nav       string
	User      *auth.Principal
	Version   string
	AssetVer  string
	Providers []SignInProvider
	Data      any
	rq        *request
}

// CSRF returns the CSRF token for the page's forms.
func (pg *page) CSRF() string { return pg.rq.csrfToken() }

// render renders template name with data as the page's body.
func (rq *request) render(status int, name, title string, data any) {
	h := rq.h
	t := h.pages[name]
	pg := &page{Title: title, User: rq.p, Version: h.opts.Version, AssetVer: h.assetVersion,
		Providers: h.opts.SignIn, Data: data, rq: rq}
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
	http.Redirect(rq.w, rq.r, "/ui/login?next="+url.QueryEscape(rq.r.URL.RequestURI()), http.StatusSeeOther)
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
