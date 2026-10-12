package auth

import (
	"crypto/rand"
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"github.com/terrabyteian/flint/internal/server"
)

// The sign-in endpoints start and end browser sessions:
//
//	GET  /auth/login                         the sign-in page
//	POST /auth/login                         sign in with a user name and password
//	POST /auth/logout                        sign out
//	GET  /auth/oidc/{provider}/login         sign in through an OIDC provider
//	GET  /auth/oidc/{provider}/callback      the provider's redirect back
//
// Each takes an optional "return" parameter, a path on this server to go
// to afterwards. The sign-in page is deliberately small: it lists the
// providers, takes a password, and, once signed in, creates API tokens
// through the admin API, until the UI serves its own pages.

// Paths of the sign-in endpoints.
const (
	SignInPath  = "/auth/login"
	SignOutPath = "/auth/logout"
)

// maxSignInForm bounds the sign-in form.
const maxSignInForm = 16 << 10

func (s *Service) registerSignIn(srv *server.Server) {
	srv.HandleFunc("GET "+SignInPath, s.handleSignInPage)
	srv.HandleFunc("POST "+SignInPath, s.handlePasswordSignIn)
	srv.HandleFunc("POST "+SignOutPath, s.handleSignOut)
	srv.HandleFunc("GET "+oidcPathPrefix+"{provider}"+oidcLoginPath, s.handleOIDCLogin)
	srv.HandleFunc("GET "+oidcPathPrefix+"{provider}"+oidcCallback, s.handleOIDCCallback)
}

// SignInProvider is an OIDC provider as the sign-in page lists it.
type SignInProvider struct {
	// Name is the provider's configured name; DisplayName is shown.
	Name, DisplayName string
	// LoginPath starts a sign-in through the provider, relative to the
	// server's base URL; add "?return=<path>" to come back to a page.
	LoginPath string
}

// SignInProviders lists the configured OIDC providers, in order.
func (s *Service) SignInProviders() []SignInProvider {
	if s.oidc == nil {
		return nil
	}
	out := make([]SignInProvider, 0, len(s.oidc.order))
	for _, name := range s.oidc.order {
		p := s.oidc.providers[name]
		out = append(out, SignInProvider{Name: name, DisplayName: p.cfg.Display(), LoginPath: oidcPathPrefix + name + oidcLoginPath})
	}
	return out
}

// signInPage is the sign-in page's data.
type signInPage struct {
	Base      string // the server's base URL
	Return    string
	Error     string
	User      string // the signed-in user, or ""
	Providers []SignInProvider
	Failed    bool   // an error page, with only a link back to sign in
	Nonce     string // the page's script and style nonce
}

func (s *Service) handleSignInPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	page := signInPage{Base: server.BaseURL(r), Return: r.URL.Query().Get("return"), Providers: s.SignInProviders()}
	if r.URL.Query().Get("error") == "invalid" {
		page.Error = "Incorrect user name or password."
	}
	switch p, err := s.SessionPrincipal(r); {
	case err != nil && !errors.Is(err, ErrInvalidCredentials):
		s.log.Error("authentication failed", "err", err)
		s.signInError(w, r, http.StatusInternalServerError, "Internal error.")
		return
	case p != nil:
		page.User = p.User
	}
	s.renderSignIn(w, http.StatusOK, page)
}

// handlePasswordSignIn signs a user in with a password from the sign-in
// form.
func (s *Service) handlePasswordSignIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := s.CheckCrossOrigin(r); err != nil {
		s.signInError(w, r, http.StatusForbidden, "Cross-origin sign-in is not allowed.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSignInForm)
	if err := r.ParseForm(); err != nil {
		s.signInError(w, r, http.StatusBadRequest, "Invalid sign-in form.")
		return
	}
	ret := r.PostForm.Get("return")
	p, err := s.checkPassword(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		target := server.BaseURL(r) + SignInPath + "?error=invalid"
		if ret != "" {
			target += "&return=" + url.QueryEscape(ret)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	case err != nil:
		s.log.Error("authentication failed", "err", err)
		s.signInError(w, r, http.StatusInternalServerError, "Internal error.")
		return
	}
	if err := s.startSession(r.Context(), w, r, p.User, "password"); err != nil {
		s.log.Error("starting a session failed", "user", p.User, "err", err)
		s.signInError(w, r, http.StatusInternalServerError, "Internal error.")
		return
	}
	http.Redirect(w, r, returnPath(r, ret), http.StatusSeeOther)
}

// handleSignOut ends the request's session.
func (s *Service) handleSignOut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := s.CheckCrossOrigin(r); err != nil {
		s.signInError(w, r, http.StatusForbidden, "Cross-origin sign-out is not allowed.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSignInForm)
	r.ParseForm()
	if err := s.endSession(r.Context(), w, r); err != nil {
		s.log.Error("ending a session failed", "err", err)
		s.signInError(w, r, http.StatusInternalServerError, "Internal error.")
		return
	}
	http.Redirect(w, r, returnPath(r, r.Form.Get("return")), http.StatusSeeOther)
}

// signInError shows an error page with a link back to the sign-in page.
func (s *Service) signInError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.renderSignIn(w, status, signInPage{Base: server.BaseURL(r), Error: msg, Failed: true})
}

func (s *Service) renderSignIn(w http.ResponseWriter, status int, page signInPage) {
	page.Nonce = rand.Text()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+page.Nonce+"'; script-src 'nonce-"+page.Nonce+"'; "+
		"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	if err := signInTemplate.Execute(w, page); err != nil {
		s.log.Debug("writing the sign-in page failed", "err", err)
	}
}

// signInTemplate is the sign-in page. Its links, forms, and requests use
// paths relative to /auth/login, so they work under a path prefix that a
// reverse proxy adds; only the error page, served at other paths, links
// back through the base URL.
var signInTemplate = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · flint</title>
<style nonce="{{.Nonce}}">
body { font: 16px/1.5 system-ui, sans-serif; max-width: 26rem; margin: 3rem auto; padding: 0 1rem; color: #1b1f24; background: #fff; }
h1 { font-size: 1.4rem; }
a.button, button { display: block; width: 100%; box-sizing: border-box; padding: .6rem; margin: .5rem 0; font: inherit;
  text-align: center; border: 1px solid #8c959f; border-radius: 6px; background: #f6f8fa; color: inherit; text-decoration: none; cursor: pointer; }
input { display: block; width: 100%; box-sizing: border-box; padding: .5rem; margin: .25rem 0 .75rem; font: inherit; border: 1px solid #8c959f; border-radius: 6px; }
.error { color: #b42318; }
.or { text-align: center; color: #57606a; margin: 1rem 0; }
pre { white-space: pre-wrap; word-break: break-all; background: #f6f8fa; padding: .5rem; border-radius: 6px; }
@media (prefers-color-scheme: dark) {
  body { color: #e6edf3; background: #0d1117; }
  a.button, button, input, pre { background: #161b22; border-color: #484f58; color: inherit; }
  .error { color: #ff7b72; }
}
</style>
</head>
<body>
<h1>flint</h1>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
{{if .Failed}}
<p><a class="button" href="{{.Base}}/auth/login">Back to sign-in</a></p>
{{else if .User}}
<p>Signed in as <strong>{{.User}}</strong>.</p>
<h2>Create an API token</h2>
<p>Docker, PyPI, npm, and other package clients sign in with an API token.</p>
<form id="token">
<label>Name <input name="name" required maxlength="128" value="cli"></label>
<label>Expires in <input name="expiresIn" value="720h" placeholder="such as 720h; empty for never"></label>
<button type="submit">Create token</button>
</form>
<pre id="result" hidden></pre>
<form method="post" action="logout"><input type="hidden" name="return" value="{{.Return}}"><button type="submit">Sign out</button></form>
<script nonce="{{.Nonce}}">
document.getElementById("token").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target), out = document.getElementById("result");
  const body = {name: f.get("name")};
  if (f.get("expiresIn")) body.expiresIn = f.get("expiresIn");
  const resp = await fetch("../api/v1/tokens", {method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  const data = await resp.json().catch(() => ({}));
  out.hidden = false;
  out.textContent = resp.ok ? "Copy the token now; it is not shown again:\n\n" + data.token : "Error: " + (data.error || resp.status);
});
</script>
{{else}}
{{range .Providers}}<a class="button" href="oidc/{{.Name}}/login{{if $.Return}}?return={{$.Return}}{{end}}">Sign in with {{.DisplayName}}</a>
{{end}}{{if .Providers}}<p class="or">or</p>{{end}}
<form method="post" action="login">
<input type="hidden" name="return" value="{{.Return}}">
<label>User name <input name="username" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form>
{{end}}
</body>
</html>
`))
