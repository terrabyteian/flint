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
// back through the base URL, as does the link on to the web UI. It looks
// like the web UI: its style repeats the colors of the UI's stylesheet,
// internal/ui/static/style.css, in the page's own nonce'd style, since
// the page has its own Content-Security-Policy and does not depend on
// the UI.
var signInTemplate = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta name="color-scheme" content="light dark">
<title>Sign in · flint</title>
<style nonce="{{.Nonce}}">
:root { --bg: #fafaf9; --surface: #fff; --surface-2: #f5f5f4; --text: #1c1917; --muted: #57534e; --border: #e7e5e4;
  --border-strong: #d6d3d1; --accent: #c2410c; --accent-hover: #9a3412; --accent-text: #fff; --focus: #ea580c;
  --danger: #b91c1c; --danger-soft: #fef2f2; --code-bg: #1c1917; --code-text: #f5f5f4;
  --shadow: 0 1px 2px rgb(28 25 23 / .04), 0 8px 24px -8px rgb(28 25 23 / .12); color-scheme: light; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #0f0d0c; --surface: #1a1715; --surface-2: #231f1c; --text: #f5f5f4; --muted: #b8b2ad; --border: #2e2925;
    --border-strong: #443d38; --accent: #fb923c; --accent-hover: #fdba74; --accent-text: #1c1007; --focus: #fb923c;
    --danger: #f87171; --danger-soft: #2c1414; --code-bg: #0b0a09; --shadow: 0 0 0 1px rgb(0 0 0 / .2); color-scheme: dark; }
}
*, *::before, *::after { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 1.5rem 1rem; background: var(--bg); color: var(--text);
  font: .9375rem/1.55 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; -webkit-font-smoothing: antialiased; }
main { width: 100%; max-width: 24rem; }
.brand { display: flex; align-items: center; gap: .55rem; justify-content: center; margin-bottom: 1.25rem; font-weight: 700; font-size: 1.25rem; letter-spacing: -.02em; }
.mark { display: inline-grid; place-items: center; width: 2.1rem; height: 2.1rem; border-radius: 8px; background: #1c1917; color: #f59e0b; }
.mark svg { width: 1.3rem; height: 1.3rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; box-shadow: var(--shadow); }
h1 { font-size: 1.25rem; letter-spacing: -.01em; margin: 0 0 1rem; font-weight: 650; }
h2 { font-size: 1rem; margin: 1.25rem 0 .25rem; font-weight: 650; }
p { margin: .5rem 0; }
.muted { color: var(--muted); font-size: .875rem; }
label { display: block; font-weight: 600; font-size: .8125rem; margin: .75rem 0 .35rem; }
input { display: block; width: 100%; min-height: 2.5rem; padding: .5rem .7rem; font: inherit; color: var(--text); background: var(--surface);
  border: 1px solid var(--border-strong); border-radius: 6px; }
input:focus-visible { outline: 2px solid var(--focus); outline-offset: 0; border-color: var(--focus); }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
a.button, button { display: flex; align-items: center; justify-content: center; width: 100%; min-height: 2.5rem; margin: .75rem 0 0; padding: 0 1rem;
  font: inherit; font-weight: 600; color: var(--text); background: var(--surface); border: 1px solid var(--border-strong); border-radius: 6px;
  text-decoration: none; cursor: pointer; }
a.button:hover, button:hover { background: var(--surface-2); }
button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-text); margin-top: 1.1rem; }
button.primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
.provider + .provider { margin-top: .5rem; }
.provider:first-child { margin-top: 0; }
.or { display: flex; align-items: center; gap: .75rem; color: var(--muted); font-size: .8125rem; margin: 1.1rem 0 .25rem; }
.or::before, .or::after { content: ""; flex: 1; border-top: 1px solid var(--border); }
.error { padding: .6rem .8rem; border-radius: 8px; background: var(--danger-soft); color: var(--danger); font-size: .875rem; margin: 0 0 1rem; }
pre { white-space: pre-wrap; word-break: break-all; background: var(--code-bg); color: var(--code-text); padding: .7rem .8rem; border-radius: 8px;
  font: .8125rem/1.6 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.foot { text-align: center; margin-top: 1rem; font-size: .8125rem; }
a { color: var(--accent); }
</style>
</head>
<body>
<main>
<div class="brand"><span class="mark"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M13.5 2 4 14h7l-1.5 8L20 9.5h-7.2z" fill="currentColor"/></svg></span>flint</div>
<div class="card">
{{if .Failed}}
<h1>Sign in</h1>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<a class="button" href="{{.Base}}/auth/login">Back to sign-in</a>
{{else if .User}}
<h1>Signed in</h1>
<p>Signed in as <strong>{{.User}}</strong>.</p>
<a class="button" href="{{.Base}}/ui/">Continue to flint</a>
<h2>Create an API token</h2>
<p class="muted">Docker, PyPI, npm, and other package clients sign in with an API token.</p>
<form id="token">
<label for="token-name">Name</label><input id="token-name" name="name" required maxlength="128" value="cli">
<label for="token-expiry">Expires in</label><input id="token-expiry" name="expiresIn" value="720h" placeholder="such as 720h; empty for never">
<button type="submit" class="primary">Create token</button>
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
<h1>Sign in</h1>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
{{range .Providers}}<a class="button provider" href="oidc/{{.Name}}/login{{if $.Return}}?return={{$.Return}}{{end}}">Sign in with {{.DisplayName}}</a>
{{end}}{{if .Providers}}<p class="or">or</p>{{end}}
<form method="post" action="login">
<input type="hidden" name="return" value="{{.Return}}">
<label for="username">User name</label><input id="username" name="username" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit" class="primary">Sign in</button>
</form>
{{end}}
</div>
</main>
</body>
</html>
`))
