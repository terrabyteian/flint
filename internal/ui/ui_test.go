package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/auth"
)

func TestHeaders(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	for _, path := range []string{"/ui/", "/ui/login", "/ui/repositories/public", "/ui/nope"} {
		r := b.get(path)
		h := r.Header
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") ||
			!strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s: Content-Security-Policy %q", path, csp)
		}
		for k, v := range map[string]string{"Cache-Control": "no-store", "X-Frame-Options": "DENY",
			"X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin"} {
			if h.Get(k) != v {
				t.Errorf("%s: %s %q, want %q", path, k, h.Get(k), v)
			}
		}
		// No inline script or style that the policy would block.
		if strings.Contains(r.body, "<script>") || strings.Contains(r.body, " style=") || strings.Contains(r.body, "<style") ||
			regexp.MustCompile(` on[a-z]+="`).MatchString(r.body) {
			t.Errorf("%s: the page has inline script or style", path)
		}
	}
}

func TestRootRedirect(t *testing.T) {
	e := newEnv(t)
	r := e.browser().get("/")
	if r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/ui/" {
		t.Errorf("GET /: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
}

func TestStatic(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	r := b.expect("/ui/static/app.js?v="+e.h.assetVersion, http.StatusOK)
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("app.js Content-Type %q", ct)
	}
	if cc := r.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("versioned asset Cache-Control %q", cc)
	}
	if cc := b.expect("/ui/static/style.css", http.StatusOK).Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("unversioned asset Cache-Control %q", cc)
	}
	if ct := b.expect("/ui/static/favicon.svg", http.StatusOK).Header.Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("favicon Content-Type %q", ct)
	}
	b.expect("/ui/static/missing.js", http.StatusNotFound)
	// Pages reference the versioned assets.
	b.expect("/ui/", http.StatusOK).has(t, "/ui/static/app.js?v="+e.h.assetVersion, "/ui/static/style.css?v="+e.h.assetVersion)
}

// TestHomeVisibility shows each client the repositories it may read.
func TestHomeVisibility(t *testing.T) {
	e := newEnv(t)
	anon := e.browser()
	r := anon.expect("/ui/", http.StatusOK)
	r.has(t, ">public<", "Sign in</a> to see")
	r.lacks(t, ">oci-local<", ">secret<", ">pypi-local<", "Sign out")

	alice := e.browser()
	alice.signIn("alice", "alice-password")
	r = alice.expect("/ui/", http.StatusOK)
	r.has(t, ">public<", ">oci-local<", ">oci-all<", ">pypi-local<", ">pypi-remote<", ">files<", ">go-remote<", "Sign out", ">alice<")
	r.lacks(t, ">secret<", "Sign in</a> to see", `href="/ui/admin"`)

	bob := e.browser()
	bob.signIn("bob", "bob-password")
	r = bob.expect("/ui/", http.StatusOK)
	r.has(t, ">public<")
	r.lacks(t, ">oci-local<")

	root := e.browser()
	root.signIn("root", "root-password")
	r = root.expect("/ui/", http.StatusOK)
	r.has(t, ">secret<", ">broken<", `href="/ui/admin"`)

	// Filtering.
	r = alice.expect("/ui/?q=pypi", http.StatusOK)
	r.has(t, ">pypi-local<", ">pypi-remote<")
	r.lacks(t, ">oci-local<")
	r = alice.expect("/ui/?q=virtual", http.StatusOK)
	r.has(t, ">oci-all<")
	alice.expect("/ui/?q=nothing-matches", http.StatusOK).has(t, "No repository matches")
}

// TestPermissions checks every page against the permission model.
func TestPermissions(t *testing.T) {
	e := newEnv(t)
	anon, alice, bob, root := e.browser(), e.browser(), e.browser(), e.browser()
	alice.signIn("alice", "alice-password")
	bob.signIn("bob", "bob-password")
	root.signIn("root", "root-password")
	const (
		ok     = http.StatusOK
		login  = http.StatusSeeOther
		absent = http.StatusNotFound
	)
	for _, c := range []struct {
		path                   string
		anon, alice, bob, root int
	}{
		{"/ui/repositories/public", ok, ok, ok, ok},
		{"/ui/repositories/public/images/team/app", ok, ok, ok, ok},
		{"/ui/repositories/oci-local", login, ok, absent, ok},
		{"/ui/repositories/oci-local/images/team/app", login, ok, absent, ok},
		{"/ui/repositories/oci-local/manifests/" + indexDigest + "/team/app", login, ok, absent, ok},
		{"/ui/repositories/secret", login, absent, absent, ok},
		{"/ui/repositories/secret/images/team/app", login, absent, absent, ok},
		{"/ui/repositories/oci-all", login, ok, absent, ok},
		{"/ui/repositories/pypi-local/packages/acme-lib", login, ok, absent, ok},
		{"/ui/repositories/files?dir=tools/", login, ok, absent, ok},
		{"/ui/repositories/nonexistent", login, absent, absent, absent},
		{"/ui/account", login, ok, ok, ok},
		{"/ui/admin", login, absent, absent, ok},
	} {
		for _, u := range []struct {
			name string
			b    *browser
			want int
		}{{"anonymous", anon, c.anon}, {"alice", alice, c.alice}, {"bob", bob, c.bob}, {"root", root, c.root}} {
			r := u.b.get(c.path)
			if r.StatusCode != u.want {
				t.Errorf("%s GET %s: %d, want %d", u.name, c.path, r.StatusCode, u.want)
				continue
			}
			if u.want == login {
				want := "/ui/login?next=" + url.QueryEscape(c.path)
				if loc := r.Header.Get("Location"); loc != want {
					t.Errorf("%s GET %s: redirected to %q, want %q", u.name, c.path, loc, want)
				}
			}
		}
	}
}

// TestVirtualMembers shows a virtual repository's members, linking only
// those the client may read.
func TestVirtualMembers(t *testing.T) {
	e := newEnv(t)
	alice := e.browser()
	alice.signIn("alice", "alice-password")
	r := alice.expect("/ui/repositories/oci-all", http.StatusOK)
	r.has(t, `<a href="/ui/repositories/oci-local">oci-local</a>`, ">secret<", "publish target", "Dependency-confusion protection is on")
	r.lacks(t, `href="/ui/repositories/secret"`)
	r.has(t, "docker push")
}

func TestBrowsePages(t *testing.T) {
	e := newEnv(t)
	alice := e.browser()
	alice.signIn("alice", "alice-password")

	r := alice.expect("/ui/repositories/oci-local", http.StatusOK)
	r.has(t, `href="/ui/repositories/oci-local/images/team/app"`, "tools/web", "docker login", "docker pull",
		"helm repo add oci-local", "helm push")
	// Paging and filtering.
	r = alice.expect("/ui/repositories/oci-local?q=web", http.StatusOK)
	r.has(t, "tools/web")
	r.lacks(t, "team/app")

	r = alice.expect("/ui/repositories/oci-local/images/team/app", http.StatusOK)
	r.has(t, ">v1<", "index", "referrer", "application/vnd.dev.cosign.artifact.sig.v1+json",
		"docker pull 127.0.0.1", "/oci-local/team/app:v1",
		`href="/ui/repositories/oci-local/manifests/`+url.PathEscape(indexDigest)+`/team/app"`)
	alice.expect("/ui/repositories/oci-local/images/missing", http.StatusNotFound)

	r = alice.expect("/ui/repositories/oci-local/manifests/"+indexDigest+"/team/app", http.StatusOK)
	r.has(t, "Platforms", "linux/amd64", "linux/s390x", "Referrers", "application/vnd.dev.cosign.artifact.sig.v1+json",
		`href="/ui/repositories/oci-local/manifests/`+url.PathEscape(amdDigest)+`/team/app"`)
	// A child not stored under the image is not linked.
	r.lacks(t, url.PathEscape(layerDigest)+"/team/app")
	r = alice.expect("/ui/repositories/oci-local/manifests/"+amdDigest+"/team/app", http.StatusOK)
	r.has(t, "Layers", "config", "3.0 MiB", "No signatures or other referrers")
	alice.expect("/ui/repositories/oci-local/manifests/sha256:nope/team/app", http.StatusNotFound)

	r = alice.expect("/ui/repositories/pypi-local", http.StatusOK)
	r.has(t, "acme-lib", "The acme library", "pip install --index-url "+e.srv.URL+"/pypi/pypi-local/simple/")
	r = alice.expect("/ui/repositories/pypi-local/packages/acme-lib", http.StatusOK)
	r.has(t, "2.0", "yanked: broken", "acme_lib-2.0.tar.gz", "2.0 KiB", `href="/pypi/x/files/acme-lib/acme_lib-2.0.tar.gz"`,
		"pip install --index-url", "acme-lib==2.0")
	alice.expect("/ui/repositories/pypi-local/packages/missing", http.StatusNotFound)
	alice.expect("/ui/repositories/pypi-remote/packages/acme-lib", http.StatusOK)
	alice.expect("/ui/repositories/npm-local/packages/@acme/lib", http.StatusOK).has(t, "npm install @acme/lib@2.0", "latest")
	alice.expect("/ui/repositories/maven-local", http.StatusOK).has(t, "distributionManagement", "settings.gradle.kts")
	alice.expect("/ui/repositories/cargo-local", http.StatusOK).has(t, `index = "sparse+`+e.srv.URL+`/cargo/cargo-local/"`)
	// The wrong kind of page for a repository is not found.
	alice.expect("/ui/repositories/pypi-local/images/team/app", http.StatusNotFound)
	alice.expect("/ui/repositories/oci-local/packages/acme-lib", http.StatusNotFound)
	alice.expect("/ui/repositories/files/packages/acme-lib", http.StatusNotFound)

	r = alice.expect("/ui/repositories/files", http.StatusOK)
	r.has(t, `href="/ui/repositories/files?dir=tools%2F"`, `href="/generic/files/notes.txt"`, "curl -fsSLO")
	r = alice.expect("/ui/repositories/files?dir=tools/", http.StatusOK)
	r.has(t, "tool-1.0.tar.gz", `<a href="/ui/repositories/files?dir=tools%2F">tools</a>`)
	alice.expect("/ui/repositories/files?dir=missing/", http.StatusNotFound)
	alice.expect("/ui/repositories/go-remote", http.StatusOK).has(t, "Cached files", "go env -w GOPROXY="+e.srv.URL+"/go/go-remote")
	// A view's failure is a server error, which does not leak the error.
	r = alice.expect("/ui/repositories/broken", http.StatusInternalServerError)
	r.lacks(t, errBroken.Error())
}

func TestSignIn(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	r := b.expect("/ui/login?next=/ui/repositories/oci-local", http.StatusOK)
	r.has(t, `name="next" value="/ui/repositories/oci-local"`, "Sign in with Example SSO", `href="/auth/oidc/login"`)
	if c := cookie(r.Response, csrfCookie); c == nil || !c.HttpOnly || c.Path != "/ui/" {
		t.Fatalf("CSRF cookie %+v", c)
	}

	form := func(user, pw, next string) url.Values {
		return url.Values{"username": {user}, "password": {pw}, "next": {next}}
	}
	r = b.post("/ui/login", "/ui/login", form("alice", "wrong-password", ""))
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	r.has(t, "incorrect user name or password", `value="alice"`)
	if c := cookie(r.Response, sessionCookie); c != nil {
		t.Error("a failed sign-in set a session cookie")
	}
	// Without the CSRF token, or with another browser's.
	if r := b.do("POST", "/ui/login", form("alice", "alice-password", "")); r.StatusCode != http.StatusForbidden {
		t.Errorf("no CSRF token: %d", r.StatusCode)
	}
	other := e.browser()
	f := form("alice", "alice-password", "")
	f.Set("csrf", other.csrf("/ui/login"))
	if r := b.do("POST", "/ui/login", f); r.StatusCode != http.StatusForbidden {
		t.Errorf("another browser's CSRF token: %d", r.StatusCode)
	}

	r = b.post("/ui/login", "/ui/login", form("alice", "alice-password", "/ui/repositories/oci-local"))
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/ui/repositories/oci-local" {
		t.Fatalf("sign-in: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	c := cookie(r.Response, sessionCookie)
	if c == nil || !c.HttpOnly || c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/ui/" ||
		!strings.HasPrefix(c.Value, "flints_") || c.Expires.IsZero() {
		t.Fatalf("session cookie %+v", c)
	}
	// Signed in, the sign-in page goes where it was asked to.
	if r := b.get("/ui/login?next=/ui/account"); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/ui/account" {
		t.Errorf("sign-in page when signed in: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
}

// TestNextPath never redirects off the UI after signing in.
func TestNextPath(t *testing.T) {
	for next, want := range map[string]string{
		"/ui/account":          "/ui/account",
		"/ui/repositories/x?a": "/ui/repositories/x?a",
		"":                     "/ui/",
		"//evil.example/ui/":   "/ui/",
		"https://evil.example": "/ui/",
		"/api/v1/users":        "/ui/",
		"/ui/\\evil":           "/ui/",
		"/ui/\r\nSet-Cookie:":  "/ui/",
	} {
		if got := nextPath(next); got != want {
			t.Errorf("nextPath(%q) = %q, want %q", next, got, want)
		}
	}
}

func cookie(r *http.Response, name string) *http.Cookie {
	for _, c := range r.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestSecureCookie marks cookies Secure when the client reached flint
// over TLS.
func TestSecureCookie(t *testing.T) {
	e := newEnv(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://flint.example/ui/login", nil)
	e.h.wrap(e.h.loginPage).ServeHTTP(w, r)
	if c := cookie(w.Result(), csrfCookie); c == nil || !c.Secure {
		t.Errorf("CSRF cookie over TLS %+v", c)
	}
	w = httptest.NewRecorder()
	if err := e.h.SignInAs(w, httptest.NewRequest("GET", "https://flint.example/auth/callback", nil), "alice", "oidc"); err != nil {
		t.Fatal(err)
	}
	if c := cookie(w.Result(), sessionCookie); c == nil || !c.Secure || !c.HttpOnly {
		t.Errorf("session cookie over TLS %+v", c)
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.signIn("alice", "alice-password")
	b.expect("/ui/account", http.StatusOK)
	e.clock.Add(time.Hour)
	r := b.get("/ui/account")
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("account page after expiry: %d", r.StatusCode)
	}
	if c := cookie(r.Response, sessionCookie); c == nil || c.MaxAge >= 0 {
		t.Errorf("the expired session's cookie was not cleared: %+v", c)
	}
	b.expect("/ui/", http.StatusOK).has(t, "Sign in")
}

func TestSignOut(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.signIn("alice", "alice-password")
	u, _ := url.Parse(e.srv.URL + "/ui/")
	var secret string
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == sessionCookie {
			secret = c.Value
		}
	}
	// Signing out needs the CSRF token.
	if r := b.do("POST", "/ui/logout", url.Values{}); r.StatusCode != http.StatusForbidden {
		t.Errorf("sign-out without CSRF token: %d", r.StatusCode)
	}
	r := b.post("/ui/", "/ui/logout", nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/ui/" {
		t.Fatalf("sign-out: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	if r := b.get("/ui/account"); r.StatusCode != http.StatusSeeOther {
		t.Errorf("account page after signing out: %d", r.StatusCode)
	}
	// The session ended on the server, not only in the browser.
	if _, err := e.auth.SessionPrincipal(secret); err == nil {
		t.Error("the session outlived signing out")
	}
}

// TestCrossSite refuses state-changing requests from other sites even
// with a valid CSRF token.
func TestCrossSite(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.signIn("alice", "alice-password")
	token := b.csrf("/ui/account")
	create := func(hdr ...string) int {
		return b.do("POST", "/ui/account/tokens", url.Values{"csrf": {token}, "name": {"t"}, "expiry": {"7d"}, "scope": {"all"}},
			hdr...).StatusCode
	}
	for _, hdr := range [][]string{
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Site", "same-site"},
		{"Origin", "https://evil.example"},
		{"Origin", "null"},
	} {
		if got := create(hdr...); got != http.StatusForbidden {
			t.Errorf("%v: %d, want 403", hdr, got)
		}
	}
	if list, _ := e.auth.Tokens(principal(t, e, "alice")); len(list) != 0 {
		t.Fatalf("a refused request created a token: %+v", list)
	}
	for _, hdr := range [][]string{{"Sec-Fetch-Site", "same-origin"}, {"Origin", e.srv.URL}, nil} {
		if got := create(hdr...); got != http.StatusOK {
			t.Errorf("%v: %d, want 200", hdr, got)
		}
	}
	// A GET never changes anything, so needs no token.
	if r := b.get("/ui/account/tokens"); r.StatusCode != http.StatusNotFound && r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET of a form's target: %d", r.StatusCode)
	}
}

// principal returns the principal of a fresh session of user.
func principal(t *testing.T, e *env, user string) *auth.Principal {
	t.Helper()
	pw := map[string]string{"alice": "alice-password", "bob": "bob-password", "root": "root-password"}[user]
	secret, _, err := e.auth.SignIn(t.Context(), user, pw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.auth.SessionPrincipal(secret)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var tokenRE = regexp.MustCompile(`flint_[a-z2-7]{16}_[a-z2-7]{52}`)

func TestTokens(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.signIn("alice", "alice-password")
	b.expect("/ui/account", http.StatusOK).has(t, "You have no API tokens", "alice")

	create := func(form url.Values) response {
		t.Helper()
		return b.post("/ui/account", "/ui/account/tokens", form)
	}
	r := create(url.Values{"name": {"ci"}, "expiry": {"30d"}, "scope": {"selected"}, "repositories": {"oci-local, files"},
		"role": {"read"}})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("creating a token: %d\n%s", r.StatusCode, r.body)
	}
	secret := tokenRE.FindString(r.body)
	if secret == "" {
		t.Fatal("the new token is not shown")
	}
	r.has(t, "shown only once", "read on oci-local, files", e.clock.Now().Add(30*24*time.Hour).Format("2006-01-02 15:04"))
	// It is shown once only.
	if tokenRE.MatchString(b.expect("/ui/account", http.StatusOK).body) {
		t.Error("the token is shown again")
	}
	tokens, _ := e.auth.Tokens(principal(t, e, "alice"))
	if len(tokens) != 1 || tokens[0].Name != "ci" || len(tokens[0].Scopes) != 1 || tokens[0].Scopes[0].Role != auth.RoleRead {
		t.Fatalf("tokens %+v", tokens)
	}
	id := tokens[0].ID
	if !strings.Contains(secret, id) {
		t.Errorf("token %s has id %s", secret, id)
	}

	r = create(url.Values{"name": {"everything"}, "expiry": {"never"}, "scope": {"all"}})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("unscoped token: %d", r.StatusCode)
	}
	r.has(t, "admin on *", "never")

	for _, c := range []struct {
		form url.Values
		msg  string
	}{
		{url.Values{"name": {""}, "expiry": {"7d"}, "scope": {"all"}}, "token name"},
		{url.Values{"name": {"x"}, "expiry": {"0d"}, "scope": {"all"}}, "Choose an expiry"},
		{url.Values{"name": {"x"}, "expiry": {"forever"}, "scope": {"all"}}, "Choose an expiry"},
		{url.Values{"name": {"x"}, "expiry": {"7d"}, "scope": {"selected"}, "role": {"read"}}, "at least one repository"},
		{url.Values{"name": {"x"}, "expiry": {"7d"}, "scope": {"selected"}, "repositories": {"a"}, "role": {"owner"}}, "Choose a role"},
		{url.Values{"name": {"x"}, "expiry": {"7d"}, "scope": {"selected"}, "repositories": {"Bad Name!"}, "role": {"read"}}, "is not a repository"},
		{url.Values{"name": {"x"}, "expiry": {"7d"}, "scope": {"all"}, "admin": {"on"}}, "only an administrator"},
	} {
		r := create(c.form)
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("%v: %d, want 400", c.form, r.StatusCode)
			continue
		}
		r.has(t, c.msg)
		// The form keeps what was entered.
		if n := c.form.Get("name"); n != "" {
			r.has(t, `value="`+n+`"`)
		}
	}
	if tokens, _ := e.auth.Tokens(principal(t, e, "alice")); len(tokens) != 2 {
		t.Errorf("%d tokens after refused forms, want 2", len(tokens))
	}

	// Administrators may give a token the global admin role.
	root := e.browser()
	root.signIn("root", "root-password")
	r = root.post("/ui/account", "/ui/account/tokens", url.Values{"name": {"adm"}, "expiry": {"7d"}, "scope": {"all"}, "admin": {"on"}})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("admin token: %d", r.StatusCode)
	}
	r.has(t, "global admin")
	rootTokens, _ := e.auth.Tokens(principal(t, e, "root"))

	// Revoking: one's own only.
	if r := b.post("/ui/account", "/ui/account/tokens/"+rootTokens[0].ID+"/revoke", nil); r.StatusCode != http.StatusSeeOther {
		t.Errorf("revoking another user's token: %d", r.StatusCode)
	}
	if rt, _ := e.auth.Tokens(principal(t, e, "root")); len(rt) != 1 {
		t.Error("alice revoked root's token")
	}
	if r := root.post("/ui/account", "/ui/account/tokens/"+id+"/revoke", nil); r.StatusCode != http.StatusSeeOther {
		t.Errorf("root revoking alice's token: %d", r.StatusCode)
	}
	if at, _ := e.auth.Tokens(principal(t, e, "alice")); len(at) != 2 {
		t.Error("root revoked alice's token through the UI")
	}
	r = b.post("/ui/account", "/ui/account/tokens/"+id+"/revoke", nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/ui/account#tokens" {
		t.Fatalf("revoking: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	if at, _ := e.auth.Tokens(principal(t, e, "alice")); len(at) != 1 || at[0].ID == id {
		t.Errorf("tokens after revoking %+v", at)
	}
	b.expect("/ui/account", http.StatusOK).lacks(t, id)

	// Anonymous clients cannot reach the forms.
	anon := e.browser()
	f := url.Values{"csrf": {anon.csrf("/ui/login")}, "name": {"x"}, "expiry": {"7d"}, "scope": {"all"}}
	if r := anon.do("POST", "/ui/account/tokens", f); r.StatusCode != http.StatusSeeOther {
		t.Errorf("anonymous token creation: %d", r.StatusCode)
	}
}

func TestChangePassword(t *testing.T) {
	e := newEnv(t)
	b, other := e.browser(), e.browser()
	b.signIn("alice", "alice-password")
	other.signIn("alice", "alice-password")
	change := func(current, next, confirm string) response {
		t.Helper()
		return b.post("/ui/account", "/ui/account/password", url.Values{"current": {current}, "new": {next}, "confirm": {confirm}})
	}
	for _, c := range []struct{ current, next, confirm, msg string }{
		{"alice-password", "new-password-1", "new-password-2", "do not match"},
		{"wrong-password", "new-password-1", "new-password-1", "current password is incorrect"},
		{"alice-password", "short", "short", "at least 8"},
	} {
		r := change(c.current, c.next, c.confirm)
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("%+v: %d", c, r.StatusCode)
		}
		r.has(t, c.msg)
	}
	r := change("alice-password", "new-password-1", "new-password-1")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("changing the password: %d\n%s", r.StatusCode, r.body)
	}
	r.has(t, "Your password was changed")
	// This session stays; the other one ended.
	b.expect("/ui/account", http.StatusOK)
	if r := other.get("/ui/account"); r.StatusCode != http.StatusSeeOther {
		t.Errorf("the other session after the change: %d", r.StatusCode)
	}
	if _, _, err := e.auth.SignIn(t.Context(), "alice", "new-password-1"); err != nil {
		t.Errorf("new password: %v", err)
	}
}

func TestPasswordlessUser(t *testing.T) {
	e := newEnv(t)
	// A user who signs in through a provider has no password to change.
	w := httptest.NewRecorder()
	if err := e.h.SignInAs(w, httptest.NewRequest("GET", "/auth/callback", nil), "nobody", "oidc"); err == nil {
		t.Error("SignInAs an unknown user succeeded")
	}
	b := e.browser()
	b.signIn("alice", "alice-password")
	b.expect("/ui/account", http.StatusOK).has(t, `action="/ui/account/password"`)
}

func TestSignInAs(t *testing.T) {
	e := newEnv(t)
	w := httptest.NewRecorder()
	if err := e.h.SignInAs(w, httptest.NewRequest("GET", "/auth/callback", nil), "alice", "oidc"); err != nil {
		t.Fatal(err)
	}
	c := cookie(w.Result(), sessionCookie)
	if c == nil {
		t.Fatal("no session cookie")
	}
	b := e.browser()
	u, _ := url.Parse(e.srv.URL + "/ui/")
	b.client.Jar.SetCookies(u, []*http.Cookie{{Name: c.Name, Value: c.Value, Path: c.Path}})
	b.expect("/ui/account", http.StatusOK).has(t, ">alice<")
}

func TestAdmin(t *testing.T) {
	e := newEnv(t)
	root := e.browser()
	root.signIn("root", "root-password")
	r := root.expect("/ui/admin", http.StatusOK)
	r.has(t, "Garbage collection", "succeeded", "24h0m0s", "/backups", "5.0 GiB", "paused",
		">secret<", "Helm repository view", "Proxy of https://pypi.org/simple/", "Members: oci-local, secret",
		"publishes to oci-local", "oci-all, pypi-*", "Web sessions last 1h0m0s")
	// Read-only: no forms but signing out.
	if n := strings.Count(r.body, "<form"); n != 1 {
		t.Errorf("the status page has %d forms", n)
	}
}

func TestNotFound(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	r := b.expect("/ui/no/such/page", http.StatusNotFound)
	r.has(t, "Not found")
	if r := b.do("DELETE", "/ui/account", nil); r.StatusCode != http.StatusMethodNotAllowed && r.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE /ui/account: %d", r.StatusCode)
	}
}

func TestFormatSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 3 << 20: "3.0 MiB", 5 << 40: "5.0 TiB"} {
		if got := formatSize(n); got != want {
			t.Errorf("formatSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestParseExpiry(t *testing.T) {
	for s, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "never": 0, "3650d": 3650 * 24 * time.Hour} {
		if got, ok := parseExpiry(s); !ok || got != want {
			t.Errorf("parseExpiry(%q) = %v, %v", s, got, ok)
		}
	}
	for _, s := range []string{"", "0d", "-1d", "3651d", "7", "7h", "07d", "1.5d"} {
		if _, ok := parseExpiry(s); ok {
			t.Errorf("parseExpiry(%q) accepted", s)
		}
	}
}
