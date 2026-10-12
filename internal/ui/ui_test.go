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
	for _, path := range []string{"/ui/", "/ui/repositories/public", "/ui/repositories/public/images/team/app", "/ui/nope"} {
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
				want := "/auth/login?return=" + url.QueryEscape(c.path)
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
	r.has(t, "acme-lib", "The acme library", "pip install --index-url "+e.srv.URL+"/pypi/pypi-local/simple/",
		"machine 127.0.0.1\nlogin __token__")
	// .netrc names the host without the port, as clients look it up.
	r.lacks(t, "machine 127.0.0.1:")
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
	r = alice.expect("/ui/repositories/go-remote", http.StatusOK)
	// The go command looks .netrc up by host and port from Go 1.24 on, and
	// by host alone before, so the snippet lists both.
	port := strings.TrimPrefix(e.srv.URL, "http://127.0.0.1")
	r.has(t, "Cached files", "go env -w GOPROXY="+e.srv.URL+"/go/go-remote", "machine 127.0.0.1\nlogin __token__",
		"machine 127.0.0.1"+port+"\nlogin __token__")
	// A view's failure is a server error, which does not leak the error.
	r = alice.expect("/ui/repositories/broken", http.StatusInternalServerError)
	r.lacks(t, errBroken.Error())
}

// TestSignIn sends visitors to the sign-in page, which brings them back.
func TestSignIn(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.expect("/ui/", http.StatusOK).has(t, `href="/auth/login?return=%2Fui%2F"`)
	b.expect("/ui/repositories/public", http.StatusOK).has(t, `href="/auth/login?return=%2Fui%2Frepositories%2Fpublic"`)
	if r := b.get("/ui/account"); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/auth/login?return=%2Fui%2Faccount" {
		t.Errorf("GET /ui/account: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}

	r := b.post(auth.SignInPath, url.Values{"username": {"alice"}, "password": {"wrong-password"}, "return": {"/ui/account"}})
	if r.StatusCode != http.StatusSeeOther || !strings.Contains(r.Header.Get("Location"), "error=invalid") {
		t.Fatalf("wrong password: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	r = b.post(auth.SignInPath, url.Values{"username": {"alice"}, "password": {"alice-password"}, "return": {"/ui/account"}})
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/ui/account" {
		t.Fatalf("sign-in: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	if c := cookie(r.Response, auth.SessionCookie); c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie %+v", c)
	}
	r = b.expect("/ui/account", http.StatusOK)
	r.has(t, ">alice<", `action="/auth/logout"`, `name="return" value="/ui/"`)
}

// TestPathPrefix serves the UI under a public URL with a path, behind a
// reverse proxy that strips the path: every link, form, asset, and
// redirect stays under it.
func TestPathPrefix(t *testing.T) {
	e := newEnvAt(t, "https://tools.example/flint")
	b := e.browser()
	// Unprefixed URLs in attributes the pages write.
	unprefixed := []string{`="/ui/`, `="/auth/`, `="/pypi/`, `="/generic/`, "return=%2Fui"}
	if r := b.get("/"); r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/flint/ui/" {
		t.Errorf("GET /: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	r := b.expect("/ui/", http.StatusOK)
	r.has(t, `href="/flint/ui/static/style.css?v=`+e.h.assetVersion, `src="/flint/ui/static/app.js?v=`+e.h.assetVersion,
		`href="/flint/ui/"`, `action="/flint/ui/"`, `href="/flint/ui/repositories/public"`,
		`href="/flint/auth/login?return=%2Fflint%2Fui%2F"`)
	r.lacks(t, unprefixed...)
	if r := b.get("/ui/account"); r.StatusCode != http.StatusSeeOther ||
		r.Header.Get("Location") != "/flint/auth/login?return=%2Fflint%2Fui%2Faccount" {
		t.Errorf("GET /ui/account: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}

	r = b.post(auth.SignInPath, url.Values{"username": {"alice"}, "password": {"alice-password"}, "return": {"/flint/ui/"}})
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/flint/ui/" {
		t.Fatalf("sign-in: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	for path, want := range map[string][]string{
		"/ui/repositories/files": {`href="/flint/ui/repositories/files?dir=tools%2F"`, `href="/flint/generic/files/notes.txt"`},
		"/ui/repositories/pypi-local/packages/acme-lib": {`href="/flint/ui/repositories/pypi-local"`,
			`href="/flint/pypi/x/files/acme-lib/acme_lib-2.0.tar.gz"`, `href="/flint/ui/account#tokens"`,
			"pip install --index-url https://tools.example/flint/pypi/pypi-local/simple/ acme-lib==2.0"},
		"/ui/repositories/oci-local/images/team/app": {`href="/flint/ui/repositories/oci-local/manifests/`},
		"/ui/account": {`action="/flint/ui/account/tokens"`, `action="/flint/ui/account/password"`,
			`action="/flint/auth/logout"`, `name="return" value="/flint/ui/"`},
	} {
		r := b.expect(path, http.StatusOK)
		r.has(t, want...)
		r.lacks(t, unprefixed...)
	}

	r = b.post("/ui/account/tokens", url.Values{"name": {"ci"}, "expiry": {"30d"}, "scope": {"all"}})
	m := regexp.MustCompile(`action="/flint(/ui/account/tokens/[^"]+/revoke)"`).FindStringSubmatch(r.body)
	if r.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("creating a token: %d\n%s", r.StatusCode, r.body)
	}
	if r := b.post(m[1], nil); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/flint/ui/account#tokens" {
		t.Errorf("revoking a token: %d to %q", r.StatusCode, r.Header.Get("Location"))
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
	b.expect("/ui/", http.StatusOK).has(t, "Sign in")
}

func TestSignOut(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.signIn("alice", "alice-password")
	b.expect("/ui/account", http.StatusOK)
	// Signing out from another site is refused.
	if r := b.do("POST", auth.SignOutPath, url.Values{"return": {"/ui/"}}, "Sec-Fetch-Site", "cross-site"); r.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site sign-out: %d", r.StatusCode)
	}
	b.expect("/ui/account", http.StatusOK)
	r := b.post(auth.SignOutPath, url.Values{"return": {"/ui/"}})
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/ui/" {
		t.Fatalf("sign-out: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	if r := b.get("/ui/account"); r.StatusCode != http.StatusSeeOther {
		t.Errorf("account page after signing out: %d", r.StatusCode)
	}
}

// TestCrossSite refuses state-changing requests from other sites.
func TestCrossSite(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.signIn("alice", "alice-password")
	create := func(hdr ...string) int {
		return b.do("POST", "/ui/account/tokens", url.Values{"name": {"t"}, "expiry": {"7d"}, "scope": {"all"}},
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

// principal returns the principal user signs in as.
func principal(t *testing.T, e *env, user string) *auth.Principal {
	t.Helper()
	b := e.browser()
	b.signIn(user, map[string]string{"alice": "alice-password", "bob": "bob-password", "root": "root-password"}[user])
	u, _ := url.Parse(e.srv.URL + "/ui/")
	r := httptest.NewRequest("GET", "/ui/", nil)
	for _, c := range b.client.Jar.Cookies(u) {
		r.AddCookie(c)
	}
	p, err := e.auth.SessionPrincipal(r)
	if err != nil || p == nil {
		t.Fatalf("session of %s: %v", user, err)
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
		return b.post("/ui/account/tokens", form)
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
	r = root.post("/ui/account/tokens", url.Values{"name": {"adm"}, "expiry": {"7d"}, "scope": {"all"}, "admin": {"on"}})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("admin token: %d", r.StatusCode)
	}
	r.has(t, "global admin")
	rootTokens, _ := e.auth.Tokens(principal(t, e, "root"))

	// Revoking: one's own only.
	if r := b.post("/ui/account/tokens/"+rootTokens[0].ID+"/revoke", nil); r.StatusCode != http.StatusSeeOther {
		t.Errorf("revoking another user's token: %d", r.StatusCode)
	}
	if rt, _ := e.auth.Tokens(principal(t, e, "root")); len(rt) != 1 {
		t.Error("alice revoked root's token")
	}
	if r := root.post("/ui/account/tokens/"+id+"/revoke", nil); r.StatusCode != http.StatusSeeOther {
		t.Errorf("root revoking alice's token: %d", r.StatusCode)
	}
	if at, _ := e.auth.Tokens(principal(t, e, "alice")); len(at) != 2 {
		t.Error("root revoked alice's token through the UI")
	}
	r = b.post("/ui/account/tokens/"+id+"/revoke", nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/ui/account#tokens" {
		t.Fatalf("revoking: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	if at, _ := e.auth.Tokens(principal(t, e, "alice")); len(at) != 1 || at[0].ID == id {
		t.Errorf("tokens after revoking %+v", at)
	}
	b.expect("/ui/account", http.StatusOK).lacks(t, id)

	// Anonymous clients cannot reach the forms.
	anon := e.browser()
	f := url.Values{"name": {"x"}, "expiry": {"7d"}, "scope": {"all"}}
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
		return b.post("/ui/account/password", url.Values{"current": {current}, "new": {next}, "confirm": {confirm}})
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
	e.browser().signIn("alice", "new-password-1")
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
