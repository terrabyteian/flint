package auth

import (
	"context"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/gc/gctest"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/server"
)

// newOIDCEnv returns an env whose configuration has one OIDC provider,
// "corp", served by an in-test provider. mod may change the provider's
// configuration before the service is created.
func newOIDCEnv(t *testing.T, mod func(p map[string]any)) (*env, *idp) {
	t.Helper()
	c := &clock{t: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	p := newIdP(t, c.Now)
	secretFile := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secretFile, []byte(p.secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prov := map[string]any{
		"name": "corp", "displayName": "Corp SSO", "issuer": p.issuer(),
		"clientId": p.clientID, "clientSecretFile": secretFile,
		"groupMappings": map[string][]string{"eng": {"ci"}},
	}
	if mod != nil {
		mod(prov)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(testConfig), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["auth"].(map[string]any)["oidc"] = []any{prov}
	b, _ := json.Marshal(cfg)
	e := newEnv(t, string(b))
	e.clock = c
	e.svc = e.newService()
	return e, p
}

// signIn signs a browser in through the provider and returns the final
// response.
func (e *env) signIn(b *browser, ret string) response {
	e.t.Helper()
	u := e.serve().URL + "/auth/oidc/corp/login"
	if ret != "" {
		u += "?return=" + url.QueryEscape(ret)
	}
	return b.get(u)
}

// apiAs makes an admin API request with the browser's session cookie.
func (b *browser) api(method, u, body string, header map[string]string) response {
	b.t.Helper()
	var r *http.Request
	var err error
	if body != "" {
		r, err = http.NewRequest(method, u, strings.NewReader(body))
	} else {
		r, err = http.NewRequest(method, u, nil)
	}
	if err != nil {
		b.t.Fatal(err)
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
	return b.do(r)
}

func TestOIDCSignIn(t *testing.T) {
	e, p := newOIDCEnv(t, nil)
	srv := e.serve()
	b := newBrowser(t)
	resp := e.signIn(b, "")
	if resp.status != http.StatusOK || !strings.Contains(resp.body, "Signed in as <strong>alice@example.com</strong>") {
		t.Fatalf("sign-in: %d %s", resp.status, resp.body)
	}

	// The authorization request carried PKCE, state, nonce, and the
	// scopes, and the token request the code verifier and the client's
	// credentials, as basic authentication.
	q := p.lastAuthReq
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" ||
		q.Get("nonce") == "" || q.Get("scope") != "openid email profile" || q.Get("response_type") != "code" ||
		q.Get("redirect_uri") != srv.URL+"/auth/oidc/corp/callback" {
		t.Errorf("authorization request %v", q)
	}
	if p.lastBasic != [2]string{"flint", "client-secret"} || p.lastTokenReq.Get("code_verifier") == "" || p.lastTokenReq.Has("client_secret") {
		t.Errorf("token request %v, basic %v", p.lastTokenReq, p.lastBasic)
	}

	// The user was created with the mapped group, and its session
	// authenticates the admin API.
	resp = b.get(srv.URL + "/api/v1/user")
	var who whoamiJSON
	json.Unmarshal([]byte(resp.body), &who)
	if resp.status != http.StatusOK || who.Name != "alice@example.com" || !slices.Equal(who.Groups, []string{"ci"}) || who.Admin {
		t.Fatalf("whoami: %d %s", resp.status, resp.body)
	}
	u, err := e.svc.getUser("alice@example.com")
	if err != nil || u.OIDC == nil || u.OIDC.Issuer != p.issuer() || u.OIDC.Subject != "user-1" || u.OIDC.Provider != "corp" || len(u.Password) != 0 {
		t.Fatalf("user %+v %+v, %v", u, u.OIDC, err)
	}
	e.addUser("root", "root-password", true)
	resp = e.do(request{path: "/api/v1/users/alice@example.com", user: "root", pass: "root-password"})
	if !strings.Contains(resp.body, `"subject": "user-1"`) || !strings.Contains(resp.body, `"provider": "corp"`) {
		t.Errorf("user JSON: %s", resp.body)
	}

	// The session creates API tokens, which then work for package
	// clients with the user's permissions.
	resp = b.api("POST", srv.URL+"/api/v1/tokens", `{"name": "laptop"}`, nil)
	var tok tokenJSON
	json.Unmarshal([]byte(resp.body), &tok)
	if resp.status != http.StatusCreated || tok.Token == "" || tok.Owner != "alice@example.com" {
		t.Fatalf("create token: %d %s", resp.status, resp.body)
	}
	if r := e.do(request{path: "/test/push/docker-local/app", bearer: tok.Token}); r.status != http.StatusOK {
		t.Errorf("push with the token: %d %s", r.status, r.body)
	}
	if r := e.do(request{path: "/test/push/public/app", bearer: tok.Token}); r.status != http.StatusForbidden {
		t.Errorf("push beyond the user's role: %d %s", r.status, r.body)
	}
	jwt := e.token(TokenUser, tok.Token, "repository:docker-local/app:pull,push")
	if c := claimsOf(t, jwt); c.Subject != "alice@example.com" || len(c.Access) != 1 || len(c.Access[0].Actions) != 2 {
		t.Errorf("docker token claims %+v", c)
	}
	// A token still cannot mint another.
	if r := e.do(request{method: "POST", path: "/api/v1/tokens", bearer: tok.Token, body: `{"name": "x"}`}); r.status != http.StatusForbidden {
		t.Errorf("token minting a token: %d %s", r.status, r.body)
	}
	// Registry and package routes do not take the session.
	if r := b.get(srv.URL + "/test/pull/docker-local/app"); r.status != http.StatusUnauthorized {
		t.Errorf("registry with a session: %d %s", r.status, r.body)
	}
	if r := b.get(srv.URL + "/style/basic/pull/docker-local/app"); r.status != http.StatusUnauthorized {
		t.Errorf("package route with a session: %d %s", r.status, r.body)
	}
	// An OIDC user has no password, and cannot be given one.
	if r := b.api("PUT", srv.URL+"/api/v1/users/alice@example.com/password", `{"password": "a-long-password"}`, nil); r.status != http.StatusBadRequest {
		t.Errorf("set an OIDC user's password: %d %s", r.status, r.body)
	}
	if r := e.do(request{path: "/api/v1/user", user: "alice@example.com", pass: ""}); r.status != http.StatusUnauthorized {
		t.Errorf("password login as an OIDC user: %d", r.status)
	}

	// Sign-ins are recorded with their actions.
	if got := metricsText(e); !strings.Contains(got, `flint_auth_attempts_total{method="oidc",result="success"} 1`) ||
		!strings.Contains(got, `flint_auth_attempts_total{method="session",result="success"}`) {
		t.Errorf("metrics:\n%s", got)
	}
	if refs := gctest.CheckMarked(t, e.store, GCMarker()); len(refs) != 0 {
		t.Errorf("auth records reference blobs: %v", refs)
	}
}

// TestOIDCGroupSync checks that groups and the admin flag follow the
// provider at every sign-in, and that the user keeps its name.
func TestOIDCGroupSync(t *testing.T) {
	e, p := newOIDCEnv(t, func(prov map[string]any) {
		prov["importGroups"] = true
		prov["adminGroups"] = []string{"Flint Admins"}
		prov["groupMappings"] = map[string][]string{"eng": {"ci", "team-a"}, "Flint Admins": {"admins"}}
	})
	srv := e.serve()
	e.addUser("root", "root-password", true)
	who := func(b *browser) whoamiJSON {
		t.Helper()
		var w whoamiJSON
		resp := b.get(srv.URL + "/api/v1/user")
		if err := json.Unmarshal([]byte(resp.body), &w); err != nil || resp.status != http.StatusOK {
			t.Fatalf("whoami: %d %s", resp.status, resp.body)
		}
		return w
	}

	p.set(func(p *idp) { p.claims["groups"] = []string{"eng", "Flint Admins", "Ops", "not a name!"} })
	b := newBrowser(t)
	e.signIn(b, "")
	if w := who(b); !w.Admin || !slices.Equal(w.Groups, []string{"admins", "ci", "eng", "ops", "team-a"}) {
		t.Fatalf("first sign-in: %+v", w)
	}

	// Removed from groups at the provider: the next sign-in removes the
	// groups and the admin role, also from a session started before.
	old := b
	p.set(func(p *idp) {
		p.claims["groups"] = "eng"
		p.claims["email"] = "renamed@example.com"
	})
	b = newBrowser(t)
	e.signIn(b, "")
	if w := who(b); w.Admin || w.Name != "alice@example.com" || !slices.Equal(w.Groups, []string{"ci", "eng", "team-a"}) {
		t.Fatalf("second sign-in: %+v", w)
	}
	if w := who(old); w.Admin || !slices.Equal(w.Groups, []string{"ci", "eng", "team-a"}) {
		t.Fatalf("old session after the sync: %+v", w)
	}

	// The last administrator is not demoted by a sync.
	e2, p2 := newOIDCEnv(t, func(prov map[string]any) { prov["adminGroups"] = []string{"admins"} })
	p2.set(func(p *idp) { p.claims["groups"] = []string{"admins"} })
	b2 := newBrowser(t)
	e2.signIn(b2, "")
	p2.set(func(p *idp) { p.claims["groups"] = []string{} })
	e2.signIn(b2, "")
	if u, _ := e2.svc.getUser("alice@example.com"); !u.Admin {
		t.Error("the last administrator was demoted")
	}
}

func TestMapGroups(t *testing.T) {
	cfg := &config.OIDCProvider{
		GroupMappings: map[string][]string{"Eng": {"ci", "team-a"}, "ops": {"ci"}},
		AdminGroups:   []string{"root"},
	}
	for _, tt := range []struct {
		idp      []string
		import_  bool
		groups   []string
		admin    bool
		setAdmin bool
	}{
		{nil, false, []string{}, false, true},
		{[]string{"Eng", "ops", "other"}, false, []string{"ci", "team-a"}, false, true},
		{[]string{"Eng", "Other", "x y", "root"}, true, []string{"ci", "eng", "other", "root", "team-a"}, true, true},
	} {
		cfg.ImportGroups = tt.import_
		groups, admin, setAdmin := mapGroups(cfg, tt.idp)
		if !slices.Equal(groups, tt.groups) || admin != tt.admin || setAdmin != tt.setAdmin {
			t.Errorf("mapGroups(%q, import %v) = %q, %v, %v", tt.idp, tt.import_, groups, admin, setAdmin)
		}
	}
	if _, _, setAdmin := mapGroups(&config.OIDCProvider{}, []string{"root"}); setAdmin {
		t.Error("admin managed without adminGroups")
	}
}

// TestOIDCSignInRefused checks the provider's restrictions and flint's
// rules for user names.
func TestOIDCSignInRefused(t *testing.T) {
	for _, tt := range []struct {
		name   string
		cfg    func(map[string]any)
		claims map[string]any
		local  string // a local user created first
		want   string
	}{
		{name: "unverified email", claims: map[string]any{"email_verified": false}, want: "no user name"},
		{name: "string email_verified", claims: map[string]any{"email_verified": "true"}},
		{name: "no username claim", claims: map[string]any{"email": nil}, want: "no user name"},
		{name: "invalid username", cfg: func(p map[string]any) { p["usernameClaim"] = "name" }, claims: map[string]any{"name": "Alice Smith"}, want: "no user name"},
		{name: "preferred_username", cfg: func(p map[string]any) { p["usernameClaim"] = "preferred_username" },
			claims: map[string]any{"preferred_username": "Alice", "email_verified": false}},
		{name: "taken by a local user", local: "alice@example.com", want: "is taken by another user"},
		{name: "allowed domain", cfg: func(p map[string]any) { p["allowedDomains"] = []string{"example.com"} }},
		{name: "other domain", cfg: func(p map[string]any) { p["allowedDomains"] = []string{"example.org"} }, want: "not allowed to sign in"},
		{name: "domain unverified", cfg: func(p map[string]any) {
			p["allowedDomains"] = []string{"example.com"}
			p["usernameClaim"] = "sub"
		}, claims: map[string]any{"email_verified": false}, want: "not allowed to sign in"},
		{name: "allowed group", cfg: func(p map[string]any) { p["allowedGroups"] = []string{"ops", "eng"} }},
		{name: "not in an allowed group", cfg: func(p map[string]any) { p["allowedGroups"] = []string{"ops"} }, want: "not allowed to sign in"},
		{name: "invalid groups claim", claims: map[string]any{"groups": 7}, want: "invalid group information"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, p := newOIDCEnv(t, tt.cfg)
			if tt.local != "" {
				e.addUser(tt.local, "local-password", false)
			}
			p.set(func(p *idp) {
				for k, v := range tt.claims {
					p.claims[k] = v
				}
			})
			resp := e.signIn(newBrowser(t), "")
			switch {
			case tt.want == "" && (resp.status != http.StatusOK || !strings.Contains(resp.body, "Signed in as")):
				t.Errorf("got %d %s, want a sign-in", resp.status, resp.body)
			case tt.want != "" && (resp.status != http.StatusForbidden || !strings.Contains(resp.body, tt.want)):
				t.Errorf("got %d %s, want 403 with %q", resp.status, resp.body, tt.want)
			}
			if tt.local != "" {
				if u, _ := e.svc.getUser(tt.local); u.OIDC != nil {
					t.Error("the local user was taken over")
				}
			}
		})
	}
}

// TestOIDCIdentity checks that users are matched by issuer and subject,
// never by email or name.
func TestOIDCIdentity(t *testing.T) {
	e, p := newOIDCEnv(t, nil)
	e.signIn(newBrowser(t), "")
	// Another subject claiming the same email is a different identity,
	// whose user name is taken.
	p.set(func(p *idp) { p.subject = "user-2" })
	if resp := e.signIn(newBrowser(t), ""); resp.status != http.StatusForbidden || !strings.Contains(resp.body, "is taken") {
		t.Errorf("second subject with the same email: %d %s", resp.status, resp.body)
	}
	// After the user is deleted, its identity signs in as a new user.
	e.addUser("root", "root-password", true)
	if r := e.do(request{method: "DELETE", path: "/api/v1/users/alice@example.com", user: "root", pass: "root-password"}); r.status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.status, r.body)
	}
	if resp := e.signIn(newBrowser(t), ""); resp.status != http.StatusOK {
		t.Errorf("sign-in after deletion: %d %s", resp.status, resp.body)
	}
	if u, err := e.svc.getUser("alice@example.com"); err != nil || u.OIDC.Subject != "user-2" {
		t.Errorf("user after deletion: %+v, %v", u, err)
	}
}

// TestOIDCCallbackChecks covers the callback's state, browser binding,
// and replay rules.
func TestOIDCCallbackChecks(t *testing.T) {
	e, p := newOIDCEnv(t, nil)
	srv := e.serve()

	// Stop at the redirect back to flint, to replay it.
	b := newBrowser(t)
	b.stop = srv.URL + "/auth/oidc/corp/callback"
	resp := b.get(srv.URL + "/auth/oidc/corp/login?return=/ui/repos?x=1")
	callback := resp.header.Get("Location")
	if resp.status != http.StatusFound || !strings.HasPrefix(callback, b.stop) {
		t.Fatalf("authorize: %d %v", resp.status, resp.header)
	}
	b.stop = ""

	// Another browser cannot complete it: the binding cookie is missing.
	other := newBrowser(t)
	if r := other.get(callback); r.status != http.StatusForbidden || !strings.Contains(r.body, "another browser") {
		t.Errorf("callback in another browser: %d %s", r.status, r.body)
	}
	// That consumed the state, so the original browser must start over.
	if r := b.get(callback); r.status != http.StatusForbidden || !strings.Contains(r.body, "expired or was already used") {
		t.Errorf("callback after the state was used: %d %s", r.status, r.body)
	}

	// A completed sign-in cannot be replayed, even by the same browser.
	b = newBrowser(t)
	b.stop = srv.URL + "/auth/oidc/corp/callback"
	callback = b.get(srv.URL + "/auth/oidc/corp/login?return=/ui/repos?x=1").header.Get("Location")
	b.stop = srv.URL + "/ui/"
	r := b.get(callback)
	if r.status != http.StatusSeeOther || r.header.Get("Location") != "/ui/repos?x=1" {
		t.Fatalf("callback: %d %v %s", r.status, r.header, r.body)
	}
	tokenReqs := p.tokenReqs
	if r := b.get(callback); r.status != http.StatusForbidden || p.tokenReqs != tokenReqs {
		t.Errorf("replayed callback: %d %s, %d token requests", r.status, r.body, p.tokenReqs-tokenReqs)
	}

	// An expired pending sign-in is refused.
	b = newBrowser(t)
	b.stop = srv.URL + "/auth/oidc/corp/callback"
	callback = b.get(srv.URL + "/auth/oidc/corp/login").header.Get("Location")
	b.stop = ""
	e.clock.Add(pendingTTL)
	if r := b.get(callback); r.status != http.StatusForbidden || !strings.Contains(r.body, "expired") {
		t.Errorf("expired sign-in: %d %s", r.status, r.body)
	}

	// The provider's refusal, and an unknown provider.
	p.set(func(p *idp) { p.authError = "access_denied" })
	if r := e.signIn(newBrowser(t), ""); r.status != http.StatusForbidden || !strings.Contains(r.body, "did not sign you in") {
		t.Errorf("provider refusal: %d %s", r.status, r.body)
	}
	if r := newBrowser(t).get(srv.URL + "/auth/oidc/nope/login"); r.status != http.StatusNotFound {
		t.Errorf("unknown provider: %d", r.status)
	}

	// Return paths must be on this server.
	p.set(func(p *idp) { p.authError = "" })
	for ret, want := range map[string]string{
		"/ui/":                 "/ui/",
		"//evil.example/":      srv.URL + SignInPath,
		"https://evil.example": srv.URL + SignInPath,
		"/\\evil.example":      srv.URL + SignInPath,
		"ui":                   srv.URL + SignInPath,
	} {
		b := newBrowser(t)
		b.stop = srv.URL + "/ui/"
		b.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.Path, "/auth/oidc/") || strings.HasPrefix(req.URL.Path, "/authorize") {
				return nil
			}
			return http.ErrUseLastResponse
		}
		if r := e.signIn(b, ret); r.header.Get("Location") != want {
			t.Errorf("return %q: redirected to %q, want %q", ret, r.header.Get("Location"), want)
		}
	}
	if fails := metricsText(e); !strings.Contains(fails, `flint_auth_attempts_total{method="oidc",result="failure"} 5`) {
		t.Errorf("failure metrics:\n%s", fails)
	}
}

// TestOIDCClientAuth checks client_secret_post and public clients.
func TestOIDCClientAuth(t *testing.T) {
	e, p := newOIDCEnv(t, nil)
	p.set(func(p *idp) { p.authMethods = []string{"client_secret_post"} })
	if r := e.signIn(newBrowser(t), ""); r.status != http.StatusOK {
		t.Fatalf("client_secret_post: %d %s", r.status, r.body)
	}
	if p.lastTokenReq.Get("client_secret") != "client-secret" || p.lastTokenReq.Get("client_id") != "flint" {
		t.Errorf("token request %v", p.lastTokenReq)
	}

	e, p = newOIDCEnv(t, func(prov map[string]any) { delete(prov, "clientSecretFile") })
	p.set(func(p *idp) { p.secret = "" })
	if r := e.signIn(newBrowser(t), ""); r.status != http.StatusOK {
		t.Fatalf("public client: %d %s", r.status, r.body)
	}
	if p.lastTokenReq.Get("client_id") != "flint" || p.lastTokenReq.Has("client_secret") || p.lastBasic != [2]string{} {
		t.Errorf("token request %v, basic %v", p.lastTokenReq, p.lastBasic)
	}

	// A wrong secret is refused by the provider.
	e, p = newOIDCEnv(t, nil)
	p.set(func(p *idp) { p.secret = "rotated" })
	if r := e.signIn(newBrowser(t), ""); r.status != http.StatusForbidden || !strings.Contains(r.body, "could not be completed") {
		t.Errorf("wrong secret: %d %s", r.status, r.body)
	}
}

// TestOIDCDiscovery checks discovery's checks and caching.
func TestOIDCDiscovery(t *testing.T) {
	e, p := newOIDCEnv(t, nil)
	b := newBrowser(t)
	e.signIn(b, "")
	e.signIn(b, "")
	if p.discoveries != 1 || p.keyFetches != 1 {
		t.Errorf("%d discoveries and %d key fetches, want 1 each", p.discoveries, p.keyFetches)
	}
	e.clock.Add(discoveryTTL)
	e.signIn(b, "")
	if p.discoveries != 2 || p.keyFetches != 2 {
		t.Errorf("after the TTL: %d discoveries and %d key fetches, want 2 each", p.discoveries, p.keyFetches)
	}

	// A discovery document for another issuer is refused.
	e, p = newOIDCEnv(t, nil)
	p.set(func(p *idp) { p.discoveryIssuer = p.issuer() + "/" })
	if r := e.signIn(newBrowser(t), ""); r.status != http.StatusBadGateway || !strings.Contains(r.body, "unavailable") {
		t.Errorf("issuer mismatch: %d %s", r.status, r.body)
	}

	// A provider that is down fails the sign-in, and its stale document
	// keeps working once fetched.
	e, p = newOIDCEnv(t, nil)
	e.signIn(newBrowser(t), "")
	prov := e.svc.oidc.providers["corp"]
	e.clock.Add(2 * time.Hour)
	p.srv.Config.Handler = http.NotFoundHandler()
	if _, err := prov.discovery(context.Background()); err != nil {
		t.Errorf("stale discovery: %v", err)
	}

	for _, tt := range []struct {
		doc  string
		want string
	}{
		{`{"issuer": "ISS", "authorization_endpoint": "http://idp.example/a", "token_endpoint": "ISS/t", "jwks_uri": "ISS/k"}`, "authorization_endpoint"},
		{`{"issuer": "ISS", "authorization_endpoint": "ISS/a", "jwks_uri": "ISS/k"}`, "token_endpoint"},
		{`{"issuer": "ISS", "authorization_endpoint": "ISS/a", "token_endpoint": "ISS/t", "jwks_uri": "ftp://x/k"}`, "jwks_uri"},
		{`not json`, "not valid JSON"},
	} {
		srv := newIdP(t, time.Now)
		srv.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(strings.ReplaceAll(tt.doc, "ISS", srv.issuer())))
		})
		pr, _ := newOIDCProvider(config.OIDCProvider{Name: "x", Issuer: srv.issuer()}, nil, time.Now, quiet)
		if _, err := pr.discovery(context.Background()); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v, want %q", tt.doc, err, tt.want)
		}
	}
}

// TestOIDCKeyRotation checks that a token signed with a key published
// after the key set was fetched is verified after a refetch, which is
// rate-limited.
func TestOIDCKeyRotation(t *testing.T) {
	e, p := newOIDCEnv(t, nil)
	p.set(func(p *idp) { p.algs = []string{"RS256", "ES256"} })
	e.signIn(newBrowser(t), "")
	next := newECTestKey(t, "ec-2", elliptic.P256(), "ES256")
	p.set(func(p *idp) {
		p.keys = append(p.keys, next)
		p.signer = next
	})
	// Within jwksMinRefresh of the last fetch, the new key is not fetched.
	if r := e.signIn(newBrowser(t), ""); r.status != http.StatusForbidden || p.keyFetches != 1 {
		t.Errorf("unknown key soon after a fetch: %d, %d fetches", r.status, p.keyFetches)
	}
	e.clock.Add(jwksMinRefresh)
	if r := e.signIn(newBrowser(t), ""); r.status != http.StatusOK || p.keyFetches != 2 {
		t.Errorf("rotated key: %d %s, %d fetches", r.status, r.body, p.keyFetches)
	}
	// The old key is retired: a token signed with it no longer verifies.
	old := newRSATestKey("rsa-1", "RS256", 0)
	p.set(func(p *idp) {
		p.keys = []testKey{next}
		p.signer = old
	})
	e.clock.Add(jwksTTL)
	if r := e.signIn(newBrowser(t), ""); r.status != http.StatusForbidden {
		t.Errorf("retired key: %d", r.status)
	}
}

// testProvider returns a provider for verifying tokens directly.
func testProvider(t *testing.T, keys []testKey, now time.Time) (*oidcProvider, *discovery) {
	t.Helper()
	p, err := newOIDCProvider(config.OIDCProvider{Name: "x", Issuer: "https://idp.example", ClientID: "flint"}, nil,
		func() time.Time { return now }, quiet)
	if err != nil {
		t.Fatal(err)
	}
	var set []map[string]any
	for _, k := range keys {
		set = append(set, jwkOf(k))
	}
	b, _ := json.Marshal(map[string]any{"keys": set})
	vk, err := parseJWKS(b)
	if err != nil {
		t.Fatal(err)
	}
	p.keys, p.keysAt, p.keysURI = vk, now, "https://idp.example/keys"
	return p, &discovery{Issuer: "https://idp.example", JWKSURI: "https://idp.example/keys", SigningAlgs: []string{"RS256", "ES256", "PS256", "EdDSA", "ES384", "HS256", "none"}}
}

func TestVerifyIDToken(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	rsaKey := newRSATestKey("rsa", "RS256", 0)
	otherRSA := newRSATestKey("rsa", "RS256", 1)
	ecKey := newECTestKey(t, "ec", elliptic.P256(), "ES256")
	ec384 := newECTestKey(t, "ec384", elliptic.P384(), "ES384")
	edKey := newEdTestKey(t, "ed")
	psKey := testKey{kid: "ps", alg: "PS256", priv: testRSAKey(1)}
	p, d := testProvider(t, []testKey{rsaKey, ecKey, ec384, edKey, psKey}, now)
	base := func() map[string]any {
		return map[string]any{
			"iss": "https://idp.example", "sub": "user-1", "aud": "flint", "nonce": "n0nce",
			"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		}
	}
	with := func(changes map[string]any) map[string]any {
		c := base()
		for k, v := range changes {
			if v == nil {
				delete(c, k)
			} else {
				c[k] = v
			}
		}
		return c
	}
	hmacToken := func(alg string, secret []byte) string {
		h, _ := json.Marshal(map[string]any{"alg": alg, "kid": "rsa"})
		c, _ := json.Marshal(base())
		msg := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(msg))
		return msg + "." + b64.EncodeToString(m.Sum(nil))
	}
	rsaPub, _ := json.Marshal(jwkOf(rsaKey))
	good := signJWT(t, rsaKey, base(), nil)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + b64.EncodeToString([]byte(`{"iss":"https://idp.example","sub":"admin","aud":"flint","nonce":"n0nce","exp":9999999999,"iat":`+
		jsonInt(now.Unix())+`}`)) + "." + parts[2]
	noneTok := b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + "."

	for _, tt := range []struct {
		name  string
		tok   string
		nonce string
		want  string // "" for valid
	}{
		{"RS256", good, "", ""},
		{"ES256", signJWT(t, ecKey, base(), nil), "", ""},
		{"ES384", signJWT(t, ec384, base(), nil), "", ""},
		{"EdDSA", signJWT(t, edKey, base(), nil), "", ""},
		{"PS256", signJWT(t, psKey, base(), nil), "", ""},
		{"no kid", signJWT(t, rsaKey, base(), map[string]any{"kid": nil}), "", ""},
		{"audience array with azp", signJWT(t, rsaKey, with(map[string]any{"aud": []string{"flint", "other"}, "azp": "flint"}), nil), "", ""},
		{"fractional times", signJWT(t, rsaKey, with(map[string]any{"exp": float64(now.Add(time.Hour).Unix()) + .5}), nil), "", ""},
		{"bad signature", tampered, "", "invalid signature"},
		{"other key with the same kid", signJWT(t, otherRSA, base(), nil), "", "invalid signature"},
		{"unknown kid", signJWT(t, rsaKey, base(), map[string]any{"kid": "gone"}), "", "unknown key"},
		{"alg none", noneTok, "", `algorithm "none" is not allowed`},
		{"HS256 with the public key as secret", hmacToken("HS256", rsaPub), "", `algorithm "HS256" is not allowed`},
		{"HS256 with the modulus as secret", hmacToken("HS256", []byte(jwkOf(rsaKey)["n"].(string))), "", "is not allowed"},
		{"RS256 header on an EC key", signJWT(t, testKey{kid: "ec", alg: "RS256", priv: rsaKey.priv}, base(), nil), "", "unknown key"},
		{"ES256 header on an ES384 key", signJWT(t, testKey{kid: "ec384", alg: "ES256", priv: ecKey.priv}, base(), nil), "", "unknown key"},
		{"PS256 header on an RS256 key", signJWT(t, testKey{kid: "rsa", alg: "PS256", priv: rsaKey.priv}, base(), nil), "", "unknown key"},
		{"critical header", signJWT(t, rsaKey, base(), map[string]any{"crit": []string{"exp"}}), "", "critical"},
		{"wrong typ", signJWT(t, rsaKey, base(), map[string]any{"typ": "at+jwt"}), "", "token type"},
		{"wrong audience", signJWT(t, rsaKey, with(map[string]any{"aud": "other"}), nil), "", "audience"},
		{"no audience", signJWT(t, rsaKey, with(map[string]any{"aud": nil}), nil), "", "audience"},
		{"several audiences without azp", signJWT(t, rsaKey, with(map[string]any{"aud": []string{"flint", "other"}}), nil), "", "authorized party"},
		{"azp of another client", signJWT(t, rsaKey, with(map[string]any{"azp": "other"}), nil), "", "authorized party"},
		{"wrong issuer", signJWT(t, rsaKey, with(map[string]any{"iss": "https://idp.example/"}), nil), "", "issuer"},
		{"expired", signJWT(t, rsaKey, with(map[string]any{"exp": now.Add(-oidcClockSkew).Unix()}), nil), "", "expired"},
		{"expired within skew", signJWT(t, rsaKey, with(map[string]any{"exp": now.Add(-oidcClockSkew + time.Second).Unix()}), nil), "", ""},
		{"no exp", signJWT(t, rsaKey, with(map[string]any{"exp": nil}), nil), "", "exp is missing"},
		{"exp not a number", signJWT(t, rsaKey, with(map[string]any{"exp": "soon"}), nil), "", "exp is not a number"},
		{"issued in the future", signJWT(t, rsaKey, with(map[string]any{"iat": now.Add(2 * oidcClockSkew).Unix()}), nil), "", "future"},
		{"issued long ago", signJWT(t, rsaKey, with(map[string]any{"iat": now.Add(-maxIDTokenAge - 2*oidcClockSkew).Unix()}), nil), "", "too long ago"},
		{"no iat", signJWT(t, rsaKey, with(map[string]any{"iat": nil}), nil), "", "iat is missing"},
		{"not yet valid", signJWT(t, rsaKey, with(map[string]any{"nbf": now.Add(2 * oidcClockSkew).Unix()}), nil), "", "not valid yet"},
		{"wrong nonce", good, "replayed", "nonce"},
		{"no nonce", signJWT(t, rsaKey, with(map[string]any{"nonce": nil}), nil), "", "nonce"},
		{"no subject", signJWT(t, rsaKey, with(map[string]any{"sub": nil}), nil), "", "sub"},
		{"long subject", signJWT(t, rsaKey, with(map[string]any{"sub": strings.Repeat("s", 256)}), nil), "", "sub"},
		{"two parts", parts[0] + "." + parts[1], "", "not a signed JWT"},
		{"four parts", good + ".x", "", "not a signed JWT"},
		{"too long", strings.Repeat("a", maxJWTLen+1), "", "too long"},
	} {
		nonce := tt.nonce
		if nonce == "" {
			nonce = "n0nce"
		}
		c, err := p.verifyIDToken(context.Background(), d, tt.tok, nonce)
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("%s: %v", tt.name, err)
		case tt.want == "" && c.Subject != "user-1":
			t.Errorf("%s: subject %q", tt.name, c.Subject)
		case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("%s: %v, want an error with %q", tt.name, err, tt.want)
		}
	}

	// Configured algorithms restrict what the provider lists.
	p.cfg.SigningAlgorithms = []string{"ES256"}
	if _, err := p.verifyIDToken(context.Background(), d, good, "n0nce"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("RS256 with only ES256 configured: %v", err)
	}
	// Without a list in the discovery document, only RS256 is accepted.
	p.cfg.SigningAlgorithms = nil
	if got := p.allowedAlgs(&discovery{}); !slices.Equal(got, []string{"RS256"}) {
		t.Errorf("default algorithms %q", got)
	}
	if got := p.allowedAlgs(d); !slices.Equal(got, []string{"RS256", "ES256", "PS256", "EdDSA", "ES384"}) {
		t.Errorf("algorithms from discovery %q", got)
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestParseJWKS(t *testing.T) {
	rsaKey := jwkOf(newRSATestKey("rsa", "RS256", 0))
	ec := jwkOf(newECTestKey(t, "ec", elliptic.P256(), "ES256"))
	set := func(keys ...any) []byte {
		b, _ := json.Marshal(map[string]any{"keys": keys})
		return b
	}
	mod := func(k map[string]any, changes map[string]any) map[string]any {
		out := map[string]any{}
		for n, v := range k {
			out[n] = v
		}
		for n, v := range changes {
			out[n] = v
		}
		return out
	}
	offCurve := mod(ec, map[string]any{"y": ec["x"]})
	for _, tt := range []struct {
		name string
		set  []byte
		keys int
		want string
	}{
		{"rsa and ec", set(rsaKey, ec), 2, ""},
		{"skips symmetric keys", set(map[string]any{"kty": "oct", "k": "c2VjcmV0"}, rsaKey), 1, ""},
		{"skips encryption keys", set(mod(rsaKey, map[string]any{"use": "enc"}), ec), 1, ""},
		{"skips unknown curves", set(mod(ec, map[string]any{"crv": "secp256k1"})), 0, ""},
		{"point off the curve", set(offCurve), 0, "invalid EC key"},
		{"short coordinate", set(mod(ec, map[string]any{"x": "AAAA"})), 0, "invalid EC key"},
		{"small RSA key", set(mod(rsaKey, map[string]any{"n": b64.EncodeToString(make([]byte, 128))})), 0, "bits"},
		{"even exponent", set(mod(rsaKey, map[string]any{"e": "Ag"})), 0, "exponent"},
		{"not json", []byte("{"), 0, "invalid key set"},
	} {
		keys, err := parseJWKS(tt.set)
		switch {
		case tt.want == "" && (err != nil || len(keys) != tt.keys):
			t.Errorf("%s: %d keys, %v", tt.name, len(keys), err)
		case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("%s: %v, want %q", tt.name, err, tt.want)
		}
	}
}

// TestSessions covers the session cookie's lifetime, the cross-origin
// rule, sign-out, and user deletion.
func TestSessions(t *testing.T) {
	e, _ := newOIDCEnv(t, nil)
	srv := e.serve()
	e.addUser("root", "root-password", true)
	b := newBrowser(t)
	e.signIn(b, "")

	// The cookie is HttpOnly and SameSite=Lax, for the whole server.
	jarCookies := b.client.Jar.Cookies(mustURL(srv.URL + "/api/v1/user"))
	var value string
	for _, c := range jarCookies {
		if c.Name == SessionCookie {
			value = c.Value
		}
	}
	if value == "" {
		t.Fatal("no session cookie")
	}

	// A cross-origin request that changes something is refused; a
	// same-origin one, or one not from a browser, is not.
	if r := b.api("POST", srv.URL+"/api/v1/tokens", `{"name": "x"}`, map[string]string{"Sec-Fetch-Site": "cross-site"}); r.status != http.StatusForbidden || !strings.Contains(r.body, "cross-origin") {
		t.Errorf("cross-site token creation: %d %s", r.status, r.body)
	}
	if r := b.api("POST", srv.URL+"/api/v1/tokens", `{"name": "x"}`, map[string]string{"Origin": "https://evil.example"}); r.status != http.StatusForbidden {
		t.Errorf("cross-origin token creation: %d %s", r.status, r.body)
	}
	if r := b.api("POST", srv.URL+"/api/v1/tokens", `{"name": "x"}`, map[string]string{"Sec-Fetch-Site": "same-origin"}); r.status != http.StatusCreated {
		t.Errorf("same-origin token creation: %d %s", r.status, r.body)
	}
	if r := b.api("GET", srv.URL+"/api/v1/tokens", "", map[string]string{"Sec-Fetch-Site": "cross-site"}); r.status != http.StatusOK {
		t.Errorf("cross-site read: %d %s", r.status, r.body)
	}

	// A forged or tampered cookie is refused.
	last := "a"
	if strings.HasSuffix(value, "a") {
		last = "b"
	}
	for _, v := range []string{"garbage", value[:len(value)-1] + last, strings.Repeat("a", 16) + "_" + strings.Repeat("b", 52)} {
		if r := e.do(request{path: "/api/v1/user", header: map[string]string{"Cookie": SessionCookie + "=" + v}}); r.status != http.StatusUnauthorized ||
			r.header.Get("WWW-Authenticate") != "" {
			t.Errorf("cookie %q: %d %v", v, r.status, r.header)
		}
	}

	// Sign-out ends the session, and a cross-origin sign-out is refused.
	if r := b.api("POST", srv.URL+"/auth/logout", "", map[string]string{"Sec-Fetch-Site": "cross-site"}); r.status != http.StatusForbidden {
		t.Errorf("cross-site sign-out: %d", r.status)
	}
	if r := b.api("POST", srv.URL+"/auth/logout", "", nil); r.status != http.StatusOK || !strings.Contains(r.body, "Sign in with Corp SSO") {
		t.Errorf("sign-out: %d %s", r.status, r.body)
	}
	if r := e.do(request{path: "/api/v1/user", header: map[string]string{"Cookie": SessionCookie + "=" + value}}); r.status != http.StatusUnauthorized {
		t.Errorf("after sign-out: %d", r.status)
	}

	// A session expires after auth.sessionTTL.
	b = newBrowser(t)
	e.signIn(b, "")
	e.clock.Add(config.DefaultSessionTTL - time.Second)
	if r := b.get(srv.URL + "/api/v1/user"); r.status != http.StatusOK {
		t.Errorf("before expiry: %d", r.status)
	}
	e.clock.Add(time.Second)
	if r := e.do(request{path: "/api/v1/user", header: map[string]string{"Cookie": cookieHeader(b, srv.URL)}}); r.status != http.StatusUnauthorized {
		t.Errorf("after expiry: %d", r.status)
	}

	// Signing in again removes the expired session; deleting the user
	// removes the live ones.
	b = newBrowser(t)
	e.signIn(b, "")
	if n := countKeys(e, sessionPrefix); n != 1 {
		t.Errorf("%d sessions after signing in again", n)
	}
	if r := e.do(request{method: "DELETE", path: "/api/v1/users/alice@example.com", user: "root", pass: "root-password"}); r.status != http.StatusNoContent {
		t.Fatalf("delete: %d", r.status)
	}
	if n := countKeys(e, sessionPrefix) + countKeys(e, userSessionPrefix) + countKeys(e, oidcPrefix); n != 0 {
		t.Errorf("%d session and identity records after deleting the user", n)
	}
	if r := b.get(srv.URL + "/api/v1/user"); r.status != http.StatusUnauthorized {
		t.Errorf("session of a deleted user: %d", r.status)
	}
}

// TestSessionLimit checks that a user keeps at most maxSessionsPerUser
// sessions.
func TestSessionLimit(t *testing.T) {
	e := newEnv(t, testConfig)
	srv := e.serve()
	e.addUser("carol", "carol-password", false)
	for range maxSessionsPerUser + 3 {
		b := newBrowser(t)
		r, err := b.client.PostForm(srv.URL+SignInPath, url.Values{"username": {"carol"}, "password": {"carol-password"}})
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
	}
	if n := countKeys(e, sessionPrefix); n != maxSessionsPerUser {
		t.Errorf("%d sessions, want %d", n, maxSessionsPerUser)
	}
}

func TestPasswordSignIn(t *testing.T) {
	e := newEnv(t, testConfig)
	srv := e.serve()
	e.addUser("carol", "carol-password", false, "ci")
	e.addUser("root", "root-password", true)

	b := newBrowser(t)
	page := b.get(srv.URL + SignInPath + "?return=/ui/")
	if page.status != http.StatusOK || !strings.Contains(page.body, `name="return" value="/ui/"`) || strings.Contains(page.body, "Sign in with") {
		t.Fatalf("sign-in page: %d %s", page.status, page.body)
	}
	if csp := page.header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP %q", csp)
	}

	post := func(b *browser, form url.Values, header map[string]string) response {
		req, _ := http.NewRequest("POST", srv.URL+SignInPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		return b.do(req)
	}
	r := post(b, url.Values{"username": {"carol"}, "password": {"wrong"}, "return": {"/ui/"}}, nil)
	if r.status != http.StatusOK || !strings.Contains(r.body, "Incorrect user name or password") || !strings.Contains(r.body, `value="/ui/"`) {
		t.Errorf("wrong password: %d %s", r.status, r.body)
	}
	if r := post(b, url.Values{"username": {"carol"}, "password": {"carol-password"}}, map[string]string{"Sec-Fetch-Site": "cross-site"}); r.status != http.StatusForbidden {
		t.Errorf("cross-site sign-in: %d", r.status)
	}
	b.stop = srv.URL + "/ui/"
	r = post(b, url.Values{"username": {"carol"}, "password": {"carol-password"}, "return": {"/ui/"}}, nil)
	if r.status != http.StatusSeeOther || r.header.Get("Location") != "/ui/" {
		t.Fatalf("sign-in: %d %v", r.status, r.header)
	}
	if r := b.get(srv.URL + SignInPath); !strings.Contains(r.body, "Signed in as <strong>carol</strong>") {
		t.Errorf("signed-in page: %s", r.body)
	}
	// The session works like a password for the admin API.
	if r := b.api("POST", srv.URL+"/api/v1/tokens", `{"name": "t", "admin": true}`, nil); r.status != http.StatusBadRequest {
		t.Errorf("admin token for a non-admin: %d %s", r.status, r.body)
	}
	if r := b.api("GET", srv.URL+"/api/v1/users", "", nil); r.status != http.StatusForbidden {
		t.Errorf("list users as a non-admin: %d", r.status)
	}

	// An administrator's session administers.
	admin := newBrowser(t)
	post(admin, url.Values{"username": {"root"}, "password": {"root-password"}}, nil)
	if r := admin.api("POST", srv.URL+"/api/v1/users", `{"name": "dave"}`, nil); r.status != http.StatusCreated {
		t.Errorf("create a user with a session: %d %s", r.status, r.body)
	}
}

func TestOIDCUserRecord(t *testing.T) {
	u := &user{Name: "a", Admin: true, Created: time.Unix(1700000000, 0), Groups: []string{"ci"},
		OIDC: &oidcIdentity{Provider: "corp", Issuer: "https://idp.example", Subject: "s\x00x"}}
	b := u.encode()
	if b[0] != oidcUserVersion {
		t.Errorf("version %d", b[0])
	}
	got, err := decodeUser("a", b)
	if err != nil || got.OIDC == nil || *got.OIDC != *u.OIDC || !got.Admin || !slices.Equal(got.Groups, u.Groups) {
		t.Errorf("decoded %+v %v", got, err)
	}
	if _, err := decodeUser("a", b[:len(b)-1]); err == nil {
		t.Error("truncated record decoded")
	}
	s := &session{ID: "i", User: "a", Hash: []byte{1, 2}, Created: time.Unix(1, 0), Expires: time.Unix(2, 0), Method: "oidc:corp"}
	gs, err := decodeSession("i", s.encode())
	if err != nil || gs.User != "a" || gs.Method != "oidc:corp" || !gs.Expires.Equal(s.Expires) || string(gs.Hash) != "\x01\x02" {
		t.Errorf("decoded session %+v %v", gs, err)
	}
	if _, err := decodeSession("i", append(s.encode(), 0)); err == nil {
		t.Error("session with trailing bytes decoded")
	}
}

func TestOIDCStartup(t *testing.T) {
	_, err := newOIDCProvider(config.OIDCProvider{Name: "x", CAFile: "/nonexistent/ca.pem"}, nil, time.Now, quiet)
	if err == nil || !strings.Contains(err.Error(), "caFile") {
		t.Errorf("missing caFile: %v", err)
	}
	f := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(f, []byte("not pem"), 0o600)
	if _, err := newOIDCProvider(config.OIDCProvider{Name: "x", CAFile: f}, nil, time.Now, quiet); err == nil {
		t.Error("caFile without certificates accepted")
	}
	p, err := newOIDCProvider(config.OIDCProvider{Name: "x", ClientSecretFile: "/nonexistent"}, nil, time.Now, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.clientSecret(); err == nil {
		t.Error("missing client secret file read")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func cookieHeader(b *browser, u string) string {
	var parts []string
	for _, c := range b.client.Jar.Cookies(mustURL(u + "/")) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func countKeys(e *env, prefix string) int {
	v := e.store.View()
	defer v.Release()
	n := 0
	v.Scan([]byte(prefix), nil, func([]byte, meta.Record) bool { n++; return true })
	return n
}

func metricsText(e *env) string {
	var b strings.Builder
	e.reg.WriteTo(&b)
	return b.String()
}

// TestBindingPath checks that the binding cookie's path includes the
// public URL's path, under which a reverse proxy serves flint.
func TestBindingPath(t *testing.T) {
	p := &oidcProvider{cfg: config.OIDCProvider{Name: "corp"}}
	for pub, want := range map[string]string{
		"":                            "/auth/oidc/corp/",
		"https://flint.example":       "/auth/oidc/corp/",
		"https://flint.example/":      "/auth/oidc/corp/",
		"https://proxy.example/flint": "/flint/auth/oidc/corp/",
	} {
		srv, err := server.New(server.Options{Addr: "127.0.0.1:0", PublicURL: pub, Logger: quiet, Metrics: metrics.NewRegistry()})
		if err != nil {
			t.Fatal(err)
		}
		var got string
		srv.HandleFunc("GET /x", func(w http.ResponseWriter, r *http.Request) { got = bindingPath(r, p) })
		srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
		if got != want {
			t.Errorf("public URL %q: binding path %q, want %q", pub, got, want)
		}
	}
}
