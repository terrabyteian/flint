package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
)

// newGoogleEnv returns an env whose configuration has one provider of
// type google, served by an in-test provider that mimics Google, and an
// administrator, root. It lets any Google account sign in unless mod
// sets hostedDomains or allowedEmails. mod may change the provider's configuration
// before the service is created.
func newGoogleEnv(t *testing.T, mod func(p map[string]any)) (*env, *idp) {
	t.Helper()
	c := &clock{t: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	p := newGoogleIdP(t, c.Now)
	secretFile := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secretFile, []byte(p.secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prov := map[string]any{"type": "google", "clientId": p.clientID, "clientSecretFile": secretFile, "allowAnyGoogleAccount": true}
	if mod != nil {
		mod(prov)
	}
	if prov["hostedDomains"] != nil || prov["allowedEmails"] != nil {
		delete(prov, "allowAnyGoogleAccount")
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(testConfig), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["auth"].(map[string]any)["oidc"] = []any{prov}
	b, _ := json.Marshal(cfg)
	e := newEnv(t, string(b))
	e.clock = c
	e.oidcTransport = googleTransport(p)
	e.svc = e.newService()
	e.addUser("root", "root-password", true)
	return e, p
}

// googleBrowser returns a browser that reaches Google's hosts at the
// in-test provider.
func googleBrowser(t *testing.T, p *idp) *browser {
	b := newBrowser(t)
	b.client.Transport = googleTransport(p)
	return b
}

// signInGoogle signs a browser in through the google provider and
// returns the final response.
func (e *env) signInGoogle(b *browser) response {
	e.t.Helper()
	return b.get(e.serve().URL + "/auth/oidc/google/login")
}

func (e *env) asRoot(method, path, body string) response {
	e.t.Helper()
	return e.do(request{method: method, path: path, body: body, user: "root", pass: "root-password"})
}

func TestGoogleSignIn(t *testing.T) {
	e, p := newGoogleEnv(t, nil)
	srv := e.serve()

	// The sign-in page lists Google under its preset name.
	if resp := newBrowser(t).get(srv.URL + "/auth/login"); !strings.Contains(resp.body, `href="oidc/google/login"`) ||
		!strings.Contains(resp.body, "Sign in with Google") {
		t.Errorf("sign-in page: %s", resp.body)
	}

	b := googleBrowser(t, p)
	resp := e.signInGoogle(b)
	if resp.status != http.StatusOK || !strings.Contains(resp.body, "Signed in as <strong>alice@example.com</strong>") {
		t.Fatalf("sign-in: %d %s", resp.status, resp.body)
	}
	// The browser went to Google's authorization endpoint from its
	// discovery document, with PKCE, and flint authenticated to the token
	// endpoint with the client secret.
	q := p.lastAuthReq
	if q.Get("client_id") != p.clientID || q.Get("scope") != "openid email profile" || q.Get("code_challenge_method") != "S256" ||
		q.Has("hd") || q.Get("redirect_uri") != srv.URL+"/auth/oidc/google/callback" {
		t.Errorf("authorization request %v", q)
	}
	if p.lastBasic != [2]string{p.clientID, p.secret} {
		t.Errorf("token request basic %v", p.lastBasic)
	}

	// The user has no groups: Google sends none.
	u, err := e.svc.getUser("alice@example.com")
	if err != nil || u.OIDC == nil || u.OIDC.Issuer != config.GoogleIssuer || u.OIDC.Subject != p.subject ||
		u.OIDC.Provider != "google" || len(u.Groups) != 0 || u.Admin {
		t.Fatalf("user %+v, %v", u, err)
	}

	// Groups and the admin flag are managed in flint and kept at the
	// next sign-in, which may name the issuer without its scheme, as
	// Google's ID tokens may.
	if r := e.asRoot("PUT", "/api/v1/groups/ci/members/alice@example.com", ""); r.status != http.StatusNoContent {
		t.Fatalf("add to group: %d %s", r.status, r.body)
	}
	if r := e.asRoot("PATCH", "/api/v1/users/alice@example.com", `{"admin": true}`); r.status != http.StatusOK {
		t.Fatalf("make admin: %d %s", r.status, r.body)
	}
	p.set(func(p *idp) { p.tokenIssuer = "accounts.google.com" })
	b = googleBrowser(t, p)
	if resp := e.signInGoogle(b); resp.status != http.StatusOK {
		t.Fatalf("second sign-in: %d %s", resp.status, resp.body)
	}
	resp = b.get(srv.URL + "/api/v1/user")
	var who whoamiJSON
	json.Unmarshal([]byte(resp.body), &who)
	if who.Name != "alice@example.com" || !slices.Equal(who.Groups, []string{"ci"}) || !who.Admin {
		t.Errorf("whoami after the second sign-in: %s", resp.body)
	}
	// The session's groups grant the user's permissions to its tokens.
	resp = b.api("POST", srv.URL+"/api/v1/tokens", `{"name": "laptop"}`, nil)
	var tok tokenJSON
	json.Unmarshal([]byte(resp.body), &tok)
	if r := e.do(request{path: "/test/push/docker-local/app", bearer: tok.Token}); r.status != http.StatusOK {
		t.Errorf("push with the token: %d %s", r.status, r.body)
	}

	// Any other issuer is refused.
	p.set(func(p *idp) { p.tokenIssuer = "https://evil.example" })
	if resp := e.signInGoogle(googleBrowser(t, p)); resp.status != http.StatusForbidden {
		t.Errorf("other issuer: %d %s", resp.status, resp.body)
	}
}

func TestGoogleSignInRefused(t *testing.T) {
	for _, tt := range []struct {
		name   string
		cfg    func(map[string]any)
		claims map[string]any
		want   string // "" for a sign-in
	}{
		{name: "unverified email", claims: map[string]any{"email_verified": false}, want: "email address is not verified"},
		{name: "no email", claims: map[string]any{"email": nil}, want: "email address is not verified"},
		{name: "unverified email with another username claim", cfg: func(p map[string]any) { p["usernameClaim"] = "sub" },
			claims: map[string]any{"email_verified": false}, want: "email address is not verified"},
		{name: "hosted domain", cfg: func(p map[string]any) { p["hostedDomains"] = []string{"example.com"} }},
		{name: "other hosted domain", cfg: func(p map[string]any) { p["hostedDomains"] = []string{"example.org"} },
			want: "not allowed to sign in"},
		{name: "no hosted domain", cfg: func(p map[string]any) { p["hostedDomains"] = []string{"example.com"} },
			claims: map[string]any{"hd": nil}, want: "not allowed to sign in"},
		{name: "allowed email", cfg: func(p map[string]any) { p["allowedEmails"] = []string{"bob@gmail.com", "alice@example.com"} },
			claims: map[string]any{"email": "Alice@Example.com"}},
		{name: "email not allowed", cfg: func(p map[string]any) { p["allowedEmails"] = []string{"bob@gmail.com"} },
			want: "not allowed to sign in"},
		{name: "allowed Gmail address outside the hosted domains", cfg: func(p map[string]any) {
			p["hostedDomains"] = []string{"example.org"}
			p["allowedEmails"] = []string{"alice@gmail.com"}
		}, claims: map[string]any{"email": "alice@gmail.com", "hd": nil}},
		{name: "allowed email Google is not authoritative for", cfg: func(p map[string]any) { p["allowedEmails"] = []string{"alice@corp.com"} },
			claims: map[string]any{"email": "alice@corp.com", "hd": nil}, want: "not allowed to sign in"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, p := newGoogleEnv(t, tt.cfg)
			p.set(func(p *idp) {
				for k, v := range tt.claims {
					p.claims[k] = v
				}
			})
			resp := e.signInGoogle(googleBrowser(t, p))
			switch {
			case tt.want == "" && (resp.status != http.StatusOK || !strings.Contains(resp.body, "Signed in as")):
				t.Errorf("got %d %s, want a sign-in", resp.status, resp.body)
			case tt.want != "" && (resp.status != http.StatusForbidden || !strings.Contains(resp.body, tt.want)):
				t.Errorf("got %d %s, want 403 with %q", resp.status, resp.body, tt.want)
			}
		})
	}
}

// TestGoogleHostedDomainHint checks that one hosted domain is passed to
// Google's account chooser as the hd parameter, unless allowedEmails
// admits accounts the hint would hide.
func TestGoogleHostedDomainHint(t *testing.T) {
	for _, tt := range []struct {
		domains, emails []string
		want            string
	}{
		{[]string{"example.com"}, nil, "example.com"},
		{[]string{"example.com", "example.org"}, nil, ""},
		{[]string{"example.com"}, []string{"contractor@gmail.com"}, ""},
	} {
		e, p := newGoogleEnv(t, func(prov map[string]any) {
			prov["hostedDomains"] = tt.domains
			if tt.emails != nil {
				prov["allowedEmails"] = tt.emails
			}
		})
		e.signInGoogle(googleBrowser(t, p))
		if got := p.lastAuthReq.Get("hd"); got != tt.want {
			t.Errorf("hostedDomains %v, allowedEmails %v: hd %q, want %q", tt.domains, tt.emails, got, tt.want)
		}
	}
}

// TestOIDCAssignedByEmail checks that a user an administrator assigns a
// verified email is linked to the identity with that email at its first
// sign-in, keeping its name, groups, and admin flag.
func TestOIDCAssignedByEmail(t *testing.T) {
	e, p := newGoogleEnv(t, nil)
	srv := e.serve()

	for _, tt := range []struct {
		body   string
		status int
	}{
		{`{"name": "x", "oidc": {"provider": "corp", "email": "x@example.com"}}`, http.StatusBadRequest},
		{`{"name": "x", "oidc": {"provider": "google", "email": "not an email"}}`, http.StatusBadRequest},
		{`{"name": "x", "oidc": {"provider": "google", "email": "x@example.com"}, "password": "a-long-password"}`, http.StatusBadRequest},
		{`{"name": "x", "oidc": {"provider": "google", "email": "x@example.com", "subject": "1"}}`, http.StatusBadRequest},
	} {
		if r := e.asRoot("POST", "/api/v1/users", tt.body); r.status != tt.status {
			t.Errorf("create %s: %d %s, want %d", tt.body, r.status, r.body, tt.status)
		}
	}

	r := e.asRoot("POST", "/api/v1/users", `{"name": "alice", "groups": ["ci"], "admin": true,
		"oidc": {"provider": "google", "email": "Alice@Example.com"}}`)
	var uj userJSON
	json.Unmarshal([]byte(r.body), &uj)
	if r.status != http.StatusCreated || uj.OIDC == nil || uj.OIDC.Email != "alice@example.com" || uj.OIDC.Subject != "" ||
		uj.OIDC.Issuer != config.GoogleIssuer || uj.Password {
		t.Fatalf("assign: %d %s", r.status, r.body)
	}
	if r := e.asRoot("POST", "/api/v1/users", `{"name": "alice2", "oidc": {"provider": "google", "email": "alice@example.com"}}`); r.status != http.StatusConflict {
		t.Errorf("assigning the email twice: %d %s", r.status, r.body)
	}
	if r := e.asRoot("PUT", "/api/v1/users/alice/password", `{"password": "a-long-password"}`); r.status != http.StatusBadRequest {
		t.Errorf("password for an assigned user: %d %s", r.status, r.body)
	}
	// Until the first sign-in, the user signs in with nothing.
	if r := e.do(request{path: "/api/v1/user", user: "alice", pass: ""}); r.status != http.StatusUnauthorized {
		t.Errorf("password login as an assigned user: %d", r.status)
	}

	b := googleBrowser(t, p)
	if resp := e.signInGoogle(b); resp.status != http.StatusOK || !strings.Contains(resp.body, "Signed in as <strong>alice</strong>") {
		t.Fatalf("sign-in: %d %s", resp.status, resp.body)
	}
	resp := b.get(srv.URL + "/api/v1/user")
	var who whoamiJSON
	json.Unmarshal([]byte(resp.body), &who)
	if who.Name != "alice" || !slices.Equal(who.Groups, []string{"ci"}) || !who.Admin {
		t.Errorf("whoami: %s", resp.body)
	}
	u, err := e.svc.getUser("alice")
	if err != nil || u.OIDC.Subject != p.subject || u.OIDC.Email != "" {
		t.Fatalf("linked user %+v, %v", u.OIDC, err)
	}
	if n := countKeys(e, oidcEmailPrefix); n != 0 {
		t.Errorf("%d email assignments left", n)
	}

	// The identity is now matched by its subject: a changed email at
	// Google signs in as the same user, and another identity with the
	// email gets a user of its own.
	p.set(func(p *idp) { p.claims["email"] = "alice@example.org" })
	if resp := e.signInGoogle(googleBrowser(t, p)); !strings.Contains(resp.body, "Signed in as <strong>alice</strong>") {
		t.Errorf("sign-in with a changed email: %d %s", resp.status, resp.body)
	}
	p.set(func(p *idp) { p.subject, p.claims["email"] = "2", "alice@example.com" })
	if resp := e.signInGoogle(googleBrowser(t, p)); !strings.Contains(resp.body, "Signed in as <strong>alice@example.com</strong>") {
		t.Errorf("another identity with the email: %d %s", resp.status, resp.body)
	}

	// Deleting a user not yet signed in frees its email.
	e.asRoot("POST", "/api/v1/users", `{"name": "bob", "oidc": {"provider": "google", "email": "bob@example.com"}}`)
	if r := e.asRoot("DELETE", "/api/v1/users/bob", ""); r.status != http.StatusNoContent || countKeys(e, oidcEmailPrefix) != 0 {
		t.Errorf("delete an assigned user: %d %s", r.status, r.body)
	}
	if r := e.asRoot("POST", "/api/v1/users", `{"name": "bob", "oidc": {"provider": "google", "email": "bob@example.com"}}`); r.status != http.StatusCreated {
		t.Errorf("assign again: %d %s", r.status, r.body)
	}
}

// TestGoogleAssignedByEmailNotAuthoritative checks that an assigned
// email links only an identity Google is authoritative for: a Workspace
// account, with an hd claim, or a Gmail address.
func TestGoogleAssignedByEmailNotAuthoritative(t *testing.T) {
	e, p := newGoogleEnv(t, nil)
	for _, body := range []string{
		`{"name": "alice", "admin": true, "oidc": {"provider": "google", "email": "alice@corp.com"}}`,
		`{"name": "bob", "oidc": {"provider": "google", "email": "bob@gmail.com"}}`,
	} {
		if r := e.asRoot("POST", "/api/v1/users", body); r.status != http.StatusCreated {
			t.Fatalf("assign %s: %d %s", body, r.status, r.body)
		}
	}

	p.set(func(p *idp) { p.subject, p.claims["email"], p.claims["hd"] = "1", "alice@corp.com", nil })
	if resp := e.signInGoogle(googleBrowser(t, p)); !strings.Contains(resp.body, "Signed in as <strong>alice@corp.com</strong>") {
		t.Errorf("sign-in with an email Google is not authoritative for: %d %s", resp.status, resp.body)
	}
	if u, _ := e.svc.getUser("alice"); u.OIDC.Subject != "" || u.OIDC.Email != "alice@corp.com" {
		t.Errorf("an email Google is not authoritative for linked the assigned user: %+v", u.OIDC)
	}

	p.set(func(p *idp) { p.subject, p.claims["email"] = "2", "bob@gmail.com" })
	if resp := e.signInGoogle(googleBrowser(t, p)); !strings.Contains(resp.body, "Signed in as <strong>bob</strong>") {
		t.Errorf("sign-in with a Gmail address: %d %s", resp.status, resp.body)
	}
}

// TestOIDCGenericNotAssignedByEmail checks that users are assigned by
// email only at Google: a generic provider's identity with a matching
// verified email never claims an assigned user.
func TestOIDCGenericNotAssignedByEmail(t *testing.T) {
	e, p := newOIDCEnv(t, nil)
	e.addUser("root", "root-password", true)
	if r := e.asRoot("POST", "/api/v1/users", `{"name": "alice", "admin": true,
		"oidc": {"provider": "corp", "email": "alice@example.com"}}`); r.status != http.StatusBadRequest {
		t.Errorf("assign at a generic provider: %d %s", r.status, r.body)
	}

	// Even with an assignment in the store, a generic provider's sign-in
	// creates a user of its own.
	pending := &user{Name: "alice", Admin: true, Created: time.Unix(1700000000, 0),
		OIDC: &oidcIdentity{Provider: "corp", Issuer: p.issuer(), Email: "alice@example.com"}}
	var b meta.Batch
	b.Put(userKey("alice"), pending.encode())
	b.Put(oidcEmailKey(p.issuer(), "alice@example.com"), []byte("alice"))
	if _, err := e.store.Commit(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	if resp := e.signIn(newBrowser(t), ""); !strings.Contains(resp.body, "Signed in as <strong>alice@example.com</strong>") {
		t.Errorf("sign-in: %d %s", resp.status, resp.body)
	}
	if u, _ := e.svc.getUser("alice"); u.OIDC.Subject != "" || u.OIDC.Email != "alice@example.com" {
		t.Errorf("a generic provider linked the assigned user: %+v", u.OIDC)
	}
	if n := countKeys(e, oidcEmailPrefix); n != 1 {
		t.Errorf("%d email assignments, want 1", n)
	}
}

func TestOIDCPendingUserRecord(t *testing.T) {
	u := &user{Name: "a", Created: time.Unix(1700000000, 0), Groups: []string{"ci"},
		OIDC: &oidcIdentity{Provider: "google", Issuer: config.GoogleIssuer, Email: "a@example.com"}}
	b := u.encode()
	if b[0] != oidcPendingUserVersion {
		t.Errorf("version %d", b[0])
	}
	got, err := decodeUser("a", b)
	if err != nil || got.OIDC == nil || *got.OIDC != *u.OIDC {
		t.Errorf("decoded %+v %v", got, err)
	}
	if _, err := decodeUser("a", b[:len(b)-1]); err == nil {
		t.Error("truncated record decoded")
	}
}
