package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// parseChallenge parses a Bearer WWW-Authenticate challenge.
func parseChallenge(t *testing.T, h string) map[string]string {
	t.Helper()
	rest, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		t.Fatalf("challenge %q is not Bearer", h)
	}
	params := map[string]string{}
	for rest != "" {
		k, v, ok := strings.Cut(rest, `="`)
		if !ok {
			t.Fatalf("malformed challenge %q", h)
		}
		v, rest, ok = strings.Cut(v, `"`)
		if !ok {
			t.Fatalf("malformed challenge %q", h)
		}
		params[k] = v
		rest = strings.TrimPrefix(rest, ",")
	}
	return params
}

// dockerFlow does what a Docker client does: it requests path, and on a
// 401 Bearer challenge fetches a token for the challenge's scope with
// basic credentials (or none) and retries with it.
func (e *env) dockerFlow(path, user, pass string) (response, string) {
	e.t.Helper()
	resp := e.do(request{path: path})
	if resp.status != http.StatusUnauthorized {
		return resp, ""
	}
	ch := parseChallenge(e.t, resp.header.Get("WWW-Authenticate"))
	realm, err := url.Parse(ch["realm"])
	if err != nil || realm.Path != TokenPath || ch["service"] != Issuer {
		e.t.Fatalf("challenge %v: realm or service is wrong", ch)
	}
	q := url.Values{"service": {ch["service"]}}
	if ch["scope"] != "" {
		q.Set("scope", ch["scope"])
	}
	tr := e.do(request{path: TokenPath + "?" + q.Encode(), user: user, pass: pass})
	if tr.status != http.StatusOK {
		return tr, ""
	}
	var body tokenResponse
	if err := json.Unmarshal([]byte(tr.body), &body); err != nil {
		e.t.Fatal(err)
	}
	if body.Token == "" || body.AccessToken != body.Token || body.ExpiresIn != 300 || body.IssuedAt == "" {
		e.t.Fatalf("token response %+v", body)
	}
	return e.do(request{path: path, bearer: body.Token}), body.Token
}

func TestDockerChallengeRoundTrip(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("carol", "carol-password", false, "ci")
	e.addUser("bob", "bob-password", false)

	// The challenge names the realm, service, and scope.
	resp := e.do(request{path: "/test/pull,push/docker-local/app"})
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated push: %d", resp.status)
	}
	ch := parseChallenge(t, resp.header.Get("WWW-Authenticate"))
	want := map[string]string{"realm": e.srv.URL + TokenPath, "service": "flint", "scope": "repository:docker-local/app:pull,push"}
	if !reflect.DeepEqual(ch, want) {
		t.Errorf("challenge = %v, want %v", ch, want)
	}
	if !strings.Contains(resp.body, `"code":"UNAUTHORIZED"`) || resp.header.Get("Content-Type") != "application/json" {
		t.Errorf("401 body %q", resp.body)
	}

	// A user with write access through a group gets a token and pushes.
	resp, tok := e.dockerFlow("/test/pull,push/docker-local/app", "carol", "carol-password")
	if resp.status != http.StatusOK {
		t.Fatalf("carol push: %d %s", resp.status, resp.body)
	}
	c := claimsOf(t, tok)
	if c.Subject != "carol" || c.Expiry-c.IssuedAt != 300 || c.Issuer != Issuer || c.Audience != Issuer ||
		!reflect.DeepEqual(c.Access, []access{{"repository", "docker-local/app", []string{"pull", "push"}}}) {
		t.Errorf("claims = %+v", c)
	}

	// A read-only user's token grants only pull, so the push is refused
	// with insufficient_scope, as Docker expects.
	resp, tok = e.dockerFlow("/test/pull,push/docker-local/app", "bob", "bob-password")
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("bob push: %d", resp.status)
	}
	if ch := parseChallenge(t, resp.header.Get("WWW-Authenticate")); ch["error"] != "insufficient_scope" {
		t.Errorf("bob push challenge = %v, want insufficient_scope", ch)
	}
	if c := claimsOf(t, tok); !reflect.DeepEqual(c.Access, []access{{"repository", "docker-local/app", []string{"pull"}}}) {
		t.Errorf("bob's token access = %+v", c.Access)
	}
	if resp, _ := e.dockerFlow("/test/pull/docker-local/app", "bob", "bob-password"); resp.status != http.StatusOK {
		t.Errorf("bob pull: %d", resp.status)
	}

	// A token for one image does not cover another image.
	if resp := e.do(request{path: "/test/pull/docker-local/other", bearer: tok}); resp.status != http.StatusUnauthorized {
		t.Errorf("token for another image: %d", resp.status)
	}

	// Anonymous clients get tokens for anonymous-pull repositories only.
	if resp, _ := e.dockerFlow("/test/pull/public/app", "", ""); resp.status != http.StatusOK {
		t.Errorf("anonymous pull from public: %d", resp.status)
	}
	if resp, _ := e.dockerFlow("/test/pull,push/public/app", "", ""); resp.status != http.StatusUnauthorized {
		t.Errorf("anonymous push to public: %d", resp.status)
	}
	if resp, _ := e.dockerFlow("/test/pull/docker-local/app", "", ""); resp.status != http.StatusUnauthorized {
		t.Errorf("anonymous pull from private: %d", resp.status)
	}
	// Without the token flow, anonymous pulls of public repositories work too.
	if resp := e.do(request{path: "/test/pull/public/app"}); resp.status != http.StatusOK {
		t.Errorf("direct anonymous pull: %d", resp.status)
	}

	// Wrong credentials at the token endpoint are a 401, as docker login expects.
	if resp, _ := e.dockerFlow("/test/pull/docker-local/app", "carol", "wrong-password"); resp.status != http.StatusUnauthorized ||
		!strings.HasPrefix(resp.header.Get("WWW-Authenticate"), "Basic ") {
		t.Errorf("wrong password: %d %v", resp.status, resp.header)
	}
	if resp, _ := e.dockerFlow("/test/pull/docker-local/app", "nobody", "whatever-password"); resp.status != http.StatusUnauthorized {
		t.Errorf("unknown user: %d", resp.status)
	}
}

// TestDockerLogin checks the flow of "docker login": the base endpoint
// challenges without a scope, and accepts any valid token.
func TestDockerLogin(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("bob", "bob-password", false)
	resp := e.do(request{path: "/test/base"})
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("base without credentials: %d", resp.status)
	}
	if ch := parseChallenge(t, resp.header.Get("WWW-Authenticate")); ch["scope"] != "" {
		t.Errorf("base challenge has a scope: %v", ch)
	}
	resp, tok := e.dockerFlow("/test/base", "bob", "bob-password")
	if resp.status != http.StatusOK {
		t.Fatalf("login: %d", resp.status)
	}
	if c := claimsOf(t, tok); c.Subject != "bob" || len(c.Access) != 0 {
		t.Errorf("login token claims %+v", c)
	}
	// Anonymous clients pass the base check with an anonymous token.
	if resp, _ := e.dockerFlow("/test/base", "", ""); resp.status != http.StatusOK {
		t.Errorf("anonymous token at base: %d", resp.status)
	}
	if resp := e.do(request{path: "/test/base", bearer: "garbage"}); resp.status != http.StatusUnauthorized {
		t.Errorf("garbage token at base: %d", resp.status)
	}
	if resp := e.do(request{path: "/test/base", user: "bob", pass: "bob-password"}); resp.status != http.StatusOK {
		t.Errorf("basic at base: %d", resp.status)
	}
}

func TestTokenEndpointScopes(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("alice", "alice-password", false)
	e.addUser("root", "root-password", true)
	e.serve()

	tok := e.token("alice", "alice-password",
		"repository:team-a-web/app:pull,push,delete repository:docker-local/x:pull",
		"repository:team-a-web/app:pull", "repository:team-a-db:*", "registry:catalog:*", "repository:BAD:pull",
		"repository:team-a-web/app:frobnicate")
	want := []access{
		{"repository", "team-a-web/app", []string{"pull", "push", "delete"}},
		{"repository", "team-a-db", []string{"pull", "push", "delete"}},
	}
	if c := claimsOf(t, tok); !reflect.DeepEqual(c.Access, want) {
		t.Errorf("alice's access = %+v, want %+v", c.Access, want)
	}
	if c := claimsOf(t, e.token("root", "root-password", "repository:anything/at/all:*")); len(c.Access) != 1 ||
		len(c.Access[0].Actions) != 3 {
		t.Errorf("admin's access = %+v", c.Access)
	}

	many := strings.Repeat("repository:a:pull ", maxScopes+1)
	if resp := e.do(request{path: TokenPath + "?scope=" + url.QueryEscape(many), user: "alice", pass: "alice-password"}); resp.status != http.StatusBadRequest {
		t.Errorf("too many scopes: %d", resp.status)
	}
	resp := e.do(request{path: TokenPath, user: "alice", pass: "alice-password"})
	if resp.header.Get("Cache-Control") != "no-store" {
		t.Errorf("token response Cache-Control = %q", resp.header.Get("Cache-Control"))
	}
}

func TestTokenEndpointPOST(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("alice", "alice-password", false)
	resp := e.do(request{method: "POST", path: TokenPath, form: map[string][]string{
		"grant_type": {"password"}, "username": {"alice"}, "password": {"alice-password"},
		"scope": {"repository:team-a-x:pull"}, "service": {"flint"}, "client_id": {"containerd-client"},
	}})
	if resp.status != http.StatusOK {
		t.Fatalf("password grant: %d %s", resp.status, resp.body)
	}
	var tr tokenResponse
	json.Unmarshal([]byte(resp.body), &tr)
	if c := claimsOf(t, tr.AccessToken); c.Subject != "alice" || len(c.Access) != 1 || tr.TokenType != "Bearer" {
		t.Errorf("password grant token %+v, claims %+v", tr, c)
	}
	if resp := e.do(request{method: "POST", path: TokenPath, form: map[string][]string{
		"grant_type": {"password"}, "username": {"alice"}, "password": {"nope-nope"}}}); resp.status != http.StatusUnauthorized {
		t.Errorf("password grant with a wrong password: %d", resp.status)
	}
	resp = e.do(request{method: "POST", path: TokenPath, form: map[string][]string{
		"grant_type": {"refresh_token"}, "refresh_token": {"x"}}})
	if resp.status != http.StatusBadRequest || !strings.Contains(resp.body, "unsupported_grant_type") {
		t.Errorf("refresh grant: %d %s", resp.status, resp.body)
	}
}

func TestAPITokenCredentials(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("carol", "carol-password", false, "ci")
	e.addUser("dave", "dave-password", false)
	readOnly := e.addToken("carol", false, time.Time{}, Scope{Repositories: []string{"docker-*"}, Role: RoleRead})
	full := e.addToken("carol", false, time.Time{})

	// The token stands in for a password, with the user name or with
	// __token__, at the token endpoint and directly.
	for _, user := range []string{"carol", TokenUser} {
		resp, tok := e.dockerFlow("/test/pull,push/docker-local/app", user, full)
		if resp.status != http.StatusOK {
			t.Errorf("%s with a full token: %d", user, resp.status)
		}
		if c := claimsOf(t, tok); c.Subject != "carol" || c.TokenID == "" {
			t.Errorf("claims %+v", c)
		}
		if resp := e.do(request{path: "/test/pull,push/docker-local/app", user: user, pass: full}); resp.status != http.StatusOK {
			t.Errorf("%s with basic token: %d", user, resp.status)
		}
	}
	// An API token is not accepted as a bearer token anywhere.
	for _, path := range []string{"/test/pull/docker-local/app", "/test/base", TokenPath, "/api/v1/user"} {
		if resp := e.do(request{path: path, bearer: full}); resp.status != http.StatusUnauthorized {
			t.Errorf("bearer API token at %s: %d", path, resp.status)
		}
	}
	// Another user's name with the token is refused.
	if resp := e.do(request{path: "/test/pull/docker-local/app", user: "dave", pass: full}); resp.status != http.StatusUnauthorized {
		t.Errorf("token with another user's name: %d", resp.status)
	}

	// A read-only token cannot push, though its owner can.
	resp, _ := e.dockerFlow("/test/pull,push/docker-local/app", TokenUser, readOnly)
	if resp.status != http.StatusUnauthorized {
		t.Errorf("read-only token push via JWT: %d", resp.status)
	}
	if resp := e.do(request{path: "/test/pull,push/docker-local/app", user: TokenUser, pass: readOnly}); resp.status != http.StatusForbidden ||
		!strings.Contains(resp.body, "DENIED") {
		t.Errorf("read-only token push via basic: %d %s", resp.status, resp.body)
	}
	if resp, _ := e.dockerFlow("/test/pull/docker-local/app", TokenUser, readOnly); resp.status != http.StatusOK {
		t.Errorf("read-only token pull: %d", resp.status)
	}

	// A wrong secret with a real token ID fails.
	id, _ := parseTokenString(full)
	forged := tokenStringPrefix + id + "_" + strings.Repeat("a", tokenSecretLen)
	if resp := e.do(request{path: "/test/pull/docker-local/app", user: TokenUser, pass: forged}); resp.status != http.StatusUnauthorized {
		t.Errorf("forged secret: %d", resp.status)
	}
}

// TestRevocation checks that revoking a token, deleting a user, or
// expiring a token ends access at once, also for JWTs already issued.
func TestRevocation(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("carol", "carol-password", false, "ci")
	e.addUser("erin", "erin-password", false, "ci")
	tokSecret := e.addToken("carol", false, time.Time{})
	expiring := e.addToken("carol", false, e.clock.Now().Add(time.Hour))
	path := "/test/pull/docker-local/app"
	_, viaToken := e.dockerFlow(path, TokenUser, tokSecret)
	_, viaExpiring := e.dockerFlow(path, TokenUser, expiring)
	_, viaPassword := e.dockerFlow(path, "erin", "erin-password")
	for _, tok := range []string{viaToken, viaExpiring, viaPassword} {
		if resp := e.do(request{path: path, bearer: tok}); resp.status != http.StatusOK {
			t.Fatalf("fresh JWT: %d", resp.status)
		}
	}

	ctx := context.Background()
	carol, _ := e.principal("carol")
	id, _ := parseTokenString(tokSecret)
	if err := e.svc.revokeToken(ctx, carol, id); err != nil {
		t.Fatal(err)
	}
	if resp := e.do(request{path: path, bearer: viaToken}); resp.status != http.StatusUnauthorized {
		t.Errorf("JWT of a revoked token: %d", resp.status)
	}
	if resp := e.do(request{path: path, user: TokenUser, pass: tokSecret}); resp.status != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", resp.status)
	}

	e.clock.Add(time.Hour)
	if resp := e.do(request{path: path, user: TokenUser, pass: expiring}); resp.status != http.StatusUnauthorized {
		t.Errorf("expired token: %d", resp.status)
	}
	// The JWT itself has expired by now too; issue a fresh one before the
	// token expires to see the token's expiry end it.
	e.clock.Add(-2 * time.Minute)
	_, viaExpiring = e.dockerFlow(path, TokenUser, expiring)
	e.clock.Add(2 * time.Minute)
	if resp := e.do(request{path: path, bearer: viaExpiring}); resp.status != http.StatusUnauthorized {
		t.Errorf("JWT of an expired token: %d", resp.status)
	}

	if err := e.svc.deleteUser(ctx, nil, "erin"); err != nil {
		t.Fatal(err)
	}
	if resp := e.do(request{path: path, bearer: viaPassword}); resp.status != http.StatusUnauthorized {
		t.Errorf("JWT of a deleted user: %d", resp.status)
	}
}

func TestJWTExpiry(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("bob", "bob-password", false)
	path := "/test/pull/docker-local/app"
	_, tok := e.dockerFlow(path, "bob", "bob-password")
	e.clock.Add(5*time.Minute - time.Second)
	if resp := e.do(request{path: path, bearer: tok}); resp.status != http.StatusOK {
		t.Errorf("JWT before expiry: %d", resp.status)
	}
	e.clock.Add(time.Second)
	resp := e.do(request{path: path, bearer: tok})
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("expired JWT: %d", resp.status)
	}
	if ch := parseChallenge(t, resp.header.Get("WWW-Authenticate")); ch["error"] != "invalid_token" || ch["scope"] == "" {
		t.Errorf("expired JWT challenge %v", ch)
	}
}

// TestSigningKeyReused checks that a restarted service accepts tokens the
// previous one issued.
func TestSigningKeyReused(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("bob", "bob-password", false)
	path := "/test/pull/docker-local/app"
	_, tok := e.dockerFlow(path, "bob", "bob-password")
	again := e.newService()
	r, _ := http.NewRequest("GET", path, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if !again.Allowed(r, "docker-local/app", ActionPull) {
		t.Error("a restarted service refused a token from before the restart")
	}
	if again.Allowed(r, "docker-local/app", ActionPush) {
		t.Error("Allowed granted an action the token lacks")
	}
}

func TestAuthMetrics(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("bob", "bob-password", false)
	e.dockerFlow("/test/pull/docker-local/app", "bob", "bob-password")
	e.dockerFlow("/test/pull/docker-local/app", "bob", "wrong-password")
	var b strings.Builder
	e.reg.WriteTo(&b)
	for _, want := range []string{
		`flint_auth_attempts_total{method="password",result="success"} 1`,
		`flint_auth_attempts_total{method="password",result="failure"} 1`,
		`flint_auth_attempts_total{method="jwt",result="success"} 1`,
		`flint_auth_tokens_issued_total 1`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics lack %q:\n%s", want, b.String())
		}
	}
}

// TestPasswordCache checks that a verified password is not re-derived on
// every request, and that changing the password invalidates it.
func TestPasswordCache(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("bob", "bob-password", false)
	ctx := context.Background()
	if _, err := e.svc.checkPassword(ctx, "bob", "bob-password"); err != nil {
		t.Fatal(err)
	}
	// Hold every hashing slot: a cached password still verifies, an
	// uncached one would block.
	for range cap(e.svc.hashing) {
		e.svc.hashing <- struct{}{}
	}
	if _, err := e.svc.checkPassword(ctx, "bob", "bob-password"); err != nil {
		t.Errorf("cached password: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := e.svc.checkPassword(cctx, "bob", "other-password"); err == nil {
		t.Error("an uncached password verified without a hashing slot")
	}
	for range cap(e.svc.hashing) {
		<-e.svc.hashing
	}
	if err := e.svc.setPassword(ctx, nil, "bob", "new-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.checkPassword(ctx, "bob", "bob-password"); err == nil {
		t.Error("the old password still works after a change")
	}
	if _, err := e.svc.checkPassword(ctx, "bob", "new-password"); err != nil {
		t.Errorf("new password: %v", err)
	}
}
