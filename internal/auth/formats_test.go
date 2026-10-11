package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestCredentialForms checks every form in which a request can present an
// API token, at the registry, the token endpoint, the admin API, and a
// route family with another challenge style.
func TestCredentialForms(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("carol", "carol-password", false, "ci")
	tok := e.addToken("carol", false, time.Time{})
	readOnly := e.addToken("carol", false, time.Time{}, Scope{Repositories: []string{"docker-local"}, Role: RoleRead})
	id, _ := parseTokenString(tok)
	forged := tokenStringPrefix + id + "_" + strings.Repeat("a", tokenSecretLen)

	forms := []struct {
		name   string
		header func(tok string) map[string]string
	}{
		{"basic with the owner", func(tok string) map[string]string { return basicHeader("carol", tok) }},
		{"basic with __token__", func(tok string) map[string]string { return basicHeader(TokenUser, tok) }},
		{"bearer", func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }},
		{"lowercase bearer", func(tok string) map[string]string { return map[string]string{"Authorization": "bearer " + tok} }},
		{"no scheme", func(tok string) map[string]string { return map[string]string{"Authorization": tok} }},
		{"NuGet API key", func(tok string) map[string]string { return map[string]string{NuGetAPIKeyHeader: tok} }},
	}
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			for _, path := range []string{"/test/pull,push/docker-local/app", "/test/base", TokenPath, "/api/v1/user",
				"/style/basic/pull,push/docker-local/app", "/style/plain/base"} {
				if resp := e.do(request{path: path, header: f.header(tok)}); resp.status != http.StatusOK {
					t.Errorf("%s: %d %s", path, resp.status, resp.body)
				}
			}
			resp := e.do(request{path: "/style/basic/pull/docker-local/app", header: f.header(tok)})
			if want := "ok carol (token " + id + ")"; resp.body != want {
				t.Errorf("actor %q, want %q", resp.body, want)
			}
			// A forged secret is refused, as invalid credentials rather
			// than missing ones.
			resp = e.do(request{path: "/test/pull/docker-local/app", header: f.header(forged)})
			if resp.status != http.StatusUnauthorized || !strings.Contains(resp.header.Get("WWW-Authenticate"), `error="invalid_token"`) {
				t.Errorf("forged token: %d %q", resp.status, resp.header.Get("WWW-Authenticate"))
			}
			if resp := e.do(request{path: "/api/v1/user", header: f.header(forged)}); resp.status != http.StatusUnauthorized {
				t.Errorf("forged token at the admin API: %d", resp.status)
			}
			// A token's scopes still cap it.
			resp = e.do(request{path: "/test/pull,push/docker-local/app", header: f.header(readOnly)})
			if resp.status != http.StatusForbidden || !strings.Contains(resp.body, "DENIED") {
				t.Errorf("read-only token push: %d %s", resp.status, resp.body)
			}
		})
	}

	// Credentials that are not API tokens fail in the token-only forms.
	for _, h := range []map[string]string{
		{"Authorization": "carol-password"},
		{"Authorization": "flint_short"},
		{"Authorization": "Bearer flint_short"},
		{"Authorization": "Token " + tok},
		{NuGetAPIKeyHeader: "carol-password"},
	} {
		if resp := e.do(request{path: "/test/pull/docker-local/app", header: h}); resp.status != http.StatusUnauthorized {
			t.Errorf("%v: %d", h, resp.status)
		}
	}

	// The Authorization header wins over X-NuGet-ApiKey, so a client that
	// sends source credentials and a placeholder key works.
	h := basicHeader("carol", "carol-password")
	h[NuGetAPIKeyHeader] = "placeholder"
	if resp := e.do(request{path: "/test/pull/docker-local/app", header: h}); resp.status != http.StatusOK {
		t.Errorf("basic credentials with a placeholder key: %d", resp.status)
	}
	h = map[string]string{"Authorization": "Bearer " + forged, NuGetAPIKeyHeader: tok}
	if resp := e.do(request{path: "/test/pull/docker-local/app", header: h}); resp.status != http.StatusUnauthorized {
		t.Errorf("a forged bearer token with a valid key: %d", resp.status)
	}

	// A bearer API token cannot create tokens: that needs a password.
	resp := e.do(request{method: "POST", path: "/api/v1/tokens", bearer: tok, body: `{"name": "x"}`})
	if resp.status != http.StatusForbidden {
		t.Errorf("bearer token creating a token: %d %s", resp.status, resp.body)
	}

	// Revoking the token ends every form at once.
	p, _ := e.principal("carol")
	if err := e.svc.revokeToken(context.Background(), p, id); err != nil {
		t.Fatal(err)
	}
	for _, f := range forms {
		if resp := e.do(request{path: "/style/basic/pull/docker-local/app", header: f.header(tok)}); resp.status != http.StatusUnauthorized {
			t.Errorf("revoked token, %s: %d", f.name, resp.status)
		}
	}
}

func basicHeader(user, pass string) map[string]string {
	r := httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth(user, pass)
	return map[string]string{"Authorization": r.Header.Get("Authorization")}
}

// TestDockerChallengeBytes pins the registry's refusals byte for byte.
func TestDockerChallengeBytes(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("bob", "bob-password", false)
	for _, path := range []string{"/test/pull,push/docker-local/app", "/style/docker/pull,push/docker-local/app"} {
		resp := e.do(request{path: path})
		want := `Bearer realm="` + e.srv.URL + `/auth/token",service="flint",scope="repository:docker-local/app:pull,push"`
		if got := resp.header.Get("WWW-Authenticate"); resp.status != http.StatusUnauthorized || got != want {
			t.Errorf("%s: %d %q, want %q", path, resp.status, got, want)
		}
		if want := `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}` + "\n"; resp.body != want {
			t.Errorf("%s: body %q, want %q", path, resp.body, want)
		}
		resp = e.do(request{path: path, user: "bob", pass: "bob-password"})
		if want := `{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}` + "\n"; resp.status != http.StatusForbidden ||
			resp.body != want || resp.header.Get("WWW-Authenticate") != "" {
			t.Errorf("%s: %d %q, want 403 %q", path, resp.status, resp.body, want)
		}
	}
	resp := e.do(request{path: "/test/base"})
	if want := `Bearer realm="` + e.srv.URL + `/auth/token",service="flint"`; resp.header.Get("WWW-Authenticate") != want {
		t.Errorf("base challenge %q, want %q", resp.header.Get("WWW-Authenticate"), want)
	}
}

func TestChallengeStyles(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("bob", "bob-password", false)
	e.addUser("carol", "carol-password", false, "ci")
	srv := e.serve()

	tests := []struct {
		style, challenge, contentType, body401, body403 string
	}{
		{"basic", `Basic realm="flint"`, "text/plain; charset=utf-8", "authentication required\n", "access denied\n"},
		{"cargo", `Cargo login_url="` + srv.URL + `/"`, "application/json",
			`{"errors":[{"detail":"authentication required"}]}` + "\n", `{"errors":[{"detail":"access denied"}]}` + "\n"},
		{"cargo-url", `Cargo login_url="https://flint.example/me?a=\"b\""`, "application/json",
			`{"errors":[{"detail":"authentication required"}]}` + "\n", `{"errors":[{"detail":"access denied"}]}` + "\n"},
		{"plain", "", "text/plain; charset=utf-8", "authentication required\n", "access denied\n"},
		{"custom", "", "application/json", `{"error":"authentication required"}` + "\n", `{"error":"access denied"}` + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.style, func(t *testing.T) {
			path := "/style/" + tt.style + "/pull,push/docker-local/app"
			check := func(what string, resp response, status int, challenge, body string) {
				t.Helper()
				if resp.status != status || resp.header.Get("WWW-Authenticate") != challenge || resp.body != body ||
					resp.header.Get("Content-Type") != tt.contentType {
					t.Errorf("%s: %d %q %q %q; want %d %q %q %q", what, resp.status, resp.header.Get("WWW-Authenticate"),
						resp.header.Get("Content-Type"), resp.body, status, challenge, tt.contentType, body)
				}
			}
			check("anonymous", e.do(request{path: path}), http.StatusUnauthorized, tt.challenge, tt.body401)
			check("anonymous base", e.do(request{path: "/style/" + tt.style + "/base"}), http.StatusUnauthorized, tt.challenge, tt.body401)
			wrong := strings.Replace(tt.body401, "authentication required", "incorrect username, password, or token", 1)
			check("wrong password", e.do(request{path: path, user: "carol", pass: "nope"}), http.StatusUnauthorized, tt.challenge, wrong)
			check("without permission", e.do(request{path: path, user: "bob", pass: "bob-password"}), http.StatusForbidden, "", tt.body403)

			// Only the registry accepts tokens from the token service.
			jwt := e.token("carol", "carol-password", "repository:docker-local/app:pull,push")
			check("token service JWT", e.do(request{path: path, bearer: jwt}), http.StatusUnauthorized, tt.challenge, wrong)

			if resp := e.do(request{path: path, user: "carol", pass: "carol-password"}); resp.status != http.StatusOK || resp.body != "ok carol" {
				t.Errorf("carol: %d %q", resp.status, resp.body)
			}
			// Anonymous pulls work where they are allowed.
			if resp := e.do(request{path: "/style/" + tt.style + "/pull/public/app"}); resp.status != http.StatusOK || resp.body != "ok anonymous" {
				t.Errorf("anonymous pull from public: %d %q", resp.status, resp.body)
			}
		})
	}
}

// TestCargoLoginURLHost checks that the default Cargo login URL uses the
// host the client addressed.
func TestCargoLoginURLHost(t *testing.T) {
	e := newEnv(t, testConfig)
	r := httptest.NewRequest("GET", "http://flint.internal/cargo/x", nil)
	r.Host = "flint.internal"
	w := httptest.NewRecorder()
	if e.svc.Authorizer(Challenge{Style: ChallengeCargo}).Authorize(w, r, "docker-local", ActionPull) {
		t.Fatal("authorized")
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Cargo login_url="http://flint.internal/"` {
		t.Errorf("challenge %q", got)
	}
}

func TestVirtualPermissions(t *testing.T) {
	e := newEnv(t, `{
  "dataDir": "/data",
  "auth": {
    "permissions": [
      {"repositories": ["npm-all"], "role": "read", "users": ["reader", "publisher", "deleter"]},
      {"repositories": ["npm-local"], "role": "write", "users": ["publisher"]},
      {"repositories": ["npm-local"], "role": "delete", "users": ["deleter"]},
      {"repositories": ["npm-local"], "role": "delete", "users": ["member-only"]},
      {"repositories": ["*"], "role": "delete", "users": ["everywhere"]}
    ]
  }
}`)
	for _, u := range []string{"reader", "publisher", "deleter", "member-only", "everywhere"} {
		e.addUser(u, u+"-password", false)
	}
	e.addUser("root", "root-password", true)
	tests := []struct {
		user, action, publishTo string
		want                    int
	}{
		// Reading needs read on the virtual repository only.
		{"reader", "pull", "npm-local", http.StatusOK},
		{"reader", "pull", "-", http.StatusOK},
		{"member-only", "pull", "npm-local", http.StatusForbidden},
		// Publishing needs write on the publishTo member.
		{"reader", "push", "npm-local", http.StatusForbidden},
		{"publisher", "push", "npm-local", http.StatusOK},
		{"publisher", "pull,push", "npm-local", http.StatusOK},
		{"publisher", "push", "-", http.StatusForbidden},
		{"publisher", "delete", "npm-local", http.StatusForbidden},
		{"deleter", "delete", "npm-local", http.StatusOK},
		// Write on the member alone does not let a client read the view.
		{"member-only", "push", "npm-local", http.StatusOK},
		{"member-only", "pull,push", "npm-local", http.StatusForbidden},
		{"", "pull", "npm-local", http.StatusUnauthorized},
		// Without publishTo, publishing is refused to everyone.
		{"root", "push", "npm-local", http.StatusOK},
		{"root", "push", "-", http.StatusForbidden},
		{"root", "delete", "-", http.StatusForbidden},
		{"everywhere", "pull,push", "npm-local", http.StatusOK},
		{"everywhere", "push", "-", http.StatusForbidden},
		{"everywhere", "delete", "-", http.StatusForbidden},
	}
	for _, tt := range tests {
		req := request{path: "/virtual/basic/" + tt.action + "/npm-all/" + tt.publishTo}
		if tt.user != "" {
			req.user, req.pass = tt.user, tt.user+"-password"
		}
		resp := e.do(req)
		if resp.status != tt.want {
			t.Errorf("%s %s through npm-all (publishTo %s): %d, want %d", tt.user, tt.action, tt.publishTo, resp.status, tt.want)
		}
	}

	// The Docker challenge names a scope on each repository involved.
	resp := e.do(request{path: "/virtual/docker/pull,push/npm-all/npm-local"})
	if got := parseChallenge(t, resp.header.Get("WWW-Authenticate"))["scope"]; got != "repository:npm-all:pull repository:npm-local:push" {
		t.Errorf("virtual scope %q", got)
	}

	// AllowedVirtual applies the same rule without writing a response.
	a := e.svc.Authorizer(Challenge{Style: ChallengeBasic})
	r := httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth("reader", "reader-password")
	if !a.AllowedVirtual(r, "npm-all", "npm-local", ActionPull) || a.AllowedVirtual(r, "npm-all", "npm-local", ActionPush) {
		t.Error("AllowedVirtual for reader")
	}
	if a.Allowed(r, "npm-local", ActionPull) {
		t.Error("reader may read the member directly")
	}
	for _, u := range []string{"root", "everywhere"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.SetBasicAuth(u, u+"-password")
		if !a.AllowedVirtual(r, "npm-all", "npm-local", ActionPush) || a.AllowedVirtual(r, "npm-all", "", ActionPush) || a.AllowedVirtual(r, "npm-all", "", ActionDelete) {
			t.Errorf("AllowedVirtual for %s without publishTo", u)
		}
	}
}

func TestLoginToken(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("carol", "carol-password", false, "ci")
	e.addUser("root", "root-password", true)
	e.addUser("nopass", "", false)
	ctx := context.Background()

	tok, err := e.svc.LoginToken(ctx, "carol", "carol-password", "npm")
	if err != nil {
		t.Fatal(err)
	}
	// It carries carol's permissions, in every credential form.
	if resp := e.do(request{path: "/style/plain/pull,push/docker-local/app", bearer: tok}); resp.status != http.StatusOK {
		t.Errorf("login token push: %d", resp.status)
	}
	if resp := e.do(request{path: "/style/plain/pull/team-a-web", bearer: tok}); resp.status != http.StatusForbidden {
		t.Errorf("login token beyond carol's permissions: %d", resp.status)
	}

	// It is listed with its name and expiry, like any other token.
	var list []tokenJSON
	e.wantStatus(e.api("GET", "/api/v1/tokens", "carol", "carol-password", "", &list), http.StatusOK, "list tokens")
	id, _ := parseTokenString(tok)
	if len(list) != 1 || list[0].ID != id || list[0].Name != "npm login 2026-05-01T12:00:00Z" || list[0].Admin ||
		list[0].Expires == nil || !list[0].Expires.Equal(e.clock.Now().Add(90*24*time.Hour)) {
		t.Errorf("tokens %+v", list)
	}

	// It expires after the login token lifetime.
	e.clock.Add(90*24*time.Hour - time.Second)
	if resp := e.do(request{path: "/test/pull/docker-local/app", bearer: tok}); resp.status != http.StatusOK {
		t.Errorf("before expiry: %d", resp.status)
	}
	e.clock.Add(time.Second)
	if resp := e.do(request{path: "/test/pull/docker-local/app", bearer: tok}); resp.status != http.StatusUnauthorized {
		t.Errorf("after expiry: %d", resp.status)
	}

	// It is revocable like any other token.
	tok2, err := e.svc.LoginToken(ctx, "carol", "carol-password", "cargo")
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := parseTokenString(tok2)
	e.wantStatus(e.api("DELETE", "/api/v1/tokens/"+id2, "carol", "carol-password", "", nil), http.StatusNoContent, "revoke")
	if resp := e.do(request{path: "/test/pull/docker-local/app", bearer: tok2}); resp.status != http.StatusUnauthorized {
		t.Errorf("revoked login token: %d", resp.status)
	}

	// An administrator's login token has the admin role on repositories,
	// but not the global admin role.
	rootTok, err := e.svc.LoginToken(ctx, "root", "root-password", "npm")
	if err != nil {
		t.Fatal(err)
	}
	if resp := e.do(request{path: "/test/delete/team-a-web", bearer: rootTok}); resp.status != http.StatusOK {
		t.Errorf("root login token delete: %d", resp.status)
	}
	if resp := e.do(request{path: "/api/v1/users", bearer: rootTok}); resp.status != http.StatusForbidden {
		t.Errorf("root login token at the admin API: %d", resp.status)
	}

	// Wrong credentials mint nothing.
	for _, c := range []struct{ user, pass string }{
		{"carol", "wrong-password"}, {"nobody", "carol-password"}, {"nopass", ""}, {"carol", tok}, {"carol", ""},
	} {
		if _, err := e.svc.LoginToken(ctx, c.user, c.pass, "npm"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("LoginToken(%q, %q) = %v, want ErrInvalidCredentials", c.user, c.pass, err)
		}
	}
	for _, client := range []string{"", strings.Repeat("x", 65), "npm\n", "npm\x00"} {
		if _, err := e.svc.LoginToken(ctx, "carol", "carol-password", client); err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("client %q: %v", client, err)
		}
	}
	if list, _ := e.svc.listTokens("carol"); len(list) != 1 {
		t.Errorf("carol has %d tokens, want 1", len(list))
	}
}

func TestLoginTokenTTL(t *testing.T) {
	e := newEnv(t, `{"dataDir": "/data", "auth": {"loginTokenTTL": "1h"}}`)
	e.addUser("carol", "carol-password", false)
	tok, err := e.svc.LoginToken(context.Background(), "carol", "carol-password", "npm")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := parseTokenString(tok)
	tk, err := e.svc.getToken(id)
	if err != nil {
		t.Fatal(err)
	}
	if want := e.clock.Now().Add(time.Hour); !tk.Expires.Equal(want) {
		t.Errorf("expires %v, want %v", tk.Expires, want)
	}
}

// signedPath returns path with a signature for p.
func (e *env) signedPath(p *Principal, path string, ttl time.Duration) string {
	return path + "?" + e.svc.SignURL(p, path, ttl)
}

func TestSignedURL(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("carol", "carol-password", false, "ci")
	e.addUser("bob", "bob-password", false)
	carol, _ := e.principal("carol")
	const path = "/signed/docker-local/pkg/v1.0/a b.zip"

	u := e.signedPath(carol, path, 0)
	if resp := e.do(request{path: strings.Replace(u, " ", "%20", 1)}); resp.status != http.StatusOK || resp.body != "ok carol" {
		t.Errorf("signed URL: %d %q", resp.status, resp.body)
	}

	// An unsigned URL is told apart from a bad signature.
	if resp := e.do(request{path: "/signed/docker-local/x"}); resp.status != http.StatusUnauthorized || !strings.Contains(resp.body, "not signed") {
		t.Errorf("unsigned: %d %q", resp.status, resp.body)
	}

	// Tampering with any signed field breaks the signature.
	good := e.signedPath(carol, "/signed/docker-local/f", 0)
	q, _ := url.ParseQuery(strings.SplitN(good, "?", 2)[1])
	tamper := func(k, v string) string {
		q2 := url.Values{}
		for kk, vv := range q {
			q2[kk] = append([]string(nil), vv...)
		}
		q2.Set(k, v)
		return "/signed/docker-local/f?" + q2.Encode()
	}
	for what, p := range map[string]string{
		"path":       strings.Replace(good, "/f?", "/g?", 1),
		"expiry":     tamper(signedExpiresParam, q.Get(signedExpiresParam)+"0"),
		"user":       tamper(signedUserParam, "bob"),
		"token":      tamper(signedTokenParam, "aaaaaaaaaaaaaaaa"),
		"signature":  tamper(signedSigParam, strings.Repeat("A", 43)),
		"bad base64": tamper(signedSigParam, "!!"),
		"duplicate":  good + "&" + signedUserParam + "=bob",
		"no expiry":  "/signed/docker-local/f?" + signedSigParam + "=" + q.Get(signedSigParam),
	} {
		if resp := e.do(request{path: p}); resp.status != http.StatusUnauthorized || !strings.Contains(resp.body, "invalid credentials") {
			t.Errorf("tampered %s: %d %q", what, resp.status, resp.body)
		}
	}

	// A signature works until it expires: 10 minutes by default.
	e.clock.Add(10*time.Minute - time.Second)
	if resp := e.do(request{path: good}); resp.status != http.StatusOK {
		t.Errorf("before expiry: %d", resp.status)
	}
	e.clock.Add(time.Second)
	if resp := e.do(request{path: good}); resp.status != http.StatusUnauthorized {
		t.Errorf("after expiry: %d", resp.status)
	}
	long := e.signedPath(carol, "/signed/docker-local/f", time.Hour)
	e.clock.Add(59 * time.Minute)
	if resp := e.do(request{path: long}); resp.status != http.StatusOK {
		t.Errorf("one-hour signature after 59 minutes: %d", resp.status)
	}

	// It works only while the principal may still read the repository.
	if resp := e.do(request{path: e.signedPath(carol, "/signed/team-a-web/f", 0)}); resp.status != http.StatusForbidden {
		t.Errorf("repository carol cannot read: %d", resp.status)
	}
	fresh := e.signedPath(carol, "/signed/docker-local/f", 0)
	if err := e.svc.setGroupMember(context.Background(), nil, "ci", "carol", false); err != nil {
		t.Fatal(err)
	}
	if resp := e.do(request{path: fresh}); resp.status != http.StatusForbidden {
		t.Errorf("after carol lost access: %d", resp.status)
	}
	bob, _ := e.principal("bob")
	bobURL := e.signedPath(bob, "/signed/docker-local/f", 0)
	if err := e.svc.deleteUser(context.Background(), nil, "bob"); err != nil {
		t.Fatal(err)
	}
	if resp := e.do(request{path: bobURL}); resp.status != http.StatusUnauthorized {
		t.Errorf("deleted user: %d", resp.status)
	}

	// Anonymous signatures follow anonymous pull.
	if resp := e.do(request{path: e.signedPath(nil, "/signed/public/f", 0)}); resp.status != http.StatusOK || resp.body != "ok anonymous" {
		t.Errorf("anonymous, public: %d %q", resp.status, resp.body)
	}
	if resp := e.do(request{path: e.signedPath(anonymous, "/signed/docker-local/f", 0)}); resp.status != http.StatusForbidden {
		t.Errorf("anonymous, private: %d", resp.status)
	}
}

func TestSignedURLToken(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("alice", "alice-password", false) // delete on team-a-*
	tok := e.addToken("alice", false, time.Time{}, Scope{Repositories: []string{"team-a-web"}, Role: RoleRead})
	id, _ := parseTokenString(tok)

	// Sign for the principal a request was admitted as.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if !e.svc.Authorizer(Challenge{Style: ChallengePlain}).Authorize(httptest.NewRecorder(), r, "team-a-web", ActionPull) {
		t.Fatal("not authorized")
	}
	p := PrincipalOf(r)
	if p == nil || p.User != "alice" || p.TokenID != id {
		t.Fatalf("principal %+v", p)
	}
	u := e.signedPath(p, "/signed/team-a-web/f", 0)
	if resp := e.do(request{path: u}); resp.status != http.StatusOK || resp.body != "ok alice (token "+id+")" {
		t.Errorf("token-signed URL: %d %q", resp.status, resp.body)
	}
	// The token's scopes still cap it, though alice may read team-a-api.
	if resp := e.do(request{path: e.signedPath(p, "/signed/team-a-api/f", 0)}); resp.status != http.StatusForbidden {
		t.Errorf("beyond the token's scopes: %d", resp.status)
	}
	// Revoking the token ends the URL.
	alice, _ := e.principal("alice")
	if err := e.svc.revokeToken(context.Background(), alice, id); err != nil {
		t.Fatal(err)
	}
	if resp := e.do(request{path: u}); resp.status != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", resp.status)
	}
}

func TestURLSigningKey(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("carol", "carol-password", false, "ci")
	carol, _ := e.principal("carol")
	b, err := readFile(e, "/data/auth/url-signing.key")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 2*urlKeyLen+1 {
		t.Errorf("key file is %d bytes", len(b))
	}
	u := e.signedPath(carol, "/signed/docker-local/f", 0)

	// The key survives a restart, so issued URLs keep working.
	e.svc = e.newService()
	e.srv = nil
	if resp := e.do(request{path: u}); resp.status != http.StatusOK {
		t.Errorf("after restart: %d", resp.status)
	}

	// A corrupt key file stops the start.
	if err := writeFileDurably(e.fs, "/data/auth/url-signing.key", []byte("not hex\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Store: e.store, KeyDir: "/data/auth", FS: e.fs, Logger: quiet, PasswordIterations: testIterations}); err == nil ||
		!strings.Contains(err.Error(), "url-signing.key") {
		t.Errorf("corrupt key: %v", err)
	}
}

func readFile(e *env, path string) ([]byte, error) {
	f, err := e.fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
