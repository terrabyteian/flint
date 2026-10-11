package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
)

// api sends an admin API request as user with password (or an API token)
// and decodes a JSON response into out, if out is not nil.
func (e *env) api(method, path, user, pass, body string, out any) response {
	e.t.Helper()
	resp := e.do(request{method: method, path: path, user: user, pass: pass, body: body})
	if out != nil && resp.status < 300 {
		if err := json.Unmarshal([]byte(resp.body), out); err != nil {
			e.t.Fatalf("%s %s: decoding %q: %v", method, path, resp.body, err)
		}
	}
	return resp
}

func (e *env) wantStatus(resp response, want int, what string) {
	e.t.Helper()
	if resp.status != want {
		e.t.Errorf("%s: status %d %s, want %d", what, resp.status, resp.body, want)
	}
}

func TestAPIAuthentication(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	resp := e.api("GET", "/api/v1/user", "", "", "", nil)
	e.wantStatus(resp, http.StatusUnauthorized, "no credentials")
	if resp.header.Get("WWW-Authenticate") != `Basic realm="flint"` {
		t.Errorf("challenge %q", resp.header.Get("WWW-Authenticate"))
	}
	e.wantStatus(e.api("GET", "/api/v1/user", "root", "wrong-password", "", nil), http.StatusUnauthorized, "wrong password")

	var me whoamiJSON
	e.wantStatus(e.api("GET", "/api/v1/user", "root", "root-password", "", &me), http.StatusOK, "whoami")
	if me.Name != "root" || !me.Admin {
		t.Errorf("whoami = %+v", me)
	}

	// Tokens from the Docker token service are not accepted.
	e.serve()
	jwt := e.token("root", "root-password")
	e.wantStatus(e.do(request{path: "/api/v1/user", bearer: jwt}), http.StatusUnauthorized, "JWT")

	e.wantStatus(e.api("GET", "/api/v1/nonexistent", "root", "root-password", "", nil), http.StatusNotFound, "unknown path")
}

func TestAPIUsers(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	as := func(method, path, body string, out any) response {
		return e.api(method, path, "root", "root-password", body, out)
	}

	var u userJSON
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "alice", "password": "alice-password", "groups": ["dev", "ci", "dev"]}`, &u),
		http.StatusCreated, "create alice")
	if u.Name != "alice" || u.Admin || !reflect.DeepEqual(u.Groups, []string{"ci", "dev"}) || !u.Password || u.Created.IsZero() {
		t.Errorf("created %+v", u)
	}
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "alice", "password": "alice-password"}`, nil), http.StatusConflict, "duplicate")
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "Alice", "password": "alice-password"}`, nil), http.StatusBadRequest, "bad name")
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "__token__", "password": "alice-password"}`, nil), http.StatusBadRequest, "reserved name")
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "x", "password": "short"}`, nil), http.StatusBadRequest, "short password")
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "x", "groups": ["Bad Group"]}`, nil), http.StatusBadRequest, "bad group")
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "x", "extra": 1}`, nil), http.StatusBadRequest, "unknown field")
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "x"} {}`, nil), http.StatusBadRequest, "trailing data")
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "`+strings.Repeat("x", maxAPIBody)+`"}`, nil),
		http.StatusRequestEntityTooLarge, "huge body")
	// A user without a password cannot log in with one.
	e.wantStatus(as("POST", "/api/v1/users", `{"name": "nopw"}`, &u), http.StatusCreated, "create without password")
	if u.Password {
		t.Error("user without a password reports one")
	}
	e.wantStatus(e.api("GET", "/api/v1/user", "nopw", "", "", nil), http.StatusUnauthorized, "empty password")

	var list []userJSON
	e.wantStatus(as("GET", "/api/v1/users", "", &list), http.StatusOK, "list")
	var names []string
	for _, u := range list {
		names = append(names, u.Name)
	}
	if !reflect.DeepEqual(names, []string{"alice", "nopw", "root"}) {
		t.Errorf("users = %v", names)
	}

	// Non-administrators may read only themselves and may not manage users.
	e.wantStatus(e.api("GET", "/api/v1/users/alice", "alice", "alice-password", "", nil), http.StatusOK, "alice reads herself")
	e.wantStatus(e.api("GET", "/api/v1/users/root", "alice", "alice-password", "", nil), http.StatusForbidden, "alice reads root")
	e.wantStatus(e.api("GET", "/api/v1/users", "alice", "alice-password", "", nil), http.StatusForbidden, "alice lists")
	e.wantStatus(e.api("POST", "/api/v1/users", "alice", "alice-password", `{"name": "y"}`, nil), http.StatusForbidden, "alice creates")
	e.wantStatus(e.api("DELETE", "/api/v1/users/root", "alice", "alice-password", "", nil), http.StatusForbidden, "alice deletes")
	e.wantStatus(e.api("PATCH", "/api/v1/users/alice", "alice", "alice-password", `{"admin": true}`, nil), http.StatusForbidden, "alice promotes herself")
	e.wantStatus(as("GET", "/api/v1/users/ghost", "", nil), http.StatusNotFound, "unknown user")

	// PATCH sets the admin flag and the groups.
	e.wantStatus(as("PATCH", "/api/v1/users/alice", `{"admin": true, "groups": ["ops"]}`, &u), http.StatusOK, "patch")
	if !u.Admin || !reflect.DeepEqual(u.Groups, []string{"ops"}) {
		t.Errorf("patched %+v", u)
	}
	e.wantStatus(as("PATCH", "/api/v1/users/alice", `{}`, &u), http.StatusOK, "empty patch")
	if !u.Admin || !reflect.DeepEqual(u.Groups, []string{"ops"}) {
		t.Errorf("empty patch changed the user: %+v", u)
	}
	e.wantStatus(as("PATCH", "/api/v1/users/alice", `{"groups": []}`, &u), http.StatusOK, "clear groups")
	if len(u.Groups) != 0 {
		t.Errorf("groups not cleared: %+v", u)
	}

	// The last administrator cannot be demoted or deleted.
	e.wantStatus(as("PATCH", "/api/v1/users/alice", `{"admin": false}`, nil), http.StatusOK, "demote alice")
	e.wantStatus(as("PATCH", "/api/v1/users/root", `{"admin": false}`, nil), http.StatusConflict, "demote the last admin")
	e.wantStatus(as("DELETE", "/api/v1/users/root", "", nil), http.StatusConflict, "delete the last admin")
	e.wantStatus(as("DELETE", "/api/v1/users/alice", "", nil), http.StatusNoContent, "delete alice")
	e.wantStatus(as("DELETE", "/api/v1/users/alice", "", nil), http.StatusNotFound, "delete alice again")
	e.wantStatus(e.api("GET", "/api/v1/user", "alice", "alice-password", "", nil), http.StatusUnauthorized, "deleted user logs in")
}

func TestAPIPasswords(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("bob", "bob-password", false)
	e.addUser("carol", "carol-password", false)
	bobToken := e.addToken("bob", false, time.Time{})

	e.wantStatus(e.api("PUT", "/api/v1/users/bob/password", "bob", "bob-password", `{"password": "bob-password-2"}`, nil),
		http.StatusNoContent, "bob changes his own")
	e.wantStatus(e.api("GET", "/api/v1/user", "bob", "bob-password", "", nil), http.StatusUnauthorized, "old password")
	e.wantStatus(e.api("GET", "/api/v1/user", "bob", "bob-password-2", "", nil), http.StatusOK, "new password")
	e.wantStatus(e.api("PUT", "/api/v1/users/carol/password", "bob", "bob-password-2", `{"password": "hijacked-pw"}`, nil),
		http.StatusForbidden, "bob changes carol's")
	e.wantStatus(e.api("PUT", "/api/v1/users/bob/password", TokenUser, bobToken, `{"password": "via-token-pw"}`, nil),
		http.StatusForbidden, "bob's token changes bob's")
	e.wantStatus(e.api("PUT", "/api/v1/users/bob/password", "bob", "bob-password-2", `{"password": "short"}`, nil),
		http.StatusBadRequest, "short password")
	e.wantStatus(e.api("PUT", "/api/v1/users/carol/password", "root", "root-password", `{"password": "carol-password-2"}`, nil),
		http.StatusNoContent, "admin changes carol's")
	e.wantStatus(e.api("GET", "/api/v1/user", "carol", "carol-password-2", "", nil), http.StatusOK, "carol's new password")
	e.wantStatus(e.api("PUT", "/api/v1/users/ghost/password", "root", "root-password", `{"password": "ghost-password"}`, nil),
		http.StatusNotFound, "unknown user")
}

func TestAPIGroups(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("bob", "bob-password", false)
	as := func(method, path string, out any) response {
		return e.api(method, path, "root", "root-password", "", out)
	}

	// bob has read on docker-local; joining ci gives him write.
	bob := func() *Principal { p, _ := e.principal("bob"); return p }
	if e.svc.Role(bob(), "docker-local") != RoleRead {
		t.Fatal("bob's starting role")
	}
	e.wantStatus(as("PUT", "/api/v1/groups/ci/members/bob", nil), http.StatusNoContent, "add bob to ci")
	e.wantStatus(as("PUT", "/api/v1/groups/ci/members/bob", nil), http.StatusNoContent, "add bob to ci again")
	e.wantStatus(as("PUT", "/api/v1/groups/ops/members/bob", nil), http.StatusNoContent, "add bob to ops")
	if e.svc.Role(bob(), "docker-local") != RoleWrite {
		t.Error("joining ci did not grant write")
	}
	var groups []groupJSON
	e.wantStatus(as("GET", "/api/v1/groups", &groups), http.StatusOK, "list groups")
	want := []groupJSON{{"ci", []string{"bob"}}, {"ops", []string{"bob"}}}
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("groups = %+v, want %+v", groups, want)
	}
	e.wantStatus(as("DELETE", "/api/v1/groups/ci/members/bob", nil), http.StatusNoContent, "remove bob from ci")
	e.wantStatus(as("DELETE", "/api/v1/groups/ci/members/bob", nil), http.StatusNoContent, "remove bob from ci again")
	if e.svc.Role(bob(), "docker-local") != RoleRead {
		t.Error("leaving ci did not revoke write")
	}
	e.wantStatus(as("GET", "/api/v1/groups", &groups), http.StatusOK, "list groups")
	want = []groupJSON{{"ci", []string{}}, {"ops", []string{"bob"}}} // ci stays listed: config names it
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("groups = %+v, want %+v", groups, want)
	}
	e.wantStatus(as("PUT", "/api/v1/groups/ci/members/ghost", nil), http.StatusNotFound, "unknown user")
	e.wantStatus(as("PUT", "/api/v1/groups/Bad/members/bob", nil), http.StatusBadRequest, "bad group")
	e.wantStatus(e.api("PUT", "/api/v1/groups/ci/members/bob", "bob", "bob-password", "", nil), http.StatusForbidden, "bob adds himself")
}

func TestAPITokens(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("carol", "carol-password", false, "ci")
	e.addUser("dave", "dave-password", false)

	var created tokenJSON
	e.wantStatus(e.api("POST", "/api/v1/tokens", "carol", "carol-password",
		`{"name": "ci pull", "expiresIn": "720h", "scopes": [{"repositories": ["docker-local"], "role": "read"}]}`, &created),
		http.StatusCreated, "create")
	if created.Token == "" || created.Owner != "carol" || created.Name != "ci pull" || created.Expires == nil ||
		!created.Expires.Equal(e.clock.Now().Add(720*time.Hour)) || created.Admin ||
		!reflect.DeepEqual(created.Scopes, []scopeJSON{{[]string{"docker-local"}, "read"}}) {
		t.Errorf("created %+v", created)
	}
	if id, ok := parseTokenString(created.Token); !ok || id != created.ID {
		t.Errorf("token %q does not carry id %q", created.Token, created.ID)
	}

	// Only the hash is stored.
	v := e.store.View()
	v.Scan(nil, nil, func(key []byte, r meta.Record) bool {
		if strings.Contains(string(r.Value), created.Token) || strings.Contains(string(r.Value), created.Token[len(tokenStringPrefix)+tokenIDLen+1:]) {
			t.Errorf("key %q stores the token secret", key)
		}
		return true
	})
	v.Release()

	// The token authenticates the API, but cannot create tokens.
	var me whoamiJSON
	e.wantStatus(e.api("GET", "/api/v1/user", TokenUser, created.Token, "", &me), http.StatusOK, "whoami by token")
	if me.Name != "carol" || me.TokenID != created.ID {
		t.Errorf("whoami by token = %+v", me)
	}
	e.wantStatus(e.api("POST", "/api/v1/tokens", TokenUser, created.Token, `{"name": "x"}`, nil), http.StatusForbidden, "token mints token")

	// Without scopes, a token carries all of its owner's permissions.
	e.clock.Add(time.Second)
	var full tokenJSON
	e.wantStatus(e.api("POST", "/api/v1/tokens", "carol", "carol-password", `{"name": "full", "expiresAt": "2027-01-01T00:00:00Z"}`, &full),
		http.StatusCreated, "create full")
	if !reflect.DeepEqual(full.Scopes, []scopeJSON{{[]string{"*"}, "admin"}}) || full.Expires == nil || full.Expires.Year() != 2027 {
		t.Errorf("full token %+v", full)
	}
	e.clock.Add(time.Second)
	var forever tokenJSON
	e.wantStatus(e.api("POST", "/api/v1/tokens", "carol", "carol-password", `{"name": "forever"}`, &forever), http.StatusCreated, "no expiry")
	if forever.Expires != nil {
		t.Errorf("token without expiry has %v", forever.Expires)
	}

	for name, body := range map[string]string{
		"no name":      `{}`,
		"blank name":   `{"name": "  "}`,
		"long name":    `{"name": "` + strings.Repeat("n", MaxTokenNameLen+1) + `"}`,
		"past expiry":  `{"name": "x", "expiresAt": "2020-01-01T00:00:00Z"}`,
		"both expiry":  `{"name": "x", "expiresIn": "1h", "expiresAt": "2030-01-01T00:00:00Z"}`,
		"bad duration": `{"name": "x", "expiresIn": "soon"}`,
		"neg duration": `{"name": "x", "expiresIn": "-1h"}`,
		"empty scopes": `{"name": "x", "scopes": []}`,
		"bad role":     `{"name": "x", "scopes": [{"repositories": ["a"], "role": "owner"}]}`,
		"no repos":     `{"name": "x", "scopes": [{"repositories": [], "role": "read"}]}`,
		"bad pattern":  `{"name": "x", "scopes": [{"repositories": ["A/B"], "role": "read"}]}`,
		"admin token":  `{"name": "x", "admin": true}`,
	} {
		e.wantStatus(e.api("POST", "/api/v1/tokens", "carol", "carol-password", body, nil), http.StatusBadRequest, name)
	}

	var list []tokenJSON
	e.wantStatus(e.api("GET", "/api/v1/tokens", "carol", "carol-password", "", &list), http.StatusOK, "list")
	if len(list) != 3 || list[0].ID != created.ID || list[1].ID != full.ID || list[2].ID != forever.ID {
		t.Fatalf("carol's tokens = %+v", list)
	}
	for _, tk := range list {
		if tk.Token != "" {
			t.Error("a listed token shows its secret")
		}
	}
	e.wantStatus(e.api("GET", "/api/v1/tokens", "dave", "dave-password", "", &list), http.StatusOK, "dave's list")
	if len(list) != 0 {
		t.Errorf("dave sees tokens %+v", list)
	}

	// Revoking: one's own, or any as an administrator; others' tokens are
	// invisible.
	e.wantStatus(e.api("DELETE", "/api/v1/tokens/"+created.ID, "dave", "dave-password", "", nil), http.StatusNotFound, "dave revokes carol's")
	e.wantStatus(e.api("DELETE", "/api/v1/tokens/"+created.ID, TokenUser, created.Token, "", nil), http.StatusNoContent, "token revokes itself")
	e.wantStatus(e.api("GET", "/api/v1/user", TokenUser, created.Token, "", nil), http.StatusUnauthorized, "revoked token")
	e.wantStatus(e.api("DELETE", "/api/v1/tokens/"+created.ID, "carol", "carol-password", "", nil), http.StatusNotFound, "revoke again")
	e.wantStatus(e.api("DELETE", "/api/v1/tokens/"+full.ID, "root", "root-password", "", nil), http.StatusNoContent, "admin revokes")
	e.wantStatus(e.api("GET", "/api/v1/tokens", "carol", "carol-password", "", &list), http.StatusOK, "list")
	if len(list) != 1 {
		t.Errorf("carol has %d tokens after revocations, want 1", len(list))
	}

	// Deleting a user deletes the user's tokens.
	e.wantStatus(e.api("DELETE", "/api/v1/users/carol", "root", "root-password", "", nil), http.StatusNoContent, "delete carol")
	v = e.store.View()
	v.Scan([]byte("auth\x00token"), nil, func(key []byte, _ meta.Record) bool {
		t.Errorf("key %q remains after deleting the user", key)
		return true
	})
	v.Release()
}

// TestAdminToken checks that a token uses its owner's global admin role
// only when created with it.
func TestAdminToken(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	var adminTok, plainTok tokenJSON
	e.wantStatus(e.api("POST", "/api/v1/tokens", "root", "root-password", `{"name": "automation", "admin": true}`, &adminTok),
		http.StatusCreated, "admin token")
	e.wantStatus(e.api("POST", "/api/v1/tokens", "root", "root-password",
		`{"name": "pull", "scopes": [{"repositories": ["*"], "role": "read"}]}`, &plainTok), http.StatusCreated, "plain token")
	if !adminTok.Admin {
		t.Error("admin token lacks the admin flag")
	}
	e.wantStatus(e.api("GET", "/api/v1/users", TokenUser, adminTok.Token, "", nil), http.StatusOK, "admin token lists users")
	e.wantStatus(e.api("GET", "/api/v1/users", TokenUser, plainTok.Token, "", nil), http.StatusForbidden, "plain token lists users")
	e.wantStatus(e.do(request{path: "/test/pull,push/anything", user: TokenUser, pass: plainTok.Token}), http.StatusForbidden, "plain token pushes")
	e.wantStatus(e.do(request{path: "/test/pull/anything", user: TokenUser, pass: plainTok.Token}), http.StatusOK, "plain token pulls")

	// An administrator demoted later loses the admin role through the token too.
	e.addUser("other", "other-password", true)
	e.wantStatus(e.api("PATCH", "/api/v1/users/root", "other", "other-password", `{"admin": false}`, nil), http.StatusOK, "demote root")
	e.wantStatus(e.api("GET", "/api/v1/users", TokenUser, adminTok.Token, "", nil), http.StatusForbidden, "demoted admin's token")
}

func TestBootstrap(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "password")

	e := newEnv(t, testConfig)
	if _, err := e.svc.Bootstrap(ctx, "admin", pwFile); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("missing file: %v", err)
	}
	os.WriteFile(pwFile, []byte("short\n"), 0o600)
	if _, err := e.svc.Bootstrap(ctx, "admin", pwFile); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Errorf("short password: %v", err)
	}
	if err := os.WriteFile(pwFile, []byte("s3cret-admin-pw\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := e.svc.Bootstrap(ctx, "admin", pwFile)
	if err != nil || !created {
		t.Fatalf("Bootstrap = %v, %v", created, err)
	}
	var me whoamiJSON
	e.wantStatus(e.api("GET", "/api/v1/user", "admin", "s3cret-admin-pw", "", &me), http.StatusOK, "bootstrap admin logs in")
	if !me.Admin {
		t.Error("the bootstrap user is not an administrator")
	}

	// With an administrator present, the file is not read again: it may
	// be gone, and a changed password does not reset the account.
	os.Remove(pwFile)
	if created, err := e.svc.Bootstrap(ctx, "admin", pwFile); err != nil || created {
		t.Errorf("second Bootstrap = %v, %v", created, err)
	}

	// The batch origin names the system as the actor, never the secret.
	var found bool
	e.store.ReadLog(ctx, 0, func(en meta.Entry) error {
		if en.Origin.Action == "auth.user.create" {
			found = true
			if en.Origin.Actor != "system" || en.Origin.Target != "user admin" {
				t.Errorf("origin %+v", en.Origin)
			}
		}
		return nil
	})
	if !found {
		t.Error("no auth.user.create batch in the log")
	}

	// A non-admin user holding the bootstrap name is an error, not a takeover.
	e2 := newEnv(t, testConfig)
	e2.addUser("admin", "not-an-admin", false)
	os.WriteFile(pwFile, []byte("s3cret-admin-pw"), 0o600)
	if _, err := e2.svc.Bootstrap(ctx, "admin", pwFile); err == nil || !strings.Contains(err.Error(), "not one") {
		t.Errorf("bootstrap over a non-admin user: %v", err)
	}
	if _, err := e2.svc.checkPassword(ctx, "admin", "s3cret-admin-pw"); err == nil {
		t.Error("the bootstrap password took over an existing user")
	}
}

// TestConcurrentDemotion checks that two administrators demoting each
// other at once cannot leave no administrator.
func TestConcurrentDemotion(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("a1", "a1-password", true)
	e.addUser("a2", "a2-password", true)
	ctx := context.Background()
	errs := make(chan error, 2)
	for _, name := range []string{"a1", "a2"} {
		go func() {
			_, err := e.svc.updateUser(ctx, nil, name, "test", func(u *user) error { u.Admin = false; return nil })
			errs <- err
		}()
	}
	failed := 0
	for range 2 {
		if err := <-errs; err != nil {
			failed++
		}
	}
	if ok, _ := e.svc.HasAdmin(); !ok || failed != 1 {
		t.Errorf("after concurrent demotions: admin exists %v, failures %d (want true, 1)", ok, failed)
	}
}
