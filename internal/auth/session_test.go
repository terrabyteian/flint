package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
)

func (e *env) signIn(name, password string) string {
	e.t.Helper()
	secret, _, err := e.svc.SignIn(context.Background(), name, password)
	if err != nil {
		e.t.Fatalf("SignIn %s: %v", name, err)
	}
	return secret
}

// countKeys counts the records under prefix.
func (e *env) countKeys(prefix string) int {
	v := e.store.View()
	defer v.Release()
	n := 0
	v.Scan([]byte(prefix), nil, func([]byte, meta.Record) bool { n++; return true })
	return n
}

func TestSignIn(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("alice", "alice-password", false, "ci")
	e.addUser("nopass", "", false)
	ctx := context.Background()

	for _, c := range []struct{ name, user, pw string }{
		{"wrong password", "alice", "wrong-password"},
		{"unknown user", "mallory", "alice-password"},
		{"no password", "nopass", ""},
	} {
		if _, _, err := e.svc.SignIn(ctx, c.user, c.pw); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: got %v, want ErrInvalidCredentials", c.name, err)
		}
	}
	// An API token is not a password.
	tok := e.addToken("alice", false, time.Time{})
	if _, _, err := e.svc.SignIn(ctx, "alice", tok); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("token as password: got %v", err)
	}

	secret, expires, err := e.svc.SignIn(ctx, "alice", "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, "flints_") {
		t.Errorf("secret %q lacks its prefix", secret)
	}
	if want := e.clock.Now().Add(12 * time.Hour); !expires.Equal(want) {
		t.Errorf("expires %v, want %v", expires, want)
	}
	p, err := e.svc.SessionPrincipal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if p.User != "alice" || p.Admin || p.Password || p.TokenID != "" || p.SessionID == "" ||
		len(p.Groups) != 1 || p.Groups[0] != "ci" || !p.SessionExpires.Equal(expires) {
		t.Errorf("principal %+v", p)
	}
	if e.svc.Role(p, "docker-local") != RoleWrite {
		t.Errorf("role %v, want write through group ci", e.svc.Role(p, "docker-local"))
	}
	// The stored key is the secret's hash, not the secret.
	v := e.store.View()
	v.Scan([]byte(sessionPrefix), nil, func(k []byte, r meta.Record) bool {
		if strings.Contains(string(k), secret) || strings.Contains(string(r.Value), secret) {
			t.Errorf("session record holds the secret")
		}
		return true
	})
	v.Release()

	for _, bad := range []string{"", "flints_", secret + "a", strings.ToUpper(secret), "flint_" + secret[7:],
		"flints_" + strings.Repeat("a", 52)} {
		if _, err := e.svc.SessionPrincipal(bad); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("SessionPrincipal(%q): got %v", bad, err)
		}
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t, `{"dataDir": "/data", "auth": {"sessionTTL": "1h"}}`)
	e.addUser("alice", "alice-password", false)
	secret := e.signIn("alice", "alice-password")
	e.clock.Add(time.Hour - time.Second)
	if _, err := e.svc.SessionPrincipal(secret); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	e.clock.Add(time.Second)
	if _, err := e.svc.SessionPrincipal(secret); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("at expiry: got %v", err)
	}
	// The next sign-in removes the expired session.
	if n := e.countKeys(sessionPrefix); n != 1 {
		t.Fatalf("%d sessions stored, want 1", n)
	}
	e.signIn("alice", "alice-password")
	if n, m := e.countKeys(sessionPrefix), e.countKeys(userSessionPrefix); n != 1 || m != 1 {
		t.Errorf("%d sessions and %d index entries after sign-in, want 1 each", n, m)
	}
}

func TestEndSession(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("alice", "alice-password", false)
	ctx := context.Background()
	first := e.signIn("alice", "alice-password")
	second := e.signIn("alice", "alice-password")
	if err := e.svc.EndSession(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SessionPrincipal(first); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("ended session: got %v", err)
	}
	if _, err := e.svc.SessionPrincipal(second); err != nil {
		t.Errorf("other session: %v", err)
	}
	// Ending it again, or a malformed one, is not an error.
	for _, s := range []string{first, "junk"} {
		if err := e.svc.EndSession(ctx, s); err != nil {
			t.Errorf("EndSession(%q): %v", s, err)
		}
	}
	if n, m := e.countKeys(sessionPrefix), e.countKeys(userSessionPrefix); n != 1 || m != 1 {
		t.Errorf("%d sessions and %d index entries, want 1 each", n, m)
	}
}

func TestSessionsEndWithUser(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("alice", "alice-password", false)
	secret := e.signIn("alice", "alice-password")
	other := e.signIn("root", "root-password")
	root, _ := e.principal("root")
	if err := e.svc.deleteUser(context.Background(), root, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SessionPrincipal(secret); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("deleted user's session: got %v", err)
	}
	if _, err := e.svc.SessionPrincipal(other); err != nil {
		t.Errorf("another user's session: %v", err)
	}
	if n := e.countKeys(userSessionPrefix + "alice\x00"); n != 0 {
		t.Errorf("%d index entries of the deleted user left", n)
	}
	// A user created again with the same name gets none of them back.
	e.addUser("alice", "alice-password", false)
	if _, err := e.svc.SessionPrincipal(secret); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("recreated user: got %v", err)
	}
}

// TestSessionReflectsUser resolves the session's user on every use, so a
// changed admin flag applies at once.
func TestSessionReflectsUser(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("alice", "alice-password", true)
	secret := e.signIn("alice", "alice-password")
	if p, _ := e.svc.SessionPrincipal(secret); !p.Admin {
		t.Fatal("administrator's session is not admin")
	}
	root, _ := e.principal("root")
	if _, err := e.svc.updateUser(context.Background(), root, "alice", "auth.user.update", func(u *user) error {
		u.Admin = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.svc.SessionPrincipal(secret); p.Admin {
		t.Error("demoted user's session is still admin")
	}
}

func TestPasswordChangeEndsSessions(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("alice", "alice-password", false)
	ctx := context.Background()
	current := e.signIn("alice", "alice-password")
	other := e.signIn("alice", "alice-password")
	p, err := e.svc.SessionPrincipal(current)
	if err != nil {
		t.Fatal(err)
	}

	if err := e.svc.ChangePassword(ctx, p, "wrong-password", "new-password-1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current password: got %v", err)
	}
	if err := e.svc.ChangePassword(ctx, p, "alice-password", "short"); err == nil {
		t.Fatal("short password accepted")
	} else if msg, ok := Message(err); !ok || !strings.Contains(msg, "at least") {
		t.Errorf("short password: message %q, %v", msg, ok)
	}
	if err := e.svc.ChangePassword(ctx, p, "alice-password", "new-password-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SessionPrincipal(current); err != nil {
		t.Errorf("the changing session ended: %v", err)
	}
	if _, err := e.svc.SessionPrincipal(other); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("another session survived the change: %v", err)
	}
	if _, _, err := e.svc.SignIn(ctx, "alice", "alice-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("old password still signs in: %v", err)
	}
	e.signIn("alice", "new-password-1")

	// An administrator setting the password ends every session.
	root, _ := e.principal("root")
	if err := e.svc.setPassword(ctx, root, "alice", "new-password-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SessionPrincipal(current); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("session survived an administrator's reset: %v", err)
	}

	// A token cannot change the password.
	tp, err := e.svc.checkAPIToken(e.addToken("alice", false, time.Time{}), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ChangePassword(ctx, tp, "new-password-2", "new-password-3"); !errors.Is(err, errNeedsPassword) {
		t.Errorf("token principal: got %v", err)
	}
}

func TestSessionBound(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("alice", "alice-password", false)
	first := e.signIn("alice", "alice-password")
	e.clock.Add(time.Second)
	second := e.signIn("alice", "alice-password")
	for range maxUserSessions - 1 {
		e.clock.Add(time.Second)
		e.signIn("alice", "alice-password")
	}
	if _, err := e.svc.SessionPrincipal(first); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("oldest session survived: %v", err)
	}
	if _, err := e.svc.SessionPrincipal(second); err != nil {
		t.Errorf("second session ended: %v", err)
	}
	if n := e.countKeys(sessionPrefix); n != maxUserSessions {
		t.Errorf("%d sessions, want %d", n, maxUserSessions)
	}
}

func TestStartSession(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("sso-user", "", false)
	secret, _, err := e.svc.StartSession(context.Background(), "sso-user", "oidc")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := e.svc.SessionPrincipal(secret); err != nil || p.User != "sso-user" {
		t.Errorf("principal %+v, %v", p, err)
	}
	if _, _, err := e.svc.StartSession(context.Background(), "nobody", "oidc"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user: got %v", err)
	}
}

func TestAccountTokens(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("alice", "alice-password", false)
	ctx := context.Background()
	p, err := e.svc.SessionPrincipal(e.signIn("alice", "alice-password"))
	if err != nil {
		t.Fatal(err)
	}

	scopes := []Scope{{Repositories: []string{"docker-local"}, Role: RoleRead}}
	info, secret, err := e.svc.CreateToken(ctx, p, "ci", time.Hour, false, scopes)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "ci" || info.Owner != "alice" || !info.Expires.Equal(e.clock.Now().Add(time.Hour)) || info.Admin ||
		len(info.Scopes) != 1 {
		t.Errorf("token %+v", info)
	}
	tp, err := e.svc.checkAPIToken(secret, "")
	if err != nil || tp.User != "alice" {
		t.Fatalf("new token: %+v, %v", tp, err)
	}
	// A token cannot mint another.
	if _, _, err := e.svc.CreateToken(ctx, tp, "more", 0, false, nil); !errors.Is(err, errNeedsPassword) {
		t.Errorf("token minting a token: got %v", err)
	}
	// Only administrators get admin tokens.
	if _, _, err := e.svc.CreateToken(ctx, p, "admin", 0, true, nil); err == nil {
		t.Error("non-administrator created an admin token")
	} else if _, ok := Message(err); !ok {
		t.Errorf("admin token refusal has no message: %v", err)
	}
	for _, c := range []struct {
		name   string
		ttl    time.Duration
		scopes []Scope
	}{
		{" ", 0, nil},
		{"past", -time.Hour, nil},
		{"empty scopes", 0, []Scope{}},
		{"bad pattern", 0, []Scope{{Repositories: []string{"Bad Name"}, Role: RoleRead}}},
		{"no role", 0, []Scope{{Repositories: []string{"x"}}}},
	} {
		if _, _, err := e.svc.CreateToken(ctx, p, c.name, c.ttl, false, c.scopes); err == nil {
			t.Errorf("%q: created", c.name)
		} else if _, ok := Message(err); !ok {
			t.Errorf("%q: no message for %v", c.name, err)
		}
	}
	all, _, err := e.svc.CreateToken(ctx, p, "all", 0, false, nil)
	if err != nil || all.Scopes[0].Role != RoleAdmin || !all.Expires.IsZero() {
		t.Fatalf("unscoped token: %+v, %v", all, err)
	}

	list, err := e.svc.Tokens(p)
	if err != nil || len(list) != 2 || list[0].Name != "ci" || list[1].Name != "all" {
		t.Fatalf("Tokens: %+v, %v", list, err)
	}

	// Revoking: an administrator revokes only their own here, and so
	// does everyone.
	rootToken := e.addToken("root", false, time.Time{})
	rootID, _ := parseTokenString(rootToken)
	if err := e.svc.RevokeToken(ctx, p, rootID); !errors.Is(err, errNoSuchToken) {
		t.Errorf("revoking another user's token: got %v", err)
	}
	rp, _ := e.svc.SessionPrincipal(e.signIn("root", "root-password"))
	if err := e.svc.RevokeToken(ctx, rp, info.ID); !errors.Is(err, errNoSuchToken) {
		t.Errorf("administrator revoking alice's token here: got %v", err)
	}
	if err := e.svc.RevokeToken(ctx, p, info.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.checkAPIToken(secret, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("revoked token still works: %v", err)
	}
	if list, _ := e.svc.Tokens(p); len(list) != 1 {
		t.Errorf("%d tokens after revoking, want 1", len(list))
	}
}

func TestHasPassword(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("alice", "alice-password", false)
	e.addUser("sso", "", false)
	for name, want := range map[string]bool{"alice": true, "sso": false, "nobody": false} {
		if got, err := e.svc.HasPassword(name); err != nil || got != want {
			t.Errorf("HasPassword(%s) = %v, %v", name, got, err)
		}
	}
}
