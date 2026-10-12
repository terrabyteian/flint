package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// session starts a sign-in session for user and returns its cookie
// value.
func (e *env) session(user string) string {
	e.t.Helper()
	w := httptest.NewRecorder()
	if err := e.svc.startSession(context.Background(), w, httptest.NewRequest("POST", SignInPath, nil), user, "password"); err != nil {
		e.t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	e.t.Fatal("no session cookie")
	return ""
}

// sessionPrincipal resolves a session cookie value, or returns nil.
func (e *env) sessionPrincipal(value string) *Principal {
	e.t.Helper()
	r := httptest.NewRequest("GET", "/ui/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: value})
	p, err := e.svc.SessionPrincipal(r)
	if errors.Is(err, ErrInvalidCredentials) {
		return nil
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

func TestChangePassword(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("alice", "alice-password", false)
	ctx := context.Background()
	current, other := e.session("alice"), e.session("alice")
	p := e.sessionPrincipal(current)

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
	if e.sessionPrincipal(current) == nil {
		t.Error("the changing session ended")
	}
	if e.sessionPrincipal(other) != nil {
		t.Error("another session survived the change")
	}
	if _, err := e.svc.checkPassword(ctx, "alice", "new-password-1"); err != nil {
		t.Errorf("new password: %v", err)
	}

	// An administrator setting the password ends every session.
	root, _ := e.principal("root")
	if err := e.svc.setPassword(ctx, root, "alice", "new-password-2"); err != nil {
		t.Fatal(err)
	}
	if e.sessionPrincipal(current) != nil {
		t.Error("a session survived an administrator's reset")
	}

	// A token cannot change the password.
	tp, err := e.svc.checkAPIToken(e.addToken("alice", false, time.Time{}), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ChangePassword(ctx, tp, "new-password-2", "new-password-3"); !errors.Is(err, errNeedsSignIn) {
		t.Errorf("token principal: got %v", err)
	}
}

func TestAccountTokens(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("alice", "alice-password", false)
	ctx := context.Background()
	p := e.sessionPrincipal(e.session("alice"))

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
	if _, _, err := e.svc.CreateToken(ctx, tp, "more", 0, false, nil); !errors.Is(err, errNeedsSignIn) {
		t.Errorf("token minting a token: got %v", err)
	}
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
	e.clock.Add(time.Second) // tokens list oldest first
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
	rootID, _ := parseTokenString(e.addToken("root", false, time.Time{}))
	if err := e.svc.RevokeToken(ctx, p, rootID); !errors.Is(err, errNoSuchToken) {
		t.Errorf("revoking another user's token: got %v", err)
	}
	rp := e.sessionPrincipal(e.session("root"))
	if err := e.svc.RevokeToken(ctx, rp, info.ID); !errors.Is(err, errNoSuchToken) {
		t.Errorf("administrator revoking alice's token here: got %v", err)
	}
	if err := e.svc.RevokeToken(ctx, p, info.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.checkAPIToken(secret, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("revoked token still works: %v", err)
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
