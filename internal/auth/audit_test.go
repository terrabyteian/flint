package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/terrabyteian/flint/internal/audit"
	"github.com/terrabyteian/flint/internal/meta"
)

// TestAuditHoldsNoSecrets creates users and tokens and changes passwords
// through the admin API, and checks that the audit log records each change
// with its actor while no password, password hash, salt, token secret, or
// token hash reaches the stream.
func TestAuditHoldsNoSecrets(t *testing.T) {
	e := newEnv(t, testConfig)
	l, err := audit.Open(audit.Options{Store: e.store, Dir: "/data/audit", FS: e.fs, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e.addUser("root", "root-password-1", true)
	e.wantStatus(e.api("POST", "/api/v1/users", "root", "root-password-1",
		`{"name": "alice", "password": "alice-password-1"}`, nil), http.StatusCreated, "create alice")
	var tok tokenJSON
	e.wantStatus(e.api("POST", "/api/v1/tokens", "alice", "alice-password-1", `{"name": "ci"}`, &tok),
		http.StatusCreated, "create a token")
	e.wantStatus(e.api("PUT", "/api/v1/users/alice/password", "alice", "alice-password-1",
		`{"password": "alice-password-2"}`, nil), http.StatusNoContent, "change alice's password")
	e.wantStatus(e.api("DELETE", "/api/v1/tokens/"+tok.ID, "alice", tok.Token, "", nil), http.StatusNoContent, "revoke the token")
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	var actions []string
	err = l.Scan(context.Background(), audit.Filter{}, func(r *audit.Record) bool {
		actions = append(actions, r.Actor+" "+r.Action+" "+r.Target)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"(system) auth.user.create user root",
		"root auth.user.create user alice",
		"alice auth.token.create token " + tok.ID + " of user alice",
		"alice auth.user.password user alice",
		"alice (token " + tok.ID + ") auth.token.revoke token " + tok.ID + " of user alice",
	}
	if len(actions) != len(want) {
		t.Fatalf("records:\n%q\nwant\n%q", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Errorf("record %d = %q, want %q", i, actions[i], want[i])
		}
	}

	stream := readTree(t, e, "/data/audit")
	secrets := [][]byte{
		[]byte("root-password-1"), []byte("alice-password-1"), []byte("alice-password-2"),
		[]byte(tok.Token), []byte(tok.Token[len(tokenStringPrefix)+tokenIDLen+1:]),
	}
	sum := sha256.Sum256([]byte(tok.Token))
	secrets = append(secrets, sum[:])
	for _, name := range []string{"root", "alice"} {
		u, err := e.svc.getUser(name)
		if err != nil {
			t.Fatal(err)
		}
		d := decoder{b: u.Password}
		d.byte()
		d.uvarint()
		salt, key := d.bytes(), d.bytes()
		if len(salt) != saltLen || len(key) != keyLen {
			t.Fatalf("cannot decode %s's password hash", name)
		}
		secrets = append(secrets, u.Password, salt, key)
	}
	for _, s := range secrets {
		if bytes.Contains(stream, s) {
			t.Errorf("the audit stream contains the secret %x", s)
		}
	}
	// The stream does hold what it should: the keys.
	if !bytes.Contains(stream, []byte("auth\x00token\x00"+tok.ID)) {
		t.Error("the audit stream lacks the token's key")
	}
	b, _ := json.Marshal(actions)
	if bytes.Contains(b, []byte("password-")) {
		t.Error("an origin holds a password")
	}
}

// TestAuditBuiltinActorsAreDistinct checks that users named system and
// anonymous are recorded, and selected by the actor filter, apart from
// flint's own work and unauthenticated clients.
func TestAuditBuiltinActorsAreDistinct(t *testing.T) {
	e := newEnv(t, testConfig)
	l, err := audit.Open(audit.Options{Store: e.store, Dir: "/data/audit", FS: e.fs, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e.addUser("root", "root-password-1", true)
	for _, name := range []string{"system", "anonymous"} {
		e.wantStatus(e.api("POST", "/api/v1/users", "root", "root-password-1",
			`{"name": "`+name+`", "password": "`+name+`-password-1"}`, nil), http.StatusCreated, "create "+name)
		e.wantStatus(e.api("PUT", "/api/v1/users/"+name+"/password", name, name+"-password-1",
			`{"password": "`+name+`-password-2"}`, nil), http.StatusNoContent, "change "+name+"'s password")
	}
	var b meta.Batch
	b.Put([]byte("test/anonymous"), []byte("x"))
	b.SetOrigin(meta.Origin{Actor: e.svc.Actor(httptest.NewRequest("GET", "/", nil)), Action: "test.anonymous"})
	if _, err := e.store.Commit(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	scan := func(actor string) []string {
		var out []string
		err := l.Scan(context.Background(), audit.Filter{Actor: actor}, func(r *audit.Record) bool {
			out = append(out, r.Actor+" "+r.Action+" "+r.Target)
			return true
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		actor string
		want  []string
	}{
		{meta.ActorSystem, []string{"(system) auth.user.create user root"}},
		{meta.ActorAnonymous, []string{"(anonymous) test.anonymous "}},
		{"system", []string{"system auth.user.password user system"}},
		{"anonymous", []string{"anonymous auth.user.password user anonymous"}},
	} {
		if got := scan(tc.actor); !slices.Equal(got, tc.want) {
			t.Errorf("actor %q: records %q, want %q", tc.actor, got, tc.want)
		}
	}
}

// readTree returns the contents of every file in dir.
func readTree(t *testing.T, e *env, dir string) []byte {
	t.Helper()
	ents, err := e.fs.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var all []byte
	for _, ent := range ents {
		f, err := e.fs.Open(filepath.Join(dir, ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	if len(all) == 0 {
		t.Fatal("the audit stream is empty")
	}
	return all
}
