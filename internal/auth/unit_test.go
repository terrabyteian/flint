package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/repo"
)

func TestPasswordHash(t *testing.T) {
	h1, err := hashPassword("correct horse", testIterations)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := hashPassword("correct horse", testIterations)
	if bytes.Equal(h1, h2) {
		t.Error("two hashes of one password are equal; the salt is not random")
	}
	if bytes.Contains(h1, []byte("correct horse")) {
		t.Error("the hash contains the password")
	}
	for _, tt := range []struct {
		pw   string
		want bool
	}{{"correct horse", true}, {"correct horsE", false}, {"", false}, {"correct horse ", false}} {
		ok, err := verifyPassword(tt.pw, h1)
		if err != nil || ok != tt.want {
			t.Errorf("verifyPassword(%q) = %v, %v; want %v", tt.pw, ok, err, tt.want)
		}
	}

	// The iteration count is stored with the hash, so a hash made with a
	// different count still verifies.
	h3, _ := hashPassword("pw-other-count", 2*testIterations)
	if ok, err := verifyPassword("pw-other-count", h3); !ok || err != nil {
		t.Errorf("hash with another iteration count: %v, %v", ok, err)
	}
	d := decoder{b: h3}
	if d.byte() != hashAlgPBKDF2SHA256 || d.uvarint() != 2*testIterations {
		t.Error("the hash does not record its algorithm and iteration count")
	}
	if salt := d.bytes(); len(salt) != saltLen {
		t.Errorf("salt length %d", len(salt))
	}

	for _, bad := range [][]byte{nil, {9}, h1[:len(h1)-1], append(bytes.Clone(h1), 0), {hashAlgPBKDF2SHA256, 0, 0, 0}} {
		if _, err := verifyPassword("x", bad); err == nil {
			t.Errorf("verifyPassword with corrupt hash %x: no error", bad)
		}
	}
}

func TestDefaultIterations(t *testing.T) {
	if DefaultPasswordIterations < 600_000 {
		t.Errorf("DefaultPasswordIterations = %d, want at least 600000", DefaultPasswordIterations)
	}
}

func TestCheckPassword(t *testing.T) {
	if checkPassword("1234567") == nil || checkPassword(strings.Repeat("a", MaxPasswordLen+1)) == nil {
		t.Error("an out-of-range password was accepted")
	}
	if err := checkPassword("12345678"); err != nil {
		t.Error(err)
	}
}

func TestVerifiedCache(t *testing.T) {
	c := newVerifiedCache(time.Minute, 3)
	now := time.Unix(1000, 0)
	id := c.id("alice", []byte("hash1"), "pw")
	if c.has(id, now) {
		t.Fatal("empty cache has an entry")
	}
	c.add(id, now)
	if !c.has(id, now.Add(59*time.Second)) {
		t.Error("entry missing before its expiry")
	}
	if c.has(id, now.Add(time.Minute)) {
		t.Error("entry present after its expiry")
	}
	// Another stored hash (a changed password), user, or password is another entry.
	for _, other := range [][32]byte{c.id("alice", []byte("hash2"), "pw"), c.id("bob", []byte("hash1"), "pw"),
		c.id("alice", []byte("hash1"), "pw2"), c.id("alic", []byte("ehash1"), "pw")} {
		if other == id {
			t.Error("distinct credentials share a cache id")
		}
	}
	// The cache stays bounded.
	for i := range 10 {
		c.add(c.id("u", nil, string(rune('a'+i))), now)
	}
	if len(c.entries) > 3 {
		t.Errorf("cache holds %d entries, max 3", len(c.entries))
	}
}

func TestRecordRoundTrip(t *testing.T) {
	u := &user{Name: "alice", Admin: true, Created: time.Unix(1700000000, 0), Password: []byte{1, 2, 3}, Groups: []string{"ci", "dev"}}
	got, err := decodeUser("alice", u.encode())
	if err != nil || !reflect.DeepEqual(got, u) {
		t.Errorf("user round trip = %+v, %v; want %+v", got, err, u)
	}
	empty := &user{Name: "x", Created: time.Unix(0, 0), Password: []byte{}}
	if got, err := decodeUser("x", empty.encode()); err != nil || got.Admin || len(got.Password) != 0 || got.Groups != nil {
		t.Errorf("empty user round trip = %+v, %v", got, err)
	}

	tok := &token{ID: "id", Owner: "alice", Name: "ci", Hash: bytes.Repeat([]byte{7}, 32), Created: time.Unix(1700000000, 0),
		Expires: time.Unix(1800000000, 0), Admin: true,
		Scopes: []Scope{{Repositories: []string{"a", "b-*"}, Role: RoleWrite}, {Repositories: []string{"*"}, Role: RoleRead}}}
	gt, err := decodeToken("id", tok.encode())
	if err != nil || !reflect.DeepEqual(gt, tok) {
		t.Errorf("token round trip = %+v, %v; want %+v", gt, err, tok)
	}
	never := &token{ID: "n", Owner: "o", Hash: []byte{}, Name: "", Created: time.Unix(5, 0)}
	if gt, err := decodeToken("n", never.encode()); err != nil || !gt.Expires.IsZero() {
		t.Errorf("non-expiring token round trip = %+v, %v", gt, err)
	}

	enc := u.encode()
	for i := range len(enc) {
		if _, err := decodeUser("alice", enc[:i]); err == nil {
			t.Errorf("truncated user record of %d bytes decoded", i)
		}
	}
	if _, err := decodeUser("alice", append(bytes.Clone(enc), 0)); err == nil {
		t.Error("user record with trailing bytes decoded")
	}
	bad := bytes.Clone(enc)
	bad[0] = 99
	if _, err := decodeUser("alice", bad); err == nil || !strings.Contains(err.Error(), "version 99") {
		t.Errorf("unknown version: %v", err)
	}
	tenc := tok.encode()
	for i := range len(tenc) {
		if _, err := decodeToken("id", tenc[:i]); err == nil {
			t.Errorf("truncated token record of %d bytes decoded", i)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"team-a", "team-a", true},
		{"team-a", "team-ab", false},
		{"team-a-*", "team-a-x", true},
		{"team-a-*", "team-a-", true},
		{"team-a-*", "team-a", false},
		{"team-a-*", "team-b-x", false},
		{"*", "anything", true},
		{"*", "", true},
		{"*-prod", "web-prod", true},
		{"*-prod", "web-prod-2", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "acb", false},
		{"a**", "a", true},
		{"*a*a*a*a*b", strings.Repeat("a", 60), false},
	}
	for _, tt := range tests {
		if got := repo.Match(tt.pattern, tt.name); got != tt.want {
			t.Errorf("repo.Match(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func TestRoles(t *testing.T) {
	if !(RoleNone < RoleRead && RoleRead < RoleWrite && RoleWrite < RoleDelete && RoleDelete < RoleAdmin) {
		t.Error("roles are not ordered read < write < delete < admin")
	}
	for _, name := range []string{"read", "write", "delete", "admin"} {
		r, ok := ParseRole(name)
		if !ok || r.String() != name {
			t.Errorf("ParseRole(%q) = %v, %v", name, r, ok)
		}
	}
	if _, ok := ParseRole("owner"); ok {
		t.Error("ParseRole accepted an unknown role")
	}
	for action, want := range map[string]Role{"pull": RoleRead, "push": RoleWrite, "delete": RoleDelete} {
		if got, ok := actionRole(action); !ok || got != want {
			t.Errorf("actionRole(%q) = %v", action, got)
		}
	}
	if _, ok := actionRole("*"); ok {
		t.Error("actionRole accepted *")
	}
}

func TestPolicyRole(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicy(cfg)
	alice := &Principal{User: "alice"}
	bob := &Principal{User: "bob", Groups: []string{"ci"}}
	carol := &Principal{User: "carol", Groups: []string{"ci"}}
	root := &Principal{User: "root", userAdmin: true, Admin: true}
	nobody := &Principal{User: "nobody"}
	tests := []struct {
		p    *Principal
		repo string
		want Role
	}{
		{anonymous, "docker-local", RoleNone},
		{anonymous, "public", RoleRead},
		{nobody, "public", RoleRead},
		{nobody, "docker-local", RoleNone},
		{alice, "team-a-web", RoleDelete},
		{alice, "team-a", RoleNone},
		{alice, "docker-local", RoleNone},
		{carol, "docker-local", RoleWrite}, // through the ci group
		{carol, "public", RoleRead},
		{bob, "docker-local", RoleWrite}, // the higher of a user grant (read) and a group grant (write)
		{root, "anything", RoleAdmin},
		// A token caps its owner's role.
		{&Principal{User: "carol", Groups: []string{"ci"}, TokenID: "t", scopes: []Scope{{[]string{"docker-*"}, RoleRead}}}, "docker-local", RoleRead},
		{&Principal{User: "carol", Groups: []string{"ci"}, TokenID: "t", scopes: []Scope{{[]string{"*"}, RoleAdmin}}}, "docker-local", RoleWrite},
		{&Principal{User: "carol", Groups: []string{"ci"}, TokenID: "t", scopes: []Scope{{[]string{"other"}, RoleAdmin}}}, "docker-local", RoleNone},
		// ... but never below what anonymous clients get.
		{&Principal{User: "carol", TokenID: "t", scopes: []Scope{{[]string{"other"}, RoleAdmin}}}, "public", RoleRead},
		{&Principal{User: "root", userAdmin: true, TokenID: "t", scopes: []Scope{{[]string{"team-*"}, RoleWrite}}}, "team-x", RoleWrite},
		{&Principal{User: "root", userAdmin: true, TokenID: "t", scopes: []Scope{{[]string{"team-*"}, RoleWrite}}}, "prod", RoleNone},
	}
	for _, tt := range tests {
		if got := p.role(tt.p, tt.repo); got != tt.want {
			t.Errorf("role(%+v, %q) = %v, want %v", tt.p, tt.repo, got, tt.want)
		}
	}
	if repoOf("docker-local/team/app") != "docker-local" || repoOf("x") != "x" {
		t.Error("repoOf does not return the first path component")
	}
}

func testSigner(t *testing.T) *signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newSigner(key)
}

func TestJWT(t *testing.T) {
	s := testSigner(t)
	now := time.Unix(1_800_000_000, 0)
	c := &claims{Issuer: Issuer, Subject: "alice", Audience: Issuer, Expiry: now.Add(5 * time.Minute).Unix(),
		NotBefore: now.Unix(), IssuedAt: now.Unix(), ID: "j1",
		Access: []access{{Type: "repository", Name: "docker-local/app", Actions: []string{"pull", "push"}}}}
	tok, err := s.sign(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.verify(tok, Issuer, Issuer, now)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("verify = %+v, %v; want %+v", got, err, c)
	}
	h, _, _ := strings.Cut(tok, ".")
	var hdr map[string]string
	if err := decodeSegment(h, &hdr); err != nil || hdr["alg"] != "EdDSA" || hdr["typ"] != "JWT" || hdr["kid"] != s.kid {
		t.Errorf("header = %v, %v", hdr, err)
	}

	if _, err := s.verify(tok, Issuer, Issuer, now.Add(5*time.Minute)); err == nil {
		t.Error("a token verified at its expiry time")
	}
	if _, err := s.verify(tok, Issuer, Issuer, now.Add(5*time.Minute-time.Second)); err != nil {
		t.Errorf("a token failed just before its expiry: %v", err)
	}
	if _, err := s.verify(tok, Issuer, Issuer, now.Add(-2*clockLeeway)); err == nil {
		t.Error("a token verified before it was issued, beyond the leeway")
	}
	if _, err := s.verify(tok, Issuer, Issuer, now.Add(-clockLeeway/2)); err != nil {
		t.Errorf("a token failed within the clock leeway: %v", err)
	}
	if _, err := s.verify(tok, Issuer, "other-service", now); err == nil {
		t.Error("a token verified for another audience")
	}
	if _, err := s.verify(tok, "other", Issuer, now); err == nil {
		t.Error("a token verified for another issuer")
	}
	if _, err := testSigner(t).verify(tok, Issuer, Issuer, now); err == nil {
		t.Error("a token verified with another key")
	}

	parts := strings.Split(tok, ".")
	forge := func(header, payload string) string {
		return b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload)) + "." + parts[2]
	}
	payload, _ := json.Marshal(c)
	elevated := strings.Replace(string(payload), `"pull","push"`, `"pull","push","delete"`, 1)
	hdrJSON, _ := b64.DecodeString(parts[0])
	for name, bad := range map[string]string{
		"tampered payload":    parts[0] + "." + b64.EncodeToString([]byte(elevated)) + "." + parts[2],
		"alg none":            forge(`{"alg":"none","typ":"JWT"}`, string(payload)),
		"alg none unsigned":   b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + ".",
		"alg HS256":           forge(`{"alg":"HS256","typ":"JWT","kid":"`+s.kid+`"}`, string(payload)),
		"padded segment":      parts[0] + "=." + parts[1] + "." + parts[2],
		"two parts":           parts[0] + "." + parts[1],
		"four parts":          tok + ".x",
		"empty":               "",
		"oversized":           strings.Repeat("a", maxJWTLen+1),
		"standard base64 sig": parts[0] + "." + parts[1] + "." + strings.NewReplacer("-", "+", "_", "/").Replace(parts[2]) + "+",
		"same header altered": forge(string(hdrJSON)+" ", string(payload)),
	} {
		if _, err := s.verify(bad, Issuer, Issuer, now); err == nil {
			t.Errorf("%s: verified", name)
		}
	}

	// A token signed by this key but with another kid or algorithm in its
	// header, or with unknown claims, is refused.
	signRaw := func(header, payload string) string {
		msg := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
		return msg + "." + b64.EncodeToString(ed25519.Sign(s.key, []byte(msg)))
	}
	if _, err := s.verify(signRaw(string(hdrJSON), string(payload)), Issuer, Issuer, now); err != nil {
		t.Fatalf("re-signed original: %v", err)
	}
	for name, bad := range map[string]string{
		"wrong kid":     signRaw(`{"alg":"EdDSA","typ":"JWT","kid":"other"}`, string(payload)),
		"wrong alg":     signRaw(`{"alg":"ES256","typ":"JWT","kid":"`+s.kid+`"}`, string(payload)),
		"wrong typ":     signRaw(`{"alg":"EdDSA","typ":"JWE","kid":"`+s.kid+`"}`, string(payload)),
		"extra header":  signRaw(`{"alg":"EdDSA","kid":"`+s.kid+`","crit":["x"]}`, string(payload)),
		"unknown claim": signRaw(string(hdrJSON), strings.Replace(string(payload), `{`, `{"admin":true,`, 1)),
		"no exp":        signRaw(string(hdrJSON), strings.Replace(string(payload), `"exp":`, `"nope":`, 1)),
		"trailing data": signRaw(string(hdrJSON), string(payload)+"{}"),
	} {
		if _, err := s.verify(bad, Issuer, Issuer, now); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestClaimsAllows(t *testing.T) {
	c := &claims{Access: []access{
		{Type: "repository", Name: "docker-local/app", Actions: []string{"pull", "push"}},
		{Type: "registry", Name: "catalog", Actions: []string{"pull"}},
	}}
	tests := []struct {
		repo, action string
		want         bool
	}{
		{"docker-local/app", "pull", true},
		{"docker-local/app", "push", true},
		{"docker-local/app", "delete", false},
		{"docker-local/other", "pull", false},
		{"docker-local", "pull", true}, // the flint repository the path is in
		{"docker", "pull", false},
		{"catalog", "pull", false}, // another resource type
	}
	for _, tt := range tests {
		if got := c.allows(tt.repo, tt.action); got != tt.want {
			t.Errorf("allows(%q, %q) = %v, want %v", tt.repo, tt.action, got, tt.want)
		}
	}
}

func TestSigningKeyPersists(t *testing.T) {
	m := fsys.NewMem()
	if err := m.MkdirAll("/data", 0o755); err != nil || m.SyncDir("/") != nil {
		t.Fatal("creating the data directory")
	}
	k1, created, err := loadOrCreateKey(m, "/data/auth")
	if err != nil || !created {
		t.Fatalf("first load: created %v, %v", created, err)
	}
	info, err := m.Stat("/data/auth/" + keyFileName)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, %v; want mode 0600", info, err)
	}
	// The key is durable: it survives a crash right after creation.
	m2 := m.Restart(nil)
	k2, created, err := loadOrCreateKey(m2, "/data/auth")
	if err != nil || created || !k1.Equal(k2) {
		t.Fatalf("after a crash: created %v, %v, same key %v", created, err, k1.Equal(k2))
	}

	f, _ := m2.OpenFile("/data/auth/"+keyFileName, os.O_WRONLY|os.O_TRUNC, 0o600)
	f.Write([]byte("not a key"))
	f.Close()
	if _, _, err := loadOrCreateKey(m2, "/data/auth"); err == nil || !strings.Contains(err.Error(), keyFileName) {
		t.Errorf("corrupt key: err = %v, want an error naming the file", err)
	}
}

func TestParseScope(t *testing.T) {
	tests := []struct {
		in      string
		typ     string
		name    string
		actions []string
		ok      bool
	}{
		{"repository:docker-local/app:pull,push", "repository", "docker-local/app", []string{"pull", "push"}, true},
		{"repository:a:*", "repository", "a", []string{"pull", "push", "delete"}, true},
		{"repository:a:", "repository", "a", nil, true},
		{"registry:catalog:*", "registry", "catalog", []string{"pull", "push", "delete"}, true},
		{"repository:A:pull", "", "", nil, false},
		{"repository:a", "", "", nil, false},
		{"repository:host:5000/a:pull", "", "", nil, false},
		{"repository::pull", "", "", nil, false},
	}
	for _, tt := range tests {
		typ, name, actions, ok := parseScope(tt.in)
		if ok != tt.ok || typ != tt.typ || name != tt.name || !reflect.DeepEqual(actions, tt.actions) {
			t.Errorf("parseScope(%q) = %q, %q, %q, %v", tt.in, typ, name, actions, ok)
		}
	}
}

func TestValidRepoPath(t *testing.T) {
	for _, s := range []string{"a", "docker-local/team/app", "a.b_c__d---e/f", "0/1", "a__b"} {
		if !validRepoPath(s) {
			t.Errorf("validRepoPath(%q) = false", s)
		}
	}
	for _, s := range []string{"", "A", "a/", "/a", "a//b", "-a", "a-", "a___b", "a._b", "a..b", "a_", "a b", "a:b", strings.Repeat("a", 256)} {
		if validRepoPath(s) {
			t.Errorf("validRepoPath(%q) = true", s)
		}
	}
}

func TestTokenString(t *testing.T) {
	id, secret := newTokenString()
	if got, ok := parseTokenString(secret); !ok || got != id {
		t.Fatalf("parseTokenString(%q) = %q, %v; want %q", secret, got, ok, id)
	}
	if !strings.HasPrefix(secret, "flint_") || len(secret) != len("flint_")+tokenIDLen+1+tokenSecretLen {
		t.Errorf("token string %q has the wrong form", secret)
	}
	_, other := newTokenString()
	if other == secret {
		t.Error("two token strings are equal")
	}
	for _, bad := range []string{"", "flint_", secret[:len(secret)-1], secret + "a", strings.ToUpper(secret),
		strings.Replace(secret, "_", "-", 2), "glint_" + secret[6:], secret[:20] + "1" + secret[21:]} {
		if _, ok := parseTokenString(bad); ok {
			t.Errorf("parseTokenString(%q) accepted", bad)
		}
	}
}
