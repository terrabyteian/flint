package auth

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/terrabyteian/flint/internal/gc"
)

// Metadata keys. The auth package owns the "auth\x00" namespace.
const (
	userPrefix      = "auth\x00user\x00"      // + name: user record
	tokenPrefix     = "auth\x00token\x00"     // + id: token record
	userTokenPrefix = "auth\x00usertoken\x00" // + user + "\x00" + id: empty, indexes a user's tokens
	// + id: sign-in session record
	sessionPrefix = "auth\x00session\x00"
	// + user + "\x00" + id: empty, indexes a user's sessions
	userSessionPrefix = "auth\x00usersession\x00"
	// + issuer + "\x00" + subject: the name of the user an OIDC identity signs in as
	oidcPrefix = "auth\x00oidc\x00"
)

// GCMarker returns the auth marker for the garbage collector: users and
// tokens reference no blobs.
func GCMarker() gc.Marker {
	return gc.Marker{
		userPrefix: nil, tokenPrefix: nil, userTokenPrefix: nil,
		sessionPrefix: nil, userSessionPrefix: nil, oidcPrefix: nil,
	}
}

func userKey(name string) []byte { return []byte(userPrefix + name) }
func tokenKey(id string) []byte  { return []byte(tokenPrefix + id) }
func userTokenKey(user, id string) []byte {
	return []byte(userTokenPrefix + user + "\x00" + id)
}
func sessionKey(id string) []byte { return []byte(sessionPrefix + id) }
func userSessionKey(user, id string) []byte {
	return []byte(userSessionPrefix + user + "\x00" + id)
}
func oidcKey(issuer, subject string) []byte {
	return []byte(oidcPrefix + issuer + "\x00" + subject)
}

// Record schema versions: the first byte of each value. A user record
// is version 1 for a local user and version 2, which adds the OIDC
// identity, for a user who signs in through an OIDC provider.
const (
	userVersion     = 1
	oidcUserVersion = 2
	tokenVersion    = 1
	sessionVersion  = 1
)

const flagAdmin = 1 << 0

// user is a stored user: a local user, or one who signs in through an
// OIDC provider.
type user struct {
	Name     string
	Admin    bool
	Created  time.Time
	Password []byte // an encoded password hash; empty means password login is disabled
	Groups   []string
	OIDC     *oidcIdentity // nil for a local user
}

// oidcIdentity is the OIDC identity a user signs in with.
type oidcIdentity struct {
	Provider string // the configured provider's name when the user was created
	Issuer   string
	Subject  string
}

func (u *user) encode() []byte {
	b := []byte{userVersion, 0}
	if u.OIDC != nil {
		b[0] = oidcUserVersion
	}
	if u.Admin {
		b[1] |= flagAdmin
	}
	b = binary.AppendVarint(b, u.Created.Unix())
	b = appendBytes(b, u.Password)
	b = binary.AppendUvarint(b, uint64(len(u.Groups)))
	for _, g := range u.Groups {
		b = appendBytes(b, []byte(g))
	}
	if u.OIDC != nil {
		b = appendBytes(b, []byte(u.OIDC.Provider))
		b = appendBytes(b, []byte(u.OIDC.Issuer))
		b = appendBytes(b, []byte(u.OIDC.Subject))
	}
	return b
}

func decodeUser(name string, b []byte) (*user, error) {
	d := decoder{b: b}
	v := d.byte()
	if v != userVersion && v != oidcUserVersion {
		return nil, errVersion(v)
	}
	u := &user{Name: name}
	u.Admin = d.byte()&flagAdmin != 0
	u.Created = time.Unix(d.varint(), 0)
	u.Password = d.bytes()
	n := d.count()
	for range n {
		u.Groups = append(u.Groups, string(d.bytes()))
	}
	if v == oidcUserVersion {
		u.OIDC = &oidcIdentity{Provider: string(d.bytes()), Issuer: string(d.bytes()), Subject: string(d.bytes())}
	}
	return u, d.done()
}

// token is a stored API token. The secret itself is never stored, only
// its SHA-256 hash.
type token struct {
	ID      string
	Owner   string
	Name    string
	Hash    []byte // SHA-256 of the whole token string
	Created time.Time
	Expires time.Time // zero: never
	Admin   bool      // may use its owner's global admin role
	Scopes  []Scope
}

func (t *token) encode() []byte {
	b := []byte{tokenVersion, 0}
	if t.Admin {
		b[1] |= flagAdmin
	}
	b = appendBytes(b, []byte(t.Owner))
	b = appendBytes(b, []byte(t.Name))
	b = appendBytes(b, t.Hash)
	b = binary.AppendVarint(b, t.Created.Unix())
	var exp int64
	if !t.Expires.IsZero() {
		exp = t.Expires.Unix()
	}
	b = binary.AppendVarint(b, exp)
	b = binary.AppendUvarint(b, uint64(len(t.Scopes)))
	for _, s := range t.Scopes {
		b = append(b, byte(s.Role))
		b = binary.AppendUvarint(b, uint64(len(s.Repositories)))
		for _, p := range s.Repositories {
			b = appendBytes(b, []byte(p))
		}
	}
	return b
}

func decodeToken(id string, b []byte) (*token, error) {
	d := decoder{b: b}
	if v := d.byte(); v != tokenVersion {
		return nil, errVersion(v)
	}
	t := &token{ID: id}
	t.Admin = d.byte()&flagAdmin != 0
	t.Owner = string(d.bytes())
	t.Name = string(d.bytes())
	t.Hash = d.bytes()
	t.Created = time.Unix(d.varint(), 0)
	if exp := d.varint(); exp != 0 {
		t.Expires = time.Unix(exp, 0)
	}
	n := d.count()
	for range n {
		s := Scope{Role: Role(d.byte())}
		m := d.count()
		for range m {
			s.Repositories = append(s.Repositories, string(d.bytes()))
		}
		t.Scopes = append(t.Scopes, s)
	}
	return t, d.done()
}

// session is a stored sign-in session. The secret in the session cookie
// is never stored, only its SHA-256 hash.
type session struct {
	ID      string
	User    string
	Hash    []byte // SHA-256 of the whole cookie value
	Created time.Time
	Expires time.Time
	// Method is how the user signed in: "password", or "oidc:" and the
	// provider's name.
	Method string
}

func (s *session) encode() []byte {
	b := []byte{sessionVersion}
	b = appendBytes(b, []byte(s.User))
	b = appendBytes(b, s.Hash)
	b = binary.AppendVarint(b, s.Created.Unix())
	b = binary.AppendVarint(b, s.Expires.Unix())
	return appendBytes(b, []byte(s.Method))
}

func decodeSession(id string, b []byte) (*session, error) {
	d := decoder{b: b}
	if v := d.byte(); v != sessionVersion {
		return nil, errVersion(v)
	}
	s := &session{ID: id}
	s.User = string(d.bytes())
	s.Hash = d.bytes()
	s.Created = time.Unix(d.varint(), 0)
	s.Expires = time.Unix(d.varint(), 0)
	s.Method = string(d.bytes())
	return s, d.done()
}

// expired reports whether the session has expired at now.
func (s *session) expired(now time.Time) bool { return !now.Before(s.Expires) }

// expired reports whether the token has expired at now.
func (t *token) expired(now time.Time) bool {
	return !t.Expires.IsZero() && !now.Before(t.Expires)
}

func appendBytes(dst, s []byte) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

var errTruncated = errors.New("auth: truncated record")

func errVersion(v byte) error {
	return fmt.Errorf("auth: unsupported record version %d", v)
}

// decoder reads a record, remembering the first error.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) fail() {
	if d.err == nil {
		d.err = errTruncated
	}
	d.b = nil
}

func (d *decoder) byte() byte {
	if len(d.b) == 0 {
		d.fail()
		return 0
	}
	c := d.b[0]
	d.b = d.b[1:]
	return c
}

func (d *decoder) uvarint() uint64 {
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.fail()
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) varint() int64 {
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.fail()
		return 0
	}
	d.b = d.b[n:]
	return v
}

// count reads a length that cannot exceed the bytes remaining, so a
// corrupt record cannot make the caller allocate without bound.
func (d *decoder) count() int {
	n := d.uvarint()
	if n > uint64(len(d.b)) {
		d.fail()
		return 0
	}
	return int(n)
}

// bytes reads a length-prefixed byte string. It returns a copy, because
// record values belong to the metadata store.
func (d *decoder) bytes() []byte {
	n := d.count()
	if d.err != nil {
		return nil
	}
	s := bytes.Clone(d.b[:n])
	d.b = d.b[n:]
	return s
}

func (d *decoder) done() error {
	if d.err == nil && len(d.b) != 0 {
		d.err = errors.New("auth: trailing bytes in record")
	}
	return d.err
}
