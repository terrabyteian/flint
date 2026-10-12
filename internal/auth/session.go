package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
)

// Sessions are the web UI's sign-ins. A session is a random secret that
// the browser keeps in a cookie; like an API token's, only its SHA-256
// hash is stored, so neither the metadata nor a backup of it holds a
// secret that signs anyone in. A session lasts until it expires, after
// auth.sessionTTL, or its user signs out, is deleted, or has a new
// password set. Every request resolves the session's user as it is
// then, so a changed admin flag or group membership applies at once.
//
// Sessions are not accepted on the API or package routes: only the UI
// reads the cookie, and it protects its forms against cross-site
// requests.

// Session methods, recorded with each session.
const (
	// SessionPassword is a session started by signing in with a password.
	SessionPassword = "password"
)

// maxUserSessions bounds a user's sessions: starting one more ends the
// oldest. Expired sessions are removed when the user next signs in.
const maxUserSessions = 64

// Session secrets are "flints_<secret>": 32 random bytes in lowercase
// base32. The prefix tells them apart from API tokens in logs and secret
// scanners.
const (
	sessionStringPrefix = "flints_"
	sessionSecretLen    = 52
)

// session is a stored session. Its key is the hex SHA-256 of its secret.
type session struct {
	ID      string // the hex SHA-256 of the secret
	User    string
	Method  string
	Created time.Time
	Expires time.Time
}

const sessionVersion = 1

func (ss *session) encode() []byte {
	b := []byte{sessionVersion}
	b = appendBytes(b, []byte(ss.User))
	b = appendBytes(b, []byte(ss.Method))
	b = binary.AppendVarint(b, ss.Created.Unix())
	return binary.AppendVarint(b, ss.Expires.Unix())
}

func decodeSession(id string, b []byte) (*session, error) {
	d := decoder{b: b}
	if v := d.byte(); v != sessionVersion {
		return nil, errVersion(v)
	}
	ss := &session{ID: id, User: string(d.bytes()), Method: string(d.bytes())}
	ss.Created = time.Unix(d.varint(), 0)
	ss.Expires = time.Unix(d.varint(), 0)
	return ss, d.done()
}

// sessionID returns the identifier of a well-formed session secret, the
// hex SHA-256 of the whole secret.
func sessionID(secret string) (string, bool) {
	rest, ok := strings.CutPrefix(secret, sessionStringPrefix)
	if !ok || len(rest) != sessionSecretLen {
		return "", false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return "", false
		}
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:]), true
}

// SignIn verifies a user's password and starts a web UI session for the
// user. It returns the session's secret, for the browser's cookie and
// the only time it is available, and when the session expires. It
// returns ErrInvalidCredentials if the user does not exist, has no
// password, or the password is wrong; an API token is not accepted in
// place of the password.
func (s *Service) SignIn(ctx context.Context, name, password string) (secret string, expires time.Time, err error) {
	if _, err := s.checkPassword(ctx, name, password); err != nil {
		return "", time.Time{}, err
	}
	return s.StartSession(ctx, name, SessionPassword)
}

// StartSession starts a web UI session for user name, whom the caller
// has authenticated, as with SessionPassword or an OpenID Connect sign-in;
// method names how, such as "oidc", for the audit log. It returns the
// session's secret and when the session expires, or ErrInvalidCredentials
// if the user does not exist.
func (s *Service) StartSession(ctx context.Context, name, method string) (secret string, expires time.Time, err error) {
	var sb [32]byte
	rand.Read(sb[:])
	secret = sessionStringPrefix + b32.EncodeToString(sb[:])
	id, _ := sessionID(secret)
	now := s.now().Truncate(time.Second)
	ss := &session{ID: id, User: name, Method: method, Created: now, Expires: now.Add(s.sessionTTL)}

	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.store.View()
	defer v.Release()
	_, ver, err := readUser(v, name)
	if errors.Is(err, errNoSuchUser) {
		return "", time.Time{}, ErrInvalidCredentials
	}
	if err != nil {
		return "", time.Time{}, err
	}
	b := new(meta.Batch)
	b.Require(userKey(name), ver)
	// Remove the user's expired sessions, and the oldest beyond the
	// bound, counting the new one.
	live, err := userSessions(v, name)
	if err != nil {
		return "", time.Time{}, err
	}
	live = slices.DeleteFunc(live, func(o *session) bool {
		if !now.Before(o.Expires) {
			deleteSession(b, o)
			return true
		}
		return false
	})
	slices.SortFunc(live, func(a, b *session) int { return a.Created.Compare(b.Created) })
	for len(live) >= maxUserSessions {
		deleteSession(b, live[0])
		live = live[1:]
	}
	b.Require(sessionKey(id), 0)
	b.Put(sessionKey(id), ss.encode())
	b.Put(userSessionKey(name, id), nil)
	if err := s.commit(ctx, b, &Principal{User: name}, "auth.session.create", "session of user "+name+" ("+method+")"); err != nil {
		return "", time.Time{}, err
	}
	return secret, ss.Expires, nil
}

// SessionPrincipal returns the principal a web UI session's secret
// stands for: its user as the user is now. It returns
// ErrInvalidCredentials if the secret is malformed or unknown, the
// session has expired or ended, or its user no longer exists.
func (s *Service) SessionPrincipal(secret string) (*Principal, error) {
	id, ok := sessionID(secret)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	v := s.store.View()
	defer v.Release()
	rec, ok := v.Get(sessionKey(id))
	if !ok {
		return nil, ErrInvalidCredentials
	}
	ss, err := decodeSession(id, rec.Value)
	if err != nil {
		return nil, err
	}
	if !s.now().Before(ss.Expires) {
		return nil, ErrInvalidCredentials
	}
	u, _, err := readUser(v, ss.User)
	if errors.Is(err, errNoSuchUser) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	p := userPrincipal(u)
	p.SessionID = id
	p.SessionExpires = ss.Expires
	return p, nil
}

// EndSession ends the web UI session whose secret is secret, as signing
// out does. Ending an unknown session is not an error.
func (s *Service) EndSession(ctx context.Context, secret string) error {
	id, ok := sessionID(secret)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.store.View()
	defer v.Release()
	rec, ok := v.Get(sessionKey(id))
	if !ok {
		return nil
	}
	ss, err := decodeSession(id, rec.Value)
	if err != nil {
		return err
	}
	b := new(meta.Batch)
	b.Require(sessionKey(id), rec.Version)
	deleteSession(b, ss)
	err = s.commit(ctx, b, &Principal{User: ss.User}, "auth.session.delete", "session of user "+ss.User)
	if errors.Is(err, meta.ErrConflict) {
		return nil // ended meanwhile
	}
	return err
}

// userSessions returns a user's sessions.
func userSessions(v meta.View, user string) ([]*session, error) {
	var out []*session
	var err error
	prefix := []byte(userSessionPrefix + user + "\x00")
	v.Scan(prefix, nil, func(key []byte, _ meta.Record) bool {
		id := string(key[len(prefix):])
		rec, ok := v.Get(sessionKey(id))
		if !ok {
			out = append(out, &session{ID: id, User: user}) // a dangling index entry
			return true
		}
		var ss *session
		if ss, err = decodeSession(id, rec.Value); err != nil {
			return false
		}
		out = append(out, ss)
		return true
	})
	return out, err
}

func deleteSession(b *meta.Batch, ss *session) {
	b.Delete(sessionKey(ss.ID))
	b.Delete(userSessionKey(ss.User, ss.ID))
}

// endUserSessions adds to b the deletion of every session of user but
// keep, which may be "".
func endUserSessions(v meta.View, b *meta.Batch, user, keep string) error {
	sessions, err := userSessions(v, user)
	for _, ss := range sessions {
		if ss.ID != keep {
			deleteSession(b, ss)
		}
	}
	return err
}
