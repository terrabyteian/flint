package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/server"
)

// A sign-in session is how a browser stays signed in, after the user
// signed in on the sign-in page with a password or through an OIDC
// provider. Its cookie holds a random secret, of which only the SHA-256
// hash is stored, and it lasts auth.sessionTTL. Sessions authenticate the
// admin API and the UI, never the registry or package endpoints, whose
// clients use API tokens. A session counts as having signed in, as a
// password does: it may create API tokens, so a user who signs in only
// through an OIDC provider can make tokens for package clients.
//
// The cookie is HttpOnly and SameSite=Lax, and a request authenticated
// by one that changes anything must not come from another origin, which
// browsers say in the Sec-Fetch-Site and Origin headers, so another site
// cannot act with a signed-in user's session.

// SessionCookie is the name of the session cookie.
const SessionCookie = "flint_session"

// maxSessionsPerUser bounds the sessions one user keeps; signing in once
// more ends the oldest.
const maxSessionsPerUser = 50

// Session cookie values are "<id>_<secret>", in the form of an API token
// string without its prefix.
func parseSessionCookie(v string) (string, bool) {
	return parseTokenString(tokenStringPrefix + v)
}

// errNoSession means the request carries no session cookie.
var errNoSession = errors.New("no session")

// checkSession authenticates a request's session cookie.
func (s *Service) checkSession(r *http.Request) (*Principal, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return nil, errNoSession
	}
	id, ok := parseSessionCookie(c.Value)
	if !ok {
		s.attempts.With("session", "failure").Inc()
		return nil, ErrInvalidCredentials
	}
	sess, err := s.getSession(id)
	if errors.Is(err, errNoSuchSession) {
		s.attempts.With("session", "failure").Inc()
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(c.Value))
	if subtle.ConstantTimeCompare(sum[:], sess.Hash) != 1 || sess.expired(s.now()) {
		s.attempts.With("session", "failure").Inc()
		return nil, ErrInvalidCredentials
	}
	u, err := s.getUser(sess.User)
	if errors.Is(err, errNoSuchUser) {
		s.attempts.With("session", "failure").Inc()
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	s.attempts.With("session", "success").Inc()
	p := userPrincipal(u)
	p.SessionID = sess.ID
	return p, nil
}

var errNoSuchSession = errors.New("no such session")

func (s *Service) getSession(id string) (*session, error) {
	v := s.store.View()
	defer v.Release()
	rec, ok := v.Get(sessionKey(id))
	if !ok {
		return nil, errNoSuchSession
	}
	sess, err := decodeSession(id, rec.Value)
	if err != nil {
		return nil, fmt.Errorf("session %s: %w", id, err)
	}
	return sess, nil
}

// SessionPrincipal returns the principal of the request's session
// cookie: nil and no error if the request has none, and
// ErrInvalidCredentials if the session is unknown, expired, or its user
// was deleted. It is for the UI, whose pages authenticate with the
// session; a handler that changes anything must also call
// CheckCrossOrigin.
func (s *Service) SessionPrincipal(r *http.Request) (*Principal, error) {
	p, err := s.checkSession(r)
	if errors.Is(err, errNoSession) {
		return nil, nil
	}
	return p, err
}

// CheckCrossOrigin returns an error if r is a browser request from
// another origin, which a request that is authenticated with a session
// cookie and changes anything must not be. Requests that are not from a
// browser, which send neither Sec-Fetch-Site nor Origin, pass.
func (s *Service) CheckCrossOrigin(r *http.Request) error {
	return s.crossOrigin.Check(r)
}

// startSession creates a session for user, ending the user's expired
// sessions and, beyond maxSessionsPerUser, the oldest, and sets its
// cookie on w. method is how the user signed in.
func (s *Service) startSession(ctx context.Context, w http.ResponseWriter, r *http.Request, name, method string) error {
	id, secret := newTokenString()
	value := strings.TrimPrefix(secret, tokenStringPrefix)
	sum := sha256.Sum256([]byte(value))
	now := s.now()
	sess := &session{
		ID: id, User: name, Hash: sum[:], Method: method,
		Created: now.Truncate(time.Second), Expires: now.Add(s.sessionTTL).Truncate(time.Second),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.store.View()
	defer v.Release()
	_, ver, err := readUser(v, name)
	if err != nil {
		return err
	}
	b := new(meta.Batch)
	b.Require(userKey(name), ver)
	b.Require(sessionKey(id), 0)
	b.Put(sessionKey(id), sess.encode())
	b.Put(userSessionKey(name, id), nil)
	var live []*session
	prefix := []byte(userSessionPrefix + name + "\x00")
	v.Scan(prefix, nil, func(key []byte, _ meta.Record) bool {
		oid := string(key[len(prefix):])
		rec, ok := v.Get(sessionKey(oid))
		var old *session
		if ok {
			old, err = decodeSession(oid, rec.Value)
		}
		switch {
		case err != nil:
			return false
		case !ok || old.expired(now):
			b.Delete(key)
			b.Delete(sessionKey(oid))
		default:
			live = append(live, old)
		}
		return true
	})
	if err != nil {
		return err
	}
	slices.SortStableFunc(live, func(a, b *session) int { return a.Created.Compare(b.Created) })
	for len(live) >= maxSessionsPerUser {
		b.Delete(userSessionKey(name, live[0].ID))
		b.Delete(sessionKey(live[0].ID))
		live = live[1:]
	}
	actor := &Principal{User: name}
	if err := s.commit(ctx, b, actor, "auth.session.create", "session "+id+" of user "+name); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		Expires:  sess.Expires,
		MaxAge:   int(sess.Expires.Sub(now) / time.Second),
		Secure:   secureCookie(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// endSession deletes the request's session, if it has a valid one, and
// clears its cookie.
func (s *Service) endSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: secureCookie(r), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	p, err := s.checkSession(r)
	if errors.Is(err, errNoSession) || errors.Is(err, ErrInvalidCredentials) {
		return nil
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := new(meta.Batch)
	b.Delete(sessionKey(p.SessionID))
	b.Delete(userSessionKey(p.User, p.SessionID))
	return s.commit(ctx, b, p, "auth.session.delete", "session "+p.SessionID+" of user "+p.User)
}

// secureCookie reports whether cookies for r should be Secure: whether
// the client reached flint over HTTPS, directly or through a trusted
// proxy.
func secureCookie(r *http.Request) bool {
	return r.TLS != nil || strings.HasPrefix(server.Origin(r), "https://")
}
