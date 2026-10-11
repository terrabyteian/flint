package auth

import (
	"context"
	"errors"
	"time"
)

// maxClientNameLen bounds the client name a login token is named after.
const maxClientNameLen = 64

// LoginToken serves a package client's login command, such as npm's
// legacy "npm login", which sends a user name and password through the
// client's own protocol and expects a token back. It verifies the
// password and mints an API token for the user, which it returns: the
// only time the token string is available.
//
// The token is owned by the user, carries all of the user's repository
// permissions but not the global admin role, is named after client and
// the time of login, as in "npm login 2026-05-01T12:00:00Z", and expires
// after auth.loginTokenTTL. It is listed and revoked like any other
// token.
//
// LoginToken returns ErrInvalidCredentials if the user does not exist,
// has no password, or the password is wrong. An API token is not
// accepted in place of the password, so a token cannot mint another.
func (s *Service) LoginToken(ctx context.Context, username, password, client string) (string, error) {
	if !validClientName(client) {
		return "", errors.New("auth: the client name must be 1 to 64 printable ASCII characters")
	}
	p, err := s.checkPassword(ctx, username, password)
	if err != nil {
		return "", err
	}
	now := s.now()
	name := client + " login " + now.UTC().Format(time.RFC3339)
	scopes := []Scope{{Repositories: []string{"*"}, Role: RoleAdmin}}
	_, secret, err := s.createToken(ctx, p, name, now.Add(s.loginTTL), false, scopes)
	if errors.Is(err, errNoSuchUser) {
		// The user was deleted after the password was checked.
		return "", ErrInvalidCredentials
	}
	return secret, err
}

// validClientName reports whether a login token can be named after
// client.
func validClientName(client string) bool {
	if client == "" || len(client) > maxClientNameLen {
		return false
	}
	for i := 0; i < len(client); i++ {
		if client[i] < ' ' || client[i] > '~' {
			return false
		}
	}
	return true
}
