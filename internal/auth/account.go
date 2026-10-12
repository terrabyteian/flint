package auth

import (
	"context"
	"errors"
	"time"
)

// The account operations serve a signed-in user managing their own
// account, as the web UI does: the same rules as the admin API's, for a
// principal the caller has authenticated. Unlike the admin API, they
// accept a web UI session for creating tokens, because a session is an
// interactive sign-in rather than a token; changing the password needs
// the current one.

// TokenInfo describes an API token, without its secret.
type TokenInfo struct {
	ID      string
	Name    string
	Owner   string
	Created time.Time
	// Expires is when the token expires, or zero for never.
	Expires time.Time
	Expired bool
	// Admin reports whether the token may use its owner's global admin
	// role.
	Admin  bool
	Scopes []Scope
}

func (s *Service) tokenInfo(t *token) TokenInfo {
	return TokenInfo{ID: t.ID, Name: t.Name, Owner: t.Owner, Created: t.Created.UTC(), Expires: t.Expires,
		Expired: t.expired(s.now()), Admin: t.Admin, Scopes: t.Scopes}
}

// Tokens returns p's own API tokens, oldest first.
func (s *Service) Tokens(p *Principal) ([]TokenInfo, error) {
	tokens, err := s.listTokens(p.User)
	if err != nil {
		return nil, err
	}
	out := make([]TokenInfo, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, s.tokenInfo(t))
	}
	return out, nil
}

// CreateToken creates an API token owned by p, named name, expiring
// after ttl or never if ttl is zero, and carrying scopes, or all of p's
// repository permissions if scopes is nil. admin also lets it use p's
// global admin role, which p must hold. It returns the token and its
// secret, the only time the secret is available. A principal that
// authenticated with an API token cannot create one.
func (s *Service) CreateToken(ctx context.Context, p *Principal, name string, ttl time.Duration, admin bool, scopes []Scope) (TokenInfo, string, error) {
	switch {
	case p.TokenID != "":
		return TokenInfo{}, "", errNeedsPassword
	case ttl < 0:
		return TokenInfo{}, "", invalidf("the expiry must be in the future")
	case scopes != nil && len(scopes) == 0:
		return TokenInfo{}, "", invalidf("scopes, if set, must not be empty")
	}
	if scopes == nil {
		scopes = []Scope{{Repositories: []string{"*"}, Role: RoleAdmin}}
	}
	var expires time.Time
	if ttl > 0 {
		expires = s.now().Add(ttl)
	}
	t, secret, err := s.createToken(ctx, p, name, expires, admin, scopes)
	if err != nil {
		return TokenInfo{}, "", err
	}
	return s.tokenInfo(t), secret, nil
}

// RevokeToken revokes p's own API token id. It returns an error that
// Message describes if p has no such token.
func (s *Service) RevokeToken(ctx context.Context, p *Principal, id string) error {
	// Administrators may revoke anyone's token through the admin API;
	// here a user revokes only their own.
	own := *p
	own.Admin = false
	return s.revokeToken(ctx, &own, id)
}

// ChangePassword sets p's password to password after checking current,
// p's current password, and ends p's other web UI sessions. It returns
// ErrInvalidCredentials if current is wrong, and an error that Message
// describes if password is unacceptable.
func (s *Service) ChangePassword(ctx context.Context, p *Principal, current, password string) error {
	if p.User == "" || p.TokenID != "" {
		return errNeedsPassword
	}
	if _, err := s.checkPassword(ctx, p.User, current); err != nil {
		return err
	}
	return s.setPassword(ctx, p, p.User, password)
}

// HasPassword reports whether user name can sign in with a password.
func (s *Service) HasPassword(name string) (bool, error) {
	u, err := s.getUser(name)
	if errors.Is(err, errNoSuchUser) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(u.Password) > 0, nil
}

// Message returns, for an error of the account operations or sign-in
// that the user can correct, such as an invalid token name or a wrong
// password, a message to show the user, and false for any other error.
func Message(err error) (string, bool) {
	var inv *invalidError
	switch {
	case errors.As(err, &inv):
		return inv.msg, true
	case errors.Is(err, ErrInvalidCredentials):
		return "incorrect user name or password", true
	case errors.Is(err, errNoSuchToken):
		return "no such token", true
	case errors.Is(err, errNeedsPassword), errors.Is(err, errLastAdmin):
		return err.Error(), true
	}
	return "", false
}
