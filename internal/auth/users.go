package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
)

// Errors of user and token management.
var (
	errNoSuchUser  = errors.New("no such user")
	errNoSuchToken = errors.New("no such token")
	errUserExists  = errors.New("the user already exists")
	errLastAdmin   = errors.New("the last administrator cannot be removed or demoted")
)

// invalidError is a request the caller must correct.
type invalidError struct{ msg string }

func (e *invalidError) Error() string { return e.msg }

func invalidf(format string, args ...any) error {
	return &invalidError{fmt.Sprintf(format, args...)}
}

func (s *Service) getUser(name string) (*user, error) {
	v := s.store.View()
	defer v.Release()
	u, _, err := readUser(v, name)
	return u, err
}

func readUser(v meta.View, name string) (*user, meta.Seq, error) {
	rec, ok := v.Get(userKey(name))
	if !ok {
		return nil, 0, errNoSuchUser
	}
	u, err := decodeUser(name, rec.Value)
	if err != nil {
		return nil, 0, fmt.Errorf("user %q: %w", name, err)
	}
	return u, rec.Version, nil
}

// listUsers returns every user, by name.
func (s *Service) listUsers() ([]*user, error) {
	v := s.store.View()
	defer v.Release()
	return scanUsers(v)
}

func scanUsers(v meta.View) ([]*user, error) {
	var users []*user
	var err error
	v.Scan([]byte(userPrefix), nil, func(key []byte, r meta.Record) bool {
		var u *user
		if u, err = decodeUser(string(key[len(userPrefix):]), r.Value); err != nil {
			return false
		}
		users = append(users, u)
		return true
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

// requireAdmins adds a precondition on every administrator's record to b,
// so the batch fails if the set of administrators changed, and returns
// how many there are.
func requireAdmins(v meta.View, b *meta.Batch) (int, error) {
	users, err := scanUsers(v)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		if u.Admin {
			rec, _ := v.Get(userKey(u.Name))
			b.Require(userKey(u.Name), rec.Version)
			n++
		}
	}
	return n, nil
}

// HasAdmin reports whether any administrator exists.
func (s *Service) HasAdmin() (bool, error) {
	users, err := s.listUsers()
	if err != nil {
		return false, err
	}
	for _, u := range users {
		if u.Admin {
			return true, nil
		}
	}
	return false, nil
}

// normalizeGroups validates group names and returns them sorted, without
// duplicates.
func normalizeGroups(groups []string) ([]string, error) {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if !config.ValidUserName(g) {
			return nil, invalidf("%q is not a valid group name", g)
		}
		out = append(out, g)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// actorOf names a principal in batch origins.
func actorOf(p *Principal) string {
	switch {
	case p == nil || p.User == "":
		return "system"
	case p.TokenID != "":
		return p.User + " (token " + p.TokenID + ")"
	}
	return p.User
}

func (s *Service) commit(ctx context.Context, b *meta.Batch, actor *Principal, action, target string) error {
	b.SetOrigin(meta.Origin{Actor: actorOf(actor), Action: action, Target: target})
	_, err := s.store.Commit(ctx, b)
	return err
}

// createUser creates a user. An empty password disables password login.
func (s *Service) createUser(ctx context.Context, actor *Principal, name, password string, admin bool, groups []string) (*user, error) {
	if !config.ValidUserName(name) {
		return nil, invalidf("%q is not a valid user name: use 1 to 64 lowercase letters, digits, \".\", \"_\", \"-\", or \"@\", starting with a letter or digit", name)
	}
	groups, err := normalizeGroups(groups)
	if err != nil {
		return nil, err
	}
	u := &user{Name: name, Admin: admin, Created: s.now().Truncate(time.Second), Groups: groups}
	if password != "" {
		if err := checkPassword(password); err != nil {
			return nil, &invalidError{err.Error()}
		}
		if u.Password, err = hashPassword(password, s.iterations); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := new(meta.Batch)
	b.Require(userKey(name), 0)
	b.Put(userKey(name), u.encode())
	err = s.commit(ctx, b, actor, "auth.user.create", "user "+name)
	if errors.Is(err, meta.ErrConflict) {
		return nil, errUserExists
	}
	return u, err
}

// updateUser changes a user under s.mu: fn modifies the user and may
// return an error to abandon the change. It refuses a change that leaves
// no administrator.
func (s *Service) updateUser(ctx context.Context, actor *Principal, name, action string, fn func(*user) error) (*user, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.store.View()
	defer v.Release()
	u, ver, err := readUser(v, name)
	if err != nil {
		return nil, err
	}
	wasAdmin := u.Admin
	if err := fn(u); err != nil {
		return nil, err
	}
	b := new(meta.Batch)
	if wasAdmin && !u.Admin {
		n, err := requireAdmins(v, b)
		if err != nil {
			return nil, err
		}
		if n <= 1 {
			return nil, errLastAdmin
		}
	}
	b.Require(userKey(name), ver)
	b.Put(userKey(name), u.encode())
	if err := s.commit(ctx, b, actor, action, "user "+name); err != nil {
		return nil, err
	}
	return u, nil
}

// setPassword replaces a user's password.
func (s *Service) setPassword(ctx context.Context, actor *Principal, name, password string) error {
	if err := checkPassword(password); err != nil {
		return &invalidError{err.Error()}
	}
	hash, err := hashPassword(password, s.iterations)
	if err != nil {
		return err
	}
	_, err = s.updateUser(ctx, actor, name, "auth.user.password", func(u *user) error {
		u.Password = hash
		return nil
	})
	return err
}

// deleteUser deletes a user and the user's tokens.
func (s *Service) deleteUser(ctx context.Context, actor *Principal, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.store.View()
	defer v.Release()
	u, ver, err := readUser(v, name)
	if err != nil {
		return err
	}
	b := new(meta.Batch)
	if u.Admin {
		n, err := requireAdmins(v, b)
		if err != nil {
			return err
		}
		if n <= 1 {
			return errLastAdmin
		}
	}
	b.Require(userKey(name), ver)
	b.Delete(userKey(name))
	prefix := []byte(userTokenPrefix + name + "\x00")
	v.Scan(prefix, nil, func(key []byte, _ meta.Record) bool {
		b.Delete(key)
		b.Delete(tokenKey(string(key[len(prefix):])))
		return true
	})
	return s.commit(ctx, b, actor, "auth.user.delete", "user "+name)
}

// setGroupMember adds a user to a group or removes the user from it.
func (s *Service) setGroupMember(ctx context.Context, actor *Principal, group, name string, member bool) error {
	if !config.ValidUserName(group) {
		return invalidf("%q is not a valid group name", group)
	}
	action := "auth.group.remove"
	if member {
		action = "auth.group.add"
	}
	_, err := s.updateUser(ctx, actor, name, action, func(u *user) error {
		i, found := slices.BinarySearch(u.Groups, group)
		switch {
		case member && !found:
			u.Groups = slices.Insert(u.Groups, i, group)
		case !member && found:
			u.Groups = slices.Delete(u.Groups, i, i+1)
		}
		return nil
	})
	return err
}

// API token strings are "flint_<id>_<secret>": a 16-character identifier,
// which names the token's record, and a 256-bit secret, both in lowercase
// base32. The prefix makes leaked tokens easy for secret scanners to spot.
const (
	tokenStringPrefix = "flint_"
	tokenIDLen        = 16 // 10 random bytes
	tokenSecretLen    = 52 // 32 random bytes
)

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// parseTokenString returns the identifier of a well-formed token string.
func parseTokenString(s string) (string, bool) {
	rest, ok := strings.CutPrefix(s, tokenStringPrefix)
	if !ok || len(rest) != tokenIDLen+1+tokenSecretLen || rest[tokenIDLen] != '_' {
		return "", false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if i != tokenIDLen && !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return "", false
		}
	}
	return rest[:tokenIDLen], true
}

func newTokenString() (id, secret string) {
	var idb [10]byte
	var sb [32]byte
	rand.Read(idb[:])
	rand.Read(sb[:])
	id = b32.EncodeToString(idb[:])
	return id, tokenStringPrefix + id + "_" + b32.EncodeToString(sb[:])
}

func (s *Service) getToken(id string) (*token, error) {
	v := s.store.View()
	defer v.Release()
	rec, ok := v.Get(tokenKey(id))
	if !ok {
		return nil, errNoSuchToken
	}
	t, err := decodeToken(id, rec.Value)
	if err != nil {
		return nil, fmt.Errorf("token %s: %w", id, err)
	}
	return t, nil
}

// MaxTokenNameLen bounds an API token's name, in bytes.
const MaxTokenNameLen = 128

// createToken creates an API token for owner and returns the token string,
// the only time it is available.
func (s *Service) createToken(ctx context.Context, owner *Principal, name string, expires time.Time, admin bool, scopes []Scope) (*token, string, error) {
	switch {
	case strings.TrimSpace(name) == "" || len(name) > MaxTokenNameLen:
		return nil, "", invalidf("the token name must be 1 to %d bytes and not blank", MaxTokenNameLen)
	case admin && !owner.Admin:
		return nil, "", invalidf("only an administrator can create a token with the admin role")
	}
	for _, sc := range scopes {
		if len(sc.Repositories) == 0 {
			return nil, "", invalidf("each scope must name at least one repository or pattern")
		}
		for _, p := range sc.Repositories {
			if !config.ValidRepoPattern(p) {
				return nil, "", invalidf("%q is not a repository name or pattern", p)
			}
		}
		if sc.Role < RoleRead || sc.Role > RoleAdmin {
			return nil, "", invalidf("each scope needs a role: read, write, delete, or admin")
		}
	}
	id, secret := newTokenString()
	sum := sha256.Sum256([]byte(secret))
	t := &token{
		ID: id, Owner: owner.User, Name: name, Hash: sum[:],
		Created: s.now().Truncate(time.Second), Admin: admin, Scopes: scopes,
	}
	if !expires.IsZero() {
		t.Expires = expires.Truncate(time.Second)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.store.View()
	defer v.Release()
	_, ver, err := readUser(v, owner.User)
	if err != nil {
		return nil, "", err
	}
	b := new(meta.Batch)
	b.Require(userKey(owner.User), ver)
	b.Require(tokenKey(id), 0)
	b.Put(tokenKey(id), t.encode())
	b.Put(userTokenKey(owner.User, id), nil)
	if err := s.commit(ctx, b, owner, "auth.token.create", "token "+id+" of user "+owner.User); err != nil {
		return nil, "", err
	}
	return t, secret, nil
}

// listTokens returns a user's tokens, oldest first.
func (s *Service) listTokens(owner string) ([]*token, error) {
	v := s.store.View()
	defer v.Release()
	var tokens []*token
	var err error
	prefix := []byte(userTokenPrefix + owner + "\x00")
	v.Scan(prefix, nil, func(key []byte, _ meta.Record) bool {
		id := string(key[len(prefix):])
		rec, ok := v.Get(tokenKey(id))
		if !ok {
			return true
		}
		var t *token
		if t, err = decodeToken(id, rec.Value); err != nil {
			return false
		}
		tokens = append(tokens, t)
		return true
	})
	slices.SortStableFunc(tokens, func(a, b *token) int { return a.Created.Compare(b.Created) })
	return tokens, err
}

// revokeToken deletes a token. Unless the actor is an administrator, the
// token must be the actor's own.
func (s *Service) revokeToken(ctx context.Context, actor *Principal, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.store.View()
	defer v.Release()
	rec, ok := v.Get(tokenKey(id))
	if !ok {
		return errNoSuchToken
	}
	t, err := decodeToken(id, rec.Value)
	if err != nil {
		return err
	}
	if t.Owner != actor.User && !actor.Admin {
		return errNoSuchToken
	}
	b := new(meta.Batch)
	b.Require(tokenKey(id), rec.Version)
	b.Delete(tokenKey(id))
	b.Delete(userTokenKey(t.Owner, id))
	return s.commit(ctx, b, actor, "auth.token.revoke", "token "+id+" of user "+t.Owner)
}
