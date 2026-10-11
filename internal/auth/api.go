package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/server"
)

// The admin API serves JSON under /api/v1/. Every request authenticates
// with a password or an API token, in any form authenticate accepts;
// tokens from the Docker token service are not accepted. Managing
// users and groups needs the global admin role. Creating an API token,
// creating or updating a user or its groups, and setting a password need
// a password, even with an admin token: a token cannot mint further
// tokens or take over its owner's or anyone else's account.

const apiPrefix = "/api/v1"

// maxAPIBody bounds admin API request bodies.
const maxAPIBody = 64 << 10

func (s *Service) registerAPI(srv *server.Server) {
	for pattern, h := range map[string]apiHandler{
		"GET /api/v1/user":                             s.apiWhoami,
		"GET /api/v1/users":                            s.admin(s.apiListUsers),
		"POST /api/v1/users":                           s.admin(s.withPassword(s.apiCreateUser)),
		"GET /api/v1/users/{name}":                     s.apiGetUser,
		"PATCH /api/v1/users/{name}":                   s.admin(s.withPassword(s.apiUpdateUser)),
		"DELETE /api/v1/users/{name}":                  s.admin(s.apiDeleteUser),
		"PUT /api/v1/users/{name}/password":            s.withPassword(s.apiSetPassword),
		"GET /api/v1/groups":                           s.admin(s.apiListGroups),
		"PUT /api/v1/groups/{group}/members/{name}":    s.admin(s.withPassword(s.apiAddMember)),
		"DELETE /api/v1/groups/{group}/members/{name}": s.admin(s.withPassword(s.apiRemoveMember)),
		"GET /api/v1/tokens":                           s.apiListTokens,
		"POST /api/v1/tokens":                          s.withPassword(s.apiCreateToken),
		"DELETE /api/v1/tokens/{id}":                   s.apiRevokeToken,
		apiPrefix + "/":                                s.apiNotFound,
	} {
		srv.Handle(pattern, s.api(h))
	}
}

// apiHandler serves an authenticated admin API request. It returns the
// status and the value to encode as the JSON response, or an error.
type apiHandler func(r *http.Request, p *Principal) (int, any, error)

// api authenticates a request, runs h, and writes its result.
func (s *Service) api(h apiHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.apiAuthenticate(w, r)
		if !ok {
			return
		}
		status, v, err := h(r, p)
		if err != nil {
			status, v = s.apiErrorResponse(err)
		}
		if v == nil {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, status, v)
	})
}

// apiAuthenticate authenticates an admin API request. If it fails, it
// writes the response and reports false.
func (s *Service) apiAuthenticate(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	w.Header().Set("Cache-Control", "no-store")
	c, err := s.authenticate(r, false)
	if err == nil && c.kind == credNone {
		err = ErrInvalidCredentials
	}
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+Issuer+`"`)
			writeJSON(w, http.StatusUnauthorized, apiError{"authentication required"})
			return nil, false
		}
		s.log.Error("authentication failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, apiError{"internal error"})
		return nil, false
	}
	logPrincipal(r.Context(), c.principal)
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIBody)
	return c.principal, true
}

// AdminHandler serves h as an admin API endpoint of another package: it
// authenticates the request as the admin API does and requires the
// global admin role, answering with the admin API's JSON errors. Within
// h, Actor names the client.
func (s *Service) AdminHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.apiAuthenticate(w, r)
		if !ok {
			return
		}
		if !p.Admin {
			writeJSON(w, http.StatusForbidden, apiError{errForbidden.Error()})
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// admin restricts h to the global admin role.
func (s *Service) admin(h apiHandler) apiHandler {
	return func(r *http.Request, p *Principal) (int, any, error) {
		if !p.Admin {
			return 0, nil, errForbidden
		}
		return h(r, p)
	}
}

// withPassword restricts h to clients authenticated with a password.
func (s *Service) withPassword(h apiHandler) apiHandler {
	return func(r *http.Request, p *Principal) (int, any, error) {
		if !p.Password {
			return 0, nil, errNeedsPassword
		}
		return h(r, p)
	}
}

var (
	errForbidden     = errors.New("this requires the admin role")
	errNeedsPassword = errors.New("this requires authenticating with a password, not a token")
	errNotFound      = errors.New("not found")
)

type apiError struct {
	Error string `json:"error"`
}

func (s *Service) apiErrorResponse(err error) (int, any) {
	var inv *invalidError
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &inv):
		return http.StatusBadRequest, apiError{inv.msg}
	case errors.As(err, &mbe):
		return http.StatusRequestEntityTooLarge, apiError{"the request body is too large"}
	case errors.Is(err, errForbidden), errors.Is(err, errNeedsPassword):
		return http.StatusForbidden, apiError{err.Error()}
	case errors.Is(err, errNoSuchUser), errors.Is(err, errNoSuchToken), errors.Is(err, errNotFound):
		return http.StatusNotFound, apiError{err.Error()}
	case errors.Is(err, errUserExists), errors.Is(err, errLastAdmin):
		return http.StatusConflict, apiError{err.Error()}
	}
	s.log.Error("admin API request failed", "err", err)
	return http.StatusInternalServerError, apiError{"internal error"}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// decodeBody decodes a JSON request body strictly into v.
func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		return invalidf("invalid JSON body: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalidf("invalid JSON body: unexpected data after the object")
	}
	return nil
}

// userJSON is a user as the API shows it.
type userJSON struct {
	Name     string    `json:"name"`
	Admin    bool      `json:"admin"`
	Groups   []string  `json:"groups"`
	Created  time.Time `json:"created"`
	Password bool      `json:"password"` // whether password login is enabled
}

func toUserJSON(u *user) userJSON {
	g := u.Groups
	if g == nil {
		g = []string{}
	}
	return userJSON{Name: u.Name, Admin: u.Admin, Groups: g, Created: u.Created.UTC(), Password: len(u.Password) > 0}
}

// whoamiJSON describes the authenticated client.
type whoamiJSON struct {
	Name    string   `json:"name"`
	Admin   bool     `json:"admin"`
	Groups  []string `json:"groups"`
	TokenID string   `json:"tokenId,omitempty"`
}

func (s *Service) apiWhoami(r *http.Request, p *Principal) (int, any, error) {
	g := p.Groups
	if g == nil {
		g = []string{}
	}
	return http.StatusOK, whoamiJSON{Name: p.User, Admin: p.Admin, Groups: g, TokenID: p.TokenID}, nil
}

func (s *Service) apiListUsers(r *http.Request, p *Principal) (int, any, error) {
	users, err := s.listUsers()
	if err != nil {
		return 0, nil, err
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, toUserJSON(u))
	}
	return http.StatusOK, out, nil
}

func (s *Service) apiCreateUser(r *http.Request, p *Principal) (int, any, error) {
	var req struct {
		Name     string   `json:"name"`
		Password string   `json:"password"`
		Admin    bool     `json:"admin"`
		Groups   []string `json:"groups"`
	}
	if err := decodeBody(r, &req); err != nil {
		return 0, nil, err
	}
	u, err := s.createUser(r.Context(), p, req.Name, req.Password, req.Admin, req.Groups)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, toUserJSON(u), nil
}

func (s *Service) apiGetUser(r *http.Request, p *Principal) (int, any, error) {
	name := r.PathValue("name")
	if !p.Admin && name != p.User {
		return 0, nil, errForbidden
	}
	u, err := s.getUser(name)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, toUserJSON(u), nil
}

func (s *Service) apiUpdateUser(r *http.Request, p *Principal) (int, any, error) {
	var req struct {
		Admin  *bool     `json:"admin"`
		Groups *[]string `json:"groups"`
	}
	if err := decodeBody(r, &req); err != nil {
		return 0, nil, err
	}
	var groups []string
	if req.Groups != nil {
		var err error
		if groups, err = normalizeGroups(*req.Groups); err != nil {
			return 0, nil, err
		}
	}
	u, err := s.updateUser(r.Context(), p, r.PathValue("name"), "auth.user.update", func(u *user) error {
		if req.Admin != nil {
			u.Admin = *req.Admin
		}
		if req.Groups != nil {
			u.Groups = groups
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, toUserJSON(u), nil
}

func (s *Service) apiDeleteUser(r *http.Request, p *Principal) (int, any, error) {
	return http.StatusNoContent, nil, s.deleteUser(r.Context(), p, r.PathValue("name"))
}

// apiSetPassword sets a user's password: an administrator's for anyone,
// or a user's own.
func (s *Service) apiSetPassword(r *http.Request, p *Principal) (int, any, error) {
	name := r.PathValue("name")
	if !p.Admin && name != p.User {
		return 0, nil, errForbidden
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeBody(r, &req); err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, s.setPassword(r.Context(), p, name, req.Password)
}

type groupJSON struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// apiListGroups lists every group that has members, and groups that
// config grants name.
func (s *Service) apiListGroups(r *http.Request, p *Principal) (int, any, error) {
	users, err := s.listUsers()
	if err != nil {
		return 0, nil, err
	}
	members := map[string][]string{}
	for _, g := range s.policy.grants {
		for name := range g.groups {
			members[name] = members[name][:0:0]
		}
	}
	for _, u := range users {
		for _, g := range u.Groups {
			members[g] = append(members[g], u.Name)
		}
	}
	out := make([]groupJSON, 0, len(members))
	for name, m := range members {
		if m == nil {
			m = []string{}
		}
		out = append(out, groupJSON{Name: name, Members: m})
	}
	slices.SortFunc(out, func(a, b groupJSON) int { return strings.Compare(a.Name, b.Name) })
	return http.StatusOK, out, nil
}

func (s *Service) apiAddMember(r *http.Request, p *Principal) (int, any, error) {
	return http.StatusNoContent, nil, s.setGroupMember(r.Context(), p, r.PathValue("group"), r.PathValue("name"), true)
}

func (s *Service) apiRemoveMember(r *http.Request, p *Principal) (int, any, error) {
	return http.StatusNoContent, nil, s.setGroupMember(r.Context(), p, r.PathValue("group"), r.PathValue("name"), false)
}

// scopeJSON is a token scope as the API shows it.
type scopeJSON struct {
	Repositories []string `json:"repositories"`
	Role         string   `json:"role"`
}

// tokenJSON is an API token as the API shows it. Token is set only in the
// response that creates it.
type tokenJSON struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Owner   string      `json:"owner"`
	Created time.Time   `json:"created"`
	Expires *time.Time  `json:"expires,omitempty"`
	Expired bool        `json:"expired"`
	Admin   bool        `json:"admin"`
	Scopes  []scopeJSON `json:"scopes"`
	Token   string      `json:"token,omitempty"`
}

func (s *Service) toTokenJSON(t *token) tokenJSON {
	out := tokenJSON{
		ID: t.ID, Name: t.Name, Owner: t.Owner, Created: t.Created.UTC(),
		Expired: t.expired(s.now()), Admin: t.Admin, Scopes: []scopeJSON{},
	}
	if !t.Expires.IsZero() {
		e := t.Expires.UTC()
		out.Expires = &e
	}
	for _, sc := range t.Scopes {
		out.Scopes = append(out.Scopes, scopeJSON{Repositories: sc.Repositories, Role: sc.Role.String()})
	}
	return out
}

func (s *Service) apiListTokens(r *http.Request, p *Principal) (int, any, error) {
	tokens, err := s.listTokens(p.User)
	if err != nil {
		return 0, nil, err
	}
	out := make([]tokenJSON, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, s.toTokenJSON(t))
	}
	return http.StatusOK, out, nil
}

func (s *Service) apiCreateToken(r *http.Request, p *Principal) (int, any, error) {
	var req struct {
		Name      string       `json:"name"`
		ExpiresIn string       `json:"expiresIn"`
		Admin     bool         `json:"admin"`
		Scopes    *[]scopeJSON `json:"scopes"`
	}
	if err := decodeBody(r, &req); err != nil {
		return 0, nil, err
	}
	var expires time.Time
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil || d <= 0 {
			return 0, nil, invalidf("expiresIn %q is not a positive duration such as \"720h\"", req.ExpiresIn)
		}
		expires = s.now().Add(d)
	}
	// Without scopes, the token carries all of its owner's repository
	// permissions.
	scopes := []Scope{{Repositories: []string{"*"}, Role: RoleAdmin}}
	if req.Scopes != nil {
		scopes = scopes[:0]
		if len(*req.Scopes) == 0 {
			return 0, nil, invalidf("scopes, if set, must not be empty")
		}
		for _, sj := range *req.Scopes {
			role, ok := ParseRole(sj.Role)
			if !ok {
				return 0, nil, invalidf("%q is not one of read, write, delete, admin", sj.Role)
			}
			scopes = append(scopes, Scope{Repositories: sj.Repositories, Role: role})
		}
	}
	t, secret, err := s.createToken(r.Context(), p, req.Name, expires, req.Admin, scopes)
	if err != nil {
		return 0, nil, err
	}
	out := s.toTokenJSON(t)
	out.Token = secret
	return http.StatusCreated, out, nil
}

func (s *Service) apiRevokeToken(r *http.Request, p *Principal) (int, any, error) {
	return http.StatusNoContent, nil, s.revokeToken(r.Context(), p, r.PathValue("id"))
}

func (s *Service) apiNotFound(r *http.Request, p *Principal) (int, any, error) {
	return 0, nil, errNotFound
}
