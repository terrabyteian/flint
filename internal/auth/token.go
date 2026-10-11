package auth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

// maxScopes bounds the scopes one token request may ask for.
const maxScopes = 64

// tokenResponse is the token endpoint's answer. "token" is what Docker
// clients read; "access_token" is the OAuth 2 name other clients read.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

// handleToken is the Docker token endpoint. GET authenticates with basic
// credentials or none (anonymous); POST is the OAuth 2 password grant that
// containerd uses. Both take "scope" parameters such as
// "repository:docker-local/app:pull,push", and the token grants each
// requested action the client's role allows. Requested actions it does
// not allow are left out, not refused: the registry then refuses the
// request that needs them.
func (s *Service) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var p *Principal
	var err error
	var scopes []string
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if r.PostForm.Get("grant_type") != "password" {
			// Refresh tokens are not issued, so only the password grant
			// is supported; containerd then falls back to GET.
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type")
			return
		}
		p, err = s.checkBasic(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
		scopes = r.PostForm["scope"]
	} else {
		var c credentials
		c, err = s.authenticate(r, false)
		p = c.principal
		scopes = r.URL.Query()["scope"]
	}
	if errors.Is(err, ErrInvalidCredentials) {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+Issuer+`"`)
		writeRegistryError(w, http.StatusUnauthorized, "UNAUTHORIZED", "incorrect username, password, or token")
		return
	}
	if err != nil {
		s.log.Error("authentication failed", "err", err)
		writeRegistryError(w, http.StatusInternalServerError, "UNKNOWN", "internal error")
		return
	}

	granted, ok := s.grant(p, scopes)
	if !ok {
		writeRegistryError(w, http.StatusBadRequest, "UNSUPPORTED", "too many scopes requested")
		return
	}
	now := s.now()
	c := &claims{
		Issuer:    Issuer,
		Subject:   p.User,
		Audience:  Issuer,
		Expiry:    now.Add(bearerTTL).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		ID:        rand.Text(),
		TokenID:   p.TokenID,
		Access:    granted,
	}
	tok, err := s.signer.sign(c)
	if err != nil {
		s.log.Error("signing a token failed", "err", err)
		writeRegistryError(w, http.StatusInternalServerError, "UNKNOWN", "internal error")
		return
	}
	s.issued.Inc()
	logPrincipal(r.Context(), p)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse{
		Token:       tok,
		AccessToken: tok,
		TokenType:   "Bearer",
		ExpiresIn:   int(bearerTTL / time.Second),
		IssuedAt:    now.UTC().Format(time.RFC3339),
	})
}

// grant computes the access entries a token for p gets for the requested
// scope parameters. Each parameter may hold several space-separated
// scopes. Besides repository scopes, it grants "registry:catalog:*".
// Malformed scopes and other resource types are ignored. It reports false
// if too many scopes were requested.
func (s *Service) grant(p *Principal, params []string) ([]access, bool) {
	granted := []access{}
	n := 0
	for _, param := range params {
		for _, sc := range strings.Fields(param) {
			if n++; n > maxScopes {
				return nil, false
			}
			typ, name, actions, ok := parseScope(sc)
			if ok && typ == "registry" && name == "catalog" && strings.HasSuffix(sc, ":*") {
				// Anyone may list repositories; the listing shows only
				// those the client may pull from.
				if !slices.ContainsFunc(granted, func(g access) bool { return g.Type == typ }) {
					granted = append(granted, access{Type: typ, Name: name, Actions: []string{"*"}})
				}
				continue
			}
			if !ok || typ != "repository" {
				continue
			}
			role := s.Role(p, name)
			var allowed []string
			for _, a := range actions {
				if need, ok := actionRole(a); ok && role >= need && !slices.Contains(allowed, a) {
					allowed = append(allowed, a)
				}
			}
			if len(allowed) == 0 {
				continue
			}
			if i := slices.IndexFunc(granted, func(g access) bool { return g.Type == typ && g.Name == name }); i >= 0 {
				for _, a := range allowed {
					if !slices.Contains(granted[i].Actions, a) {
						granted[i].Actions = append(granted[i].Actions, a)
					}
				}
				continue
			}
			granted = append(granted, access{Type: typ, Name: name, Actions: allowed})
		}
	}
	return granted, true
}

// parseScope splits a scope "type:name:actions" at its first and last
// ":"; "*" stands for every action.
func parseScope(s string) (typ, name string, actions []string, ok bool) {
	typ, rest, ok1 := strings.Cut(s, ":")
	i := strings.LastIndexByte(rest, ':')
	if !ok1 || i < 0 || !validRepoPath(rest[:i]) {
		return "", "", nil, false
	}
	name, list := rest[:i], rest[i+1:]
	for _, a := range strings.Split(list, ",") {
		if a == "*" {
			actions = append(actions, allActions...)
		} else if a != "" {
			actions = append(actions, a)
		}
	}
	return typ, name, actions, true
}

// validRepoPath reports whether s is a repository path as the OCI
// distribution spec defines names: "/"-separated components of lowercase
// letters and digits, joined within a component by ".", "_", "__", or
// runs of "-".
func validRepoPath(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, comp := range strings.Split(s, "/") {
		if comp == "" || !isAlnum(comp[0]) || !isAlnum(comp[len(comp)-1]) {
			return false
		}
		for i := 0; i < len(comp); i++ {
			switch c := comp[i]; {
			case isAlnum(c):
			case c == '.' || c == '_' && comp[i+1] != '_':
				if !isAlnum(comp[i+1]) {
					return false
				}
			case c == '_': // "__"
				if !isAlnum(comp[i+2]) || comp[i-1] == '_' {
					return false
				}
				i++
			case c == '-':
				for comp[i+1] == '-' {
					i++
				}
				if !isAlnum(comp[i+1]) {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

func isAlnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

// writeOAuthError writes an OAuth 2 error response (RFC 6749, section 5.2).
func writeOAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}
