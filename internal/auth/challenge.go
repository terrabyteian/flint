package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// ChallengeStyle is how a family of routes asks clients for credentials
// when it refuses a request with 401.
type ChallengeStyle uint8

const (
	// ChallengeDocker is the registry API's Docker token authentication
	// challenge, "WWW-Authenticate: Bearer realm=...,service=...,scope=...",
	// naming the token endpoint and the scope the client needs, with OCI
	// distribution error bodies.
	ChallengeDocker ChallengeStyle = iota
	// ChallengeBasic is `WWW-Authenticate: Basic realm="flint"`, which
	// clients such as Maven and Gradle wait for before they send
	// credentials.
	ChallengeBasic
	// ChallengeCargo is `WWW-Authenticate: Cargo login_url="..."`, which
	// tells Cargo where a user obtains a token.
	ChallengeCargo
	// ChallengePlain is a 401 without a WWW-Authenticate header, after
	// which npm tells the user to log in.
	ChallengePlain
)

// Challenge configures how an Authorizer answers the requests it refuses.
type Challenge struct {
	// Style is the challenge written with 401 responses.
	Style ChallengeStyle
	// LoginURL returns, for ChallengeCargo, the URL of the page where a
	// user obtains a token. Nil means the root of the server, as the
	// client addresses it.
	LoginURL func(r *http.Request) string
	// WriteError writes a refusal's status, 401, 403, or 500, and its
	// body, after any WWW-Authenticate header is set. Nil writes a plain
	// text message, or for ChallengeCargo the JSON errors object of
	// Cargo's web API. ChallengeDocker always writes OCI distribution
	// errors and ignores it.
	WriteError func(w http.ResponseWriter, r *http.Request, status int, msg string)
}

// Authorizer authorizes the requests of one family of routes, such as
// one package format's, and answers those it refuses in the family's
// challenge style. Every style accepts the same credentials. Bearer
// tokens from the token service are accepted only by ChallengeDocker,
// because they are issued for the registry API.
type Authorizer struct {
	s *Service
	c Challenge
}

// Authorizer returns an Authorizer that answers refusals as c says.
func (s *Service) Authorizer(c Challenge) *Authorizer {
	return &Authorizer{s: s, c: c}
}

// check is one action on one repository that a request needs.
type check struct {
	repo, action string
}

// checksFor returns the checks for actions on repo.
func checksFor(repo string, actions []string) []check {
	cs := make([]check, len(actions))
	for i, a := range actions {
		cs[i] = check{repo, a}
	}
	return cs
}

// Authorize reports whether the request may perform every action
// (ActionPull, ActionPush, ActionDelete) on repository repo, a flint
// repository or a path within one. When it returns false it has written
// the response: 401 with the authorizer's challenge if the request has no
// valid credentials (or, with ChallengeDocker, a token that lacks the
// scope), or 403 if the client presented a password or an API token that
// lacks the permission.
//
// With repo empty and no actions, it checks only that the request carries
// valid credentials.
//
// When it returns true, it records the principal in r's context for
// PrincipalOf and Actor.
func (a *Authorizer) Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool {
	return a.authorize(w, r, repo == "" && len(actions) == 0, checksFor(repo, actions), repoScope(repo, actions))
}

// AuthorizeVirtual is Authorize for a virtual repository, which serves a
// merged view of its members. Pulling through it needs read on the
// virtual repository only: the view is what its administrator composed,
// so a client needs no role on the members. Pushing and deleting through
// it need write and delete on publishTo, the hosted member that receives
// what is published to it, and are refused if publishTo is empty; a
// format should answer such a publish as unsupported before authorizing
// it.
func (a *Authorizer) AuthorizeVirtual(w http.ResponseWriter, r *http.Request, virtual, publishTo string, actions ...string) bool {
	cs := virtualChecks(virtual, publishTo, actions)
	return a.authorize(w, r, false, cs, scopeOf(cs))
}

// virtualChecks maps actions through virtual repository virtual onto the
// repositories whose roles govern them.
func virtualChecks(virtual, publishTo string, actions []string) []check {
	cs := make([]check, len(actions))
	for i, act := range actions {
		repo := virtual
		if act != ActionPull {
			repo = publishTo
		}
		cs[i] = check{repo, act}
	}
	return cs
}

// scopeOf is the Docker token scope for checks: a scope for each
// repository in turn, separated by spaces.
func scopeOf(cs []check) string {
	var scopes []string
	var repos []string
	byRepo := map[string][]string{}
	for _, c := range cs {
		if c.repo == "" {
			continue
		}
		if _, ok := byRepo[c.repo]; !ok {
			repos = append(repos, c.repo)
		}
		byRepo[c.repo] = append(byRepo[c.repo], c.action)
	}
	for _, repo := range repos {
		scopes = append(scopes, repoScope(repo, byRepo[repo]))
	}
	return strings.Join(scopes, " ")
}

// Allowed reports whether the request's credentials permit every action
// on repo, without writing a response. Invalid credentials permit
// nothing.
func (a *Authorizer) Allowed(r *http.Request, repo string, actions ...string) bool {
	c, err := a.s.authenticate(r, a.c.Style == ChallengeDocker)
	return err == nil && a.s.permits(c, checksFor(repo, actions))
}

// AllowedVirtual is Allowed for a virtual repository, with
// AuthorizeVirtual's rule.
func (a *Authorizer) AllowedVirtual(r *http.Request, virtual, publishTo string, actions ...string) bool {
	c, err := a.s.authenticate(r, a.c.Style == ChallengeDocker)
	return err == nil && a.s.permits(c, virtualChecks(virtual, publishTo, actions))
}

// Actor names the principal the request was admitted as; see
// Service.Actor.
func (a *Authorizer) Actor(r *http.Request) string { return a.s.Actor(r) }

// authorize checks that the request's credentials allow every check, or,
// for base, that it carries valid credentials. scope is the Docker token
// scope the checks need.
func (a *Authorizer) authorize(w http.ResponseWriter, r *http.Request, base bool, cs []check, scope string) bool {
	c, err := a.s.authenticate(r, a.c.Style == ChallengeDocker)
	switch {
	case err != nil && !errors.Is(err, ErrInvalidCredentials):
		a.s.log.Error("authentication failed", "err", err)
		a.internalError(w, r)
		return false
	case err != nil:
		a.unauthorized(w, r, scope, "invalid_token")
		return false
	case base:
		if c.kind == credNone {
			a.unauthorized(w, r, "", "")
			return false
		}
	case !a.s.permits(c, cs):
		switch c.kind {
		case credNone:
			a.unauthorized(w, r, scope, "")
		case credJWT:
			a.unauthorized(w, r, scope, "insufficient_scope")
		default:
			a.forbidden(w, r)
		}
		return false
	}
	admit(r, c.principal)
	return true
}

// permits reports whether the credentials allow every check.
func (s *Service) permits(c credentials, cs []check) bool {
	for _, ch := range cs {
		need, ok := actionRole(ch.action)
		if !ok || s.Role(c.principal, ch.repo) < need {
			return false
		}
		if c.kind == credJWT && !c.jwt.allows(ch.repo, ch.action) {
			return false
		}
	}
	return true
}

// unauthorized writes a 401 response with the authorizer's challenge.
// scope and errCode are for the Docker challenge: the token scope the
// client needs, and why the presented token, if any, fell short.
func (a *Authorizer) unauthorized(w http.ResponseWriter, r *http.Request, scope, errCode string) {
	msg := "authentication required"
	switch a.c.Style {
	case ChallengeDocker:
		a.s.challenge(w, r, scope, errCode)
		return
	case ChallengeBasic:
		w.Header().Set("WWW-Authenticate", `Basic realm="`+Issuer+`"`)
	case ChallengeCargo:
		u := baseURL(r) + "/"
		if a.c.LoginURL != nil {
			u = a.c.LoginURL(r)
		}
		w.Header().Set("WWW-Authenticate", `Cargo login_url=`+quote(u))
	}
	if errCode == "invalid_token" {
		msg = "incorrect username, password, or token"
	}
	a.writeError(w, r, http.StatusUnauthorized, msg)
}

// forbidden writes a 403 response.
func (a *Authorizer) forbidden(w http.ResponseWriter, r *http.Request) {
	if a.c.Style == ChallengeDocker {
		writeRegistryError(w, http.StatusForbidden, "DENIED", "requested access to the resource is denied")
		return
	}
	a.writeError(w, r, http.StatusForbidden, "access denied")
}

// internalError writes a 500 response.
func (a *Authorizer) internalError(w http.ResponseWriter, r *http.Request) {
	if a.c.Style == ChallengeDocker {
		writeRegistryError(w, http.StatusInternalServerError, "UNKNOWN", "internal error")
		return
	}
	a.writeError(w, r, http.StatusInternalServerError, "internal error")
}

// writeError writes a refusal's body for a style other than
// ChallengeDocker.
func (a *Authorizer) writeError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	switch {
	case a.c.WriteError != nil:
		a.c.WriteError(w, r, status, msg)
	case a.c.Style == ChallengeCargo:
		type detail struct {
			Detail string `json:"detail"`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(struct {
			Errors []detail `json:"errors"`
		}{[]detail{{msg}}})
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		w.Write([]byte(msg + "\n"))
	}
}

// quote returns s as an HTTP quoted-string.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}
