// Package auth authenticates and authorizes flint's clients: local users
// and groups, API tokens, the Docker bearer-token service, and
// per-repository permission checks. docs/auth.md describes the behavior
// clients see and the admin API.
//
// # Identities
//
// Users are runtime data in the metadata store. A password is stored only
// as a PBKDF2-HMAC-SHA256 hash with a per-user salt and the iteration
// count it was derived with. A user may be a global administrator, and
// belongs to any number of groups.
//
// An API token is a random secret shown once at creation; only its
// SHA-256 hash is stored. It may expire, and it carries a subset of its
// owner's permissions: on every use, the owner's current role on a
// repository is capped by the role the token's scopes give it, and the
// owner's global admin role applies only if the token was created with
// it.
//
// # Permissions
//
// Repository roles are ordered read < write < delete < admin and come from
// the grants in the configuration, to users directly or through their
// groups, by repository name or pattern. A global administrator has the
// admin role everywhere. A repository with anonymous pull lets everyone
// pull. Pull needs read, push needs write, and delete needs delete.
// Permissions apply to flint repositories, the first component of a
// repository path, so a grant on "docker-local" covers
// "docker-local/team/app".
//
// # Docker token authentication
//
// Registry requests carry a short-lived JSON Web Token from the token
// endpoint, GET or POST /auth/token, which a client obtains with HTTP basic
// credentials (a password or an API token; the "__token__" user name takes
// an API token as PyPI clients send it) or anonymously. The tokens are
// signed with an Ed25519 key generated on first start and kept in the data
// directory. Authorize checks a request against a token's granted scope
// and the subject's current permissions, so revoking a user or token takes
// effect at once rather than when the JWT expires. Registry requests may
// also present basic credentials or an API token directly.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/server"
)

// TokenUser is the basic-auth user name that says the password is an API
// token, as PyPI clients send it.
const TokenUser = "__token__"

// Issuer is the issuer and audience of the tokens the token service
// signs, and the service named in authentication challenges.
const Issuer = "flint"

// TokenPath is the path of the Docker token endpoint.
const TokenPath = "/auth/token"

// passwordCacheTTL is how long a verified password is remembered.
const passwordCacheTTL = 5 * time.Minute

// bearerTTL is the lifetime of the bearer tokens the Docker token service
// issues.
const bearerTTL = 5 * time.Minute

// Options configures a Service.
type Options struct {
	// Store holds users and tokens. Required.
	Store meta.Store
	// KeyDir is the directory of the token-signing key, normally
	// <data>/auth. Required.
	KeyDir string
	// FS is the filesystem of KeyDir; nil means fsys.OS.
	FS fsys.FS
	// Config supplies the permission grants and the repositories that
	// allow anonymous pulls. Nil grants nothing.
	Config *config.Config
	// Logger receives auth logs; nil means slog.Default().
	Logger *slog.Logger
	// Metrics receives auth metrics; nil means none.
	Metrics *metrics.Registry
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// PasswordIterations is the PBKDF2 iteration count for new password
	// hashes; zero means DefaultPasswordIterations.
	PasswordIterations int
}

// Service authenticates requests and checks permissions. It implements
// the Authorizer interface the format packages consume.
type Service struct {
	store      meta.Store
	policy     *policy
	signer     *signer
	log        *slog.Logger
	now        func() time.Time
	iterations int

	// mu serializes changes to users and tokens, so checks such as "the
	// last administrator cannot be removed" hold across concurrent
	// requests. Batches also carry preconditions on what they read.
	mu sync.Mutex

	verified *verifiedCache
	hashing  chan struct{} // bounds concurrent PBKDF2 derivations
	dummy    []byte        // hash checked for unknown users, so timing does not reveal them

	attempts *metrics.Counter
	issued   *metrics.CounterSeries
}

// New returns a Service, loading the token-signing key from KeyDir or
// generating and storing one on first start.
func New(opts Options) (*Service, error) {
	if opts.Store == nil || opts.KeyDir == "" {
		return nil, errors.New("auth: Options.Store and Options.KeyDir are required")
	}
	if opts.FS == nil {
		opts.FS = fsys.OS
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PasswordIterations <= 0 {
		opts.PasswordIterations = DefaultPasswordIterations
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.NewRegistry()
	}
	key, created, err := loadOrCreateKey(opts.FS, opts.KeyDir)
	if err != nil {
		return nil, err
	}
	s := &Service{
		store:      opts.Store,
		policy:     newPolicy(opts.Config),
		signer:     newSigner(key),
		log:        opts.Logger,
		now:        opts.Now,
		iterations: opts.PasswordIterations,
		verified:   newVerifiedCache(passwordCacheTTL, 10000),
		hashing:    make(chan struct{}, runtime.GOMAXPROCS(0)),
	}
	if s.dummy, err = hashPassword("flint-unknown-user", s.iterations); err != nil {
		return nil, err
	}
	if created {
		s.log.Info("generated the token-signing key", "path", filepath.Join(opts.KeyDir, keyFileName), "kid", s.signer.kid)
	}
	s.attempts = opts.Metrics.Counter("flint_auth_attempts_total",
		"Credential checks, by method (password, token, jwt) and result (success, failure).", "method", "result")
	s.issued = opts.Metrics.Counter("flint_auth_tokens_issued_total",
		"Bearer tokens issued by the Docker token service.").With()
	return s, nil
}

// Register adds the token endpoint and the admin API to srv.
func (s *Service) Register(srv *server.Server) {
	srv.HandleFunc("GET "+TokenPath, s.handleToken)
	srv.HandleFunc("POST "+TokenPath, s.handleToken)
	s.registerAPI(srv)
}

// Principal is an authenticated client.
type Principal struct {
	// User is the user name, or "" for an anonymous client.
	User string
	// Groups are the user's groups.
	Groups []string
	// Admin reports whether the client holds the global admin role: the
	// user is an administrator and, with a token, the token carries the
	// role.
	Admin bool
	// TokenID is the API token the client authenticated with, if any.
	TokenID string
	// Password reports whether the client authenticated with a password.
	Password bool

	userAdmin bool    // the user's own admin flag, which a token's scopes then cap
	scopes    []Scope // the token's scopes
}

// credential kinds a request can present.
const (
	credNone   = iota // no Authorization header
	credBasic         // basic, with a password or an API token
	credAPIKey        // bearer, with an API token
	credJWT           // bearer, with a token from the token service
)

// credentials is what a request authenticated as.
type credentials struct {
	kind      int
	principal *Principal
	jwt       *claims // for credJWT
}

var anonymous = &Principal{}

// errBadCredentials means a request presented credentials that are wrong,
// expired, or revoked.
var errBadCredentials = errors.New("invalid credentials")

// authenticate resolves a request's Authorization header. With acceptJWT
// false, a bearer token from the token service is not accepted.
func (s *Service) authenticate(r *http.Request, acceptJWT bool) (credentials, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return credentials{kind: credNone, principal: anonymous}, nil
	}
	scheme, param, _ := strings.Cut(h, " ")
	param = strings.TrimSpace(param)
	switch {
	case strings.EqualFold(scheme, "Basic"):
		user, pw, ok := parseBasic(param)
		if !ok {
			return credentials{kind: credBasic}, errBadCredentials
		}
		p, err := s.checkBasic(r.Context(), user, pw)
		return credentials{kind: credBasic, principal: p}, err
	case strings.EqualFold(scheme, "Bearer"):
		if strings.HasPrefix(param, tokenStringPrefix) {
			p, err := s.checkAPIToken(param, "")
			return credentials{kind: credAPIKey, principal: p}, err
		}
		if !acceptJWT {
			return credentials{kind: credJWT}, errBadCredentials
		}
		p, c, err := s.checkJWT(param)
		return credentials{kind: credJWT, principal: p, jwt: c}, err
	}
	return credentials{kind: credBasic}, errBadCredentials
}

// parseBasic decodes basic credentials. Unlike net/http's BasicAuth, it
// works on the parameter alone.
func parseBasic(param string) (user, pw string, ok bool) {
	b, err := base64.StdEncoding.DecodeString(param)
	if err != nil {
		return "", "", false
	}
	return strings.Cut(string(b), ":")
}

// checkBasic authenticates basic credentials: a user name and password, a
// user name and one of the user's API tokens, or TokenUser and an API
// token.
func (s *Service) checkBasic(ctx context.Context, name, secret string) (*Principal, error) {
	if name == TokenUser {
		return s.checkAPIToken(secret, "")
	}
	if strings.HasPrefix(secret, tokenStringPrefix) {
		p, err := s.checkAPIToken(secret, name)
		if !errors.Is(err, errNoSuchToken) {
			return p, err
		}
		// Not a token after all; perhaps a password that looks like one.
	}
	return s.checkPassword(ctx, name, secret)
}

// checkPassword verifies a user's password.
func (s *Service) checkPassword(ctx context.Context, name, pw string) (*Principal, error) {
	if len(pw) > MaxPasswordLen {
		// No stored password is this long; do not spend a derivation on it.
		s.attempts.With("password", "failure").Inc()
		return nil, errBadCredentials
	}
	u, err := s.getUser(name)
	if err != nil && !errors.Is(err, errNoSuchUser) {
		return nil, err
	}
	hash := s.dummy
	if u != nil && len(u.Password) > 0 {
		hash = u.Password
	}
	ok, err := s.verifyPassword(ctx, name, hash, pw)
	if err != nil {
		return nil, err
	}
	if !ok || u == nil || len(u.Password) == 0 {
		s.attempts.With("password", "failure").Inc()
		return nil, errBadCredentials
	}
	s.attempts.With("password", "success").Inc()
	p := userPrincipal(u)
	p.Password = true
	return p, nil
}

// verifyPassword checks pw against hash, from the cache of recent
// successes when it can, and otherwise waiting for a free hashing slot.
func (s *Service) verifyPassword(ctx context.Context, name string, hash []byte, pw string) (bool, error) {
	id := s.verified.id(name, hash, pw)
	if s.verified.has(id, s.now()) {
		return true, nil
	}
	select {
	case s.hashing <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	ok, err := verifyPassword(pw, hash)
	<-s.hashing
	if err != nil {
		return false, err
	}
	if ok {
		s.verified.add(id, s.now())
	}
	return ok, nil
}

// checkAPIToken authenticates an API token. If owner is not empty, the
// token must belong to that user.
func (s *Service) checkAPIToken(secret, owner string) (*Principal, error) {
	id, ok := parseTokenString(secret)
	if !ok {
		s.attempts.With("token", "failure").Inc()
		if owner != "" {
			return nil, errNoSuchToken
		}
		return nil, errBadCredentials
	}
	t, err := s.getToken(id)
	if errors.Is(err, errNoSuchToken) {
		s.attempts.With("token", "failure").Inc()
		if owner != "" {
			return nil, errNoSuchToken
		}
		return nil, errBadCredentials
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(sum[:], t.Hash) != 1 || (owner != "" && owner != t.Owner) {
		s.attempts.With("token", "failure").Inc()
		return nil, errBadCredentials
	}
	p, err := s.tokenPrincipal(t)
	if err != nil {
		s.attempts.With("token", "failure").Inc()
		return nil, err
	}
	s.attempts.With("token", "success").Inc()
	return p, nil
}

// tokenPrincipal returns the principal an API token stands for, if the
// token is still valid and its owner still exists.
func (s *Service) tokenPrincipal(t *token) (*Principal, error) {
	if t.expired(s.now()) {
		return nil, errBadCredentials
	}
	u, err := s.getUser(t.Owner)
	if errors.Is(err, errNoSuchUser) {
		return nil, errBadCredentials
	}
	if err != nil {
		return nil, err
	}
	p := userPrincipal(u)
	p.Admin = u.Admin && t.Admin
	p.TokenID = t.ID
	p.scopes = t.Scopes
	return p, nil
}

// checkJWT verifies a token from the token service and resolves its
// subject as it is now.
func (s *Service) checkJWT(tok string) (*Principal, *claims, error) {
	c, err := s.signer.verify(tok, Issuer, Issuer, s.now())
	if err != nil {
		s.attempts.With("jwt", "failure").Inc()
		return nil, nil, errBadCredentials
	}
	p := anonymous
	switch {
	case c.TokenID != "":
		t, terr := s.getToken(c.TokenID)
		if terr == nil && t.Owner == c.Subject {
			p, err = s.tokenPrincipal(t)
		} else if terr == nil || errors.Is(terr, errNoSuchToken) {
			err = errBadCredentials
		} else {
			err = terr
		}
	case c.Subject != "":
		var u *user
		u, err = s.getUser(c.Subject)
		if errors.Is(err, errNoSuchUser) {
			err = errBadCredentials
		} else if err == nil {
			p = userPrincipal(u)
		}
	}
	if err != nil {
		s.attempts.With("jwt", "failure").Inc()
		return nil, nil, err
	}
	s.attempts.With("jwt", "success").Inc()
	return p, c, nil
}

func userPrincipal(u *user) *Principal {
	return &Principal{User: u.Name, Groups: u.Groups, Admin: u.Admin, userAdmin: u.Admin}
}

// Role returns the role p holds on the flint repository that repository
// path repo belongs to.
func (s *Service) Role(p *Principal, repo string) Role {
	return s.policy.role(p, repoOf(repo))
}

// permits reports whether the credentials allow every action on repo.
func (s *Service) permits(c credentials, repo string, actions []string) bool {
	role := s.Role(c.principal, repo)
	for _, a := range actions {
		need, ok := actionRole(a)
		if !ok || role < need {
			return false
		}
		if c.kind == credJWT && !c.jwt.allows(repo, a) {
			return false
		}
	}
	return true
}

// Authorize reports whether the request may perform every action ("pull",
// "push", "delete") on repository repo, a flint repository or a path
// within one. When it returns false it has written the response: 401 with
// a Docker-compatible Bearer challenge naming the scope the client needs a
// token for, or 403 if the client authenticated with basic credentials or
// an API token that lacks the permission.
//
// With repo empty and no actions, it checks only that the request carries
// valid credentials, a bearer token from the token service included, as
// the registry's base endpoint needs for "docker login".
func (s *Service) Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool {
	c, err := s.authenticate(r, true)
	switch {
	case err != nil && !errors.Is(err, errBadCredentials):
		s.log.Error("authentication failed", "err", err)
		writeRegistryError(w, http.StatusInternalServerError, "UNKNOWN", "internal error")
		return false
	case err != nil:
		s.challenge(w, r, repo, actions, "invalid_token")
		return false
	case repo == "" && len(actions) == 0:
		if c.kind == credNone {
			s.challenge(w, r, "", nil, "")
			return false
		}
	case !s.permits(c, repo, actions):
		switch c.kind {
		case credNone:
			s.challenge(w, r, repo, actions, "")
		case credJWT:
			s.challenge(w, r, repo, actions, "insufficient_scope")
		default:
			writeRegistryError(w, http.StatusForbidden, "DENIED", "requested access to the resource is denied")
		}
		return false
	}
	logPrincipal(r.Context(), c.principal)
	return true
}

// Allowed reports whether the request's credentials permit every action
// on repo, without writing a response; for example, to filter a listing
// or to decide whether a cross-repository mount may read its source.
// Invalid credentials permit nothing.
func (s *Service) Allowed(r *http.Request, repo string, actions ...string) bool {
	c, err := s.authenticate(r, true)
	return err == nil && s.permits(c, repo, actions)
}

// challenge writes a 401 response with a Bearer challenge pointing at the
// token endpoint.
func (s *Service) challenge(w http.ResponseWriter, r *http.Request, repo string, actions []string, errCode string) {
	v := fmt.Sprintf(`Bearer realm="%s",service="%s"`, s.realm(r), Issuer)
	if repo != "" {
		v += fmt.Sprintf(`,scope="repository:%s:%s"`, repo, strings.Join(actions, ","))
	}
	if errCode != "" {
		v += fmt.Sprintf(`,error="%s"`, errCode)
	}
	w.Header().Set("WWW-Authenticate", v)
	writeRegistryError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
}

// realm returns the token endpoint's URL as the client addresses this
// server, honoring trusted proxies.
func (s *Service) realm(r *http.Request) string {
	info := server.Info(r.Context())
	scheme, host := info.Scheme, info.Host
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
		host = r.Host
	}
	return scheme + "://" + host + TokenPath
}

// writeRegistryError writes an OCI distribution error response.
func writeRegistryError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"errors":[{"code":%q,"message":%q}]}`+"\n", code, msg)
}

// logPrincipal adds the client's identity to the request log.
func logPrincipal(ctx context.Context, p *Principal) {
	if p == nil || p.User == "" {
		return
	}
	attrs := []slog.Attr{slog.String("user", p.User)}
	if p.TokenID != "" {
		attrs = append(attrs, slog.String("token_id", p.TokenID))
	}
	server.LogAttrs(ctx, attrs...)
}
