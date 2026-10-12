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
// # Web UI sessions
//
// The web UI signs users in to sessions: SignIn checks a password, and
// StartSession serves sign-in providers that authenticate users
// themselves. A session is a random secret, stored only as its hash,
// that SessionPrincipal resolves to its user as the user is now, until
// it expires after auth.sessionTTL or is ended by EndSession, a new
// password, or the user's deletion; see session.go. The account
// operations, such as CreateToken and ChangePassword, serve the UI's
// account page; see account.go.
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
// # PyPI clients
//
// PyPI clients send HTTP basic credentials with every request: a user
// name and password, or "__token__" and an API token. Permit checks
// them for the pypi package.
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
// also present a password or an API token directly.
//
// # Package clients
//
// Besides basic credentials, an API token is accepted as "Authorization:
// Bearer <token>", told apart from the token service's JWTs by its
// "flint_" prefix; as "Authorization: <token>" with no scheme; and in the
// X-NuGet-ApiKey header. Each family of routes answers refusals in its
// clients' challenge style through an Authorizer: the Docker Bearer
// challenge for the registry API, Basic, Cargo, or a plain 401. A format
// can mint an API token for a client's login command with LoginToken,
// put signed download URLs, from SignURL, in the metadata it serves to
// clients that send no credentials for downloads, and check them with
// VerifySignedURL. AuthorizeVirtual applies the rule for virtual
// repositories: reading needs read on the virtual repository only, and
// publishing needs write on its publishTo member.
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
	// KeyDir is the directory of the token-signing and URL-signing keys,
	// normally <data>/auth. Required.
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
	urlKey     []byte      // signs download URLs
	docker     *Authorizer // the registry API's authorizer
	loginTTL   time.Duration
	sessionTTL time.Duration
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

// New returns a Service, loading the token-signing and URL-signing keys
// from KeyDir or generating and storing them on first start.
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
		loginTTL:   config.DefaultLoginTokenTTL,
		sessionTTL: config.DefaultSessionTTL,
		verified:   newVerifiedCache(passwordCacheTTL, 10000),
		hashing:    make(chan struct{}, runtime.GOMAXPROCS(0)),
	}
	s.docker = s.Authorizer(Challenge{Style: ChallengeDocker})
	if opts.Config != nil && opts.Config.Auth.LoginTokenTTL.Duration > 0 {
		s.loginTTL = opts.Config.Auth.LoginTokenTTL.Duration
	}
	if opts.Config != nil && opts.Config.Auth.SessionTTL.Duration > 0 {
		s.sessionTTL = opts.Config.Auth.SessionTTL.Duration
	}
	var urlKeyCreated bool
	if s.urlKey, urlKeyCreated, err = loadOrCreateURLKey(opts.FS, opts.KeyDir); err != nil {
		return nil, err
	}
	if urlKeyCreated {
		s.log.Info("generated the URL-signing key", "path", filepath.Join(opts.KeyDir, urlKeyFileName))
	}
	if s.dummy, err = hashPassword("flint-unknown-user", s.iterations); err != nil {
		return nil, err
	}
	if created {
		s.log.Info("generated the token-signing key", "path", filepath.Join(opts.KeyDir, keyFileName), "kid", s.signer.kid)
	}
	s.attempts = opts.Metrics.Counter("flint_auth_attempts_total",
		"Credential checks, by method (password, token, jwt, url) and result (success, failure).", "method", "result")
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
	// SessionID identifies the web UI session the client authenticated
	// with, if any, and SessionExpires is when it expires.
	SessionID      string
	SessionExpires time.Time

	userAdmin bool    // the user's own admin flag, which a token's scopes then cap
	scopes    []Scope // the token's scopes
}

// credential kinds a request can present.
const (
	credNone   = iota // no credentials
	credDirect        // a password or an API token, presented directly
	credJWT           // bearer, with a token from the token service
)

// credentials is what a request authenticated as.
type credentials struct {
	kind      int
	principal *Principal
	jwt       *claims // for credJWT
}

var anonymous = &Principal{}

// ErrInvalidCredentials means a request presented credentials that are
// wrong, expired, or revoked.
var ErrInvalidCredentials = errors.New("invalid credentials")

// NuGetAPIKeyHeader carries an API token as NuGet clients send it for
// pushes and deletes.
const NuGetAPIKeyHeader = "X-NuGet-ApiKey"

// authenticate resolves a request's credentials. They are, in the
// Authorization header:
//
//   - "Basic" with a user name and a password or an API token;
//   - "Bearer" with an API token, told apart by its "flint_" prefix;
//   - "Bearer" with a token from the token service, unless acceptJWT is
//     false;
//   - an API token alone, with no scheme.
//
// Without an Authorization header, an API token in the X-NuGet-ApiKey
// header is used.
func (s *Service) authenticate(r *http.Request, acceptJWT bool) (credentials, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		if key := r.Header.Get(NuGetAPIKeyHeader); key != "" {
			p, err := s.checkAPIToken(strings.TrimSpace(key), "")
			return credentials{kind: credDirect, principal: p}, err
		}
		return credentials{kind: credNone, principal: anonymous}, nil
	}
	scheme, param, _ := strings.Cut(h, " ")
	param = strings.TrimSpace(param)
	switch {
	case strings.EqualFold(scheme, "Basic"):
		user, pw, ok := parseBasic(param)
		if !ok {
			return credentials{kind: credDirect}, ErrInvalidCredentials
		}
		p, err := s.checkBasic(r.Context(), user, pw)
		return credentials{kind: credDirect, principal: p}, err
	case strings.EqualFold(scheme, "Bearer") && strings.HasPrefix(param, tokenStringPrefix):
		p, err := s.checkAPIToken(param, "")
		return credentials{kind: credDirect, principal: p}, err
	case strings.EqualFold(scheme, "Bearer"):
		if !acceptJWT {
			return credentials{kind: credJWT}, ErrInvalidCredentials
		}
		p, c, err := s.checkJWT(param)
		return credentials{kind: credJWT, principal: p, jwt: c}, err
	case param == "" && strings.HasPrefix(scheme, tokenStringPrefix):
		p, err := s.checkAPIToken(scheme, "")
		return credentials{kind: credDirect, principal: p}, err
	}
	return credentials{kind: credDirect}, ErrInvalidCredentials
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
		return nil, ErrInvalidCredentials
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
		return nil, ErrInvalidCredentials
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
		return nil, ErrInvalidCredentials
	}
	t, err := s.getToken(id)
	if errors.Is(err, errNoSuchToken) {
		s.attempts.With("token", "failure").Inc()
		if owner != "" {
			return nil, errNoSuchToken
		}
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(sum[:], t.Hash) != 1 || (owner != "" && owner != t.Owner) {
		s.attempts.With("token", "failure").Inc()
		return nil, ErrInvalidCredentials
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
		return nil, ErrInvalidCredentials
	}
	u, err := s.getUser(t.Owner)
	if errors.Is(err, errNoSuchUser) {
		return nil, ErrInvalidCredentials
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
		return nil, nil, ErrInvalidCredentials
	}
	p := anonymous
	switch {
	case c.TokenID != "":
		t, terr := s.getToken(c.TokenID)
		if terr == nil && t.Owner == c.Subject {
			p, err = s.tokenPrincipal(t)
		} else if terr == nil || errors.Is(terr, errNoSuchToken) {
			err = ErrInvalidCredentials
		} else {
			err = terr
		}
	case c.Subject != "":
		var u *user
		u, err = s.getUser(c.Subject)
		if errors.Is(err, errNoSuchUser) {
			err = ErrInvalidCredentials
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

// Authorize reports whether the request may perform every action ("pull",
// "push", "delete") on repository repo, a flint repository or a path
// within one. When it returns false it has written the response: 401 with
// a Docker-compatible Bearer challenge naming the scope the client needs a
// token for, or 403 if the client presented a password or an API token
// that lacks the permission. It is the registry API's authorizer; other
// route families use an Authorizer with their own challenge style.
//
// With repo empty and no actions, it checks only that the request carries
// valid credentials, a bearer token from the token service included, as
// the registry's base endpoint needs for "docker login".
//
// When it returns true, it records the principal in r's context for Actor.
func (s *Service) Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool {
	return s.docker.Authorize(w, r, repo, actions...)
}

// Allowed reports whether the request's credentials permit every action
// on repo, without writing a response; for example, to filter a listing
// or to decide whether a cross-repository mount may read its source.
// Invalid credentials permit nothing.
func (s *Service) Allowed(r *http.Request, repo string, actions ...string) bool {
	return s.docker.Allowed(r, repo, actions...)
}

// AuthorizeVirtual is Authorize for a path within a virtual repository,
// with Authorizer.AuthorizeVirtual's rule: pulling needs read on the
// virtual repository, and pushing and deleting need write and delete on
// publishTo, the same path within its publishTo member. The challenge
// names the virtual repository's path, the scope Docker clients ask the
// token service for, which grants a push on it for the role on
// publishTo.
func (s *Service) AuthorizeVirtual(w http.ResponseWriter, r *http.Request, virtual, publishTo string, actions ...string) bool {
	return s.docker.AuthorizeVirtual(w, r, virtual, publishTo, actions...)
}

// Permit reports, as an HTTP status, whether the request's credentials,
// or their absence, allow every action on repository repo, for clients
// that authenticate with basic credentials on every request, such as
// PyPI clients: http.StatusOK; StatusUnauthorized when the
// request has no valid credentials and needs some; StatusForbidden when
// its credentials lack the permission; or StatusInternalServerError.
// Bearer tokens from the token service are not accepted. The caller
// writes the response. With StatusOK, Permit records the principal in
// r's context for Actor.
func (s *Service) Permit(r *http.Request, repo string, actions ...string) int {
	c, err := s.authenticate(r, false)
	switch {
	case err != nil && !errors.Is(err, ErrInvalidCredentials):
		s.log.Error("authentication failed", "err", err)
		return http.StatusInternalServerError
	case err != nil:
		return http.StatusUnauthorized
	case !s.permits(c, checksFor(repo, actions)):
		if c.kind == credNone {
			return http.StatusUnauthorized
		}
		return http.StatusForbidden
	}
	admit(r, c.principal)
	return http.StatusOK
}

type principalKey struct{}

// Actor names the principal Authorize admitted r as, for the origin of the
// metadata batches the request writes: the user, the user and API token,
// or meta.ActorAnonymous.
func (s *Service) Actor(r *http.Request) string {
	p := PrincipalOf(r)
	if p == nil || p.User == "" {
		return meta.ActorAnonymous
	}
	return actorOf(p)
}

// PrincipalOf returns the principal an authorizer admitted r as, or nil
// if none has.
func PrincipalOf(r *http.Request) *Principal {
	p, _ := r.Context().Value(principalKey{}).(*Principal)
	return p
}

// admit records that r is admitted as p, in the log and in r's context.
func admit(r *http.Request, p *Principal) {
	logPrincipal(r.Context(), p)
	*r = *r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}

// catalogScope is the token scope that lists repositories.
const catalogScope = "registry:catalog:*"

// AuthorizeCatalog decides whether the request may list repositories, for
// GET /v2/_catalog. Like Authorize, it writes a 401 Bearer challenge, for
// the scope "registry:catalog:*", when the request has no valid
// credentials or its token lacks that scope; any client, anonymous ones
// included, can obtain that scope. The returned filter shows only the
// repositories the client may pull from.
func (s *Service) AuthorizeCatalog(w http.ResponseWriter, r *http.Request) (func(repo string) bool, bool) {
	c, err := s.authenticate(r, true)
	switch {
	case err != nil && !errors.Is(err, ErrInvalidCredentials):
		s.log.Error("authentication failed", "err", err)
		writeRegistryError(w, http.StatusInternalServerError, "UNKNOWN", "internal error")
		return nil, false
	case err != nil:
		s.challenge(w, r, catalogScope, "invalid_token")
		return nil, false
	case c.kind == credNone:
		s.challenge(w, r, catalogScope, "")
		return nil, false
	case c.kind == credJWT && !c.jwt.allowsCatalog():
		s.challenge(w, r, catalogScope, "insufficient_scope")
		return nil, false
	}
	logPrincipal(r.Context(), c.principal)
	return func(repo string) bool { return s.Role(c.principal, repo) >= RoleRead }, true
}

// repoScope is the token scope for actions on repository repo.
func repoScope(repo string, actions []string) string {
	if repo == "" {
		return ""
	}
	return "repository:" + repo + ":" + strings.Join(actions, ",")
}

// challenge writes a 401 response with a Bearer challenge pointing at the
// token endpoint, naming scope if it is not empty.
func (s *Service) challenge(w http.ResponseWriter, r *http.Request, scope, errCode string) {
	v := fmt.Sprintf(`Bearer realm="%s",service="%s"`, s.realm(r), Issuer)
	if scope != "" {
		v += fmt.Sprintf(`,scope="%s"`, scope)
	}
	if errCode != "" {
		v += fmt.Sprintf(`,error="%s"`, errCode)
	}
	w.Header().Set("WWW-Authenticate", v)
	writeRegistryError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
}

// realm returns the token endpoint's URL as the client addresses this
// server, honoring trusted proxies. It ignores the public URL: a client
// that reached flint by another name, such as an internal service name,
// must get its token from the host it is already talking to.
func (s *Service) realm(r *http.Request) string {
	return server.Origin(r) + TokenPath
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
