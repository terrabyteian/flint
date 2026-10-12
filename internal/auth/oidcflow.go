package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/server"
)

// The sign-in flow through a provider:
//
//  1. GET /auth/oidc/<provider>/login?return=<path> picks a random state,
//     nonce, and PKCE verifier, seals the pending sign-in into a
//     short-lived cookie that binds it to this browser, and redirects to
//     the provider's authorization endpoint.
//  2. The provider redirects back to GET /auth/oidc/<provider>/callback
//     with the state and a code. The cookie must open under the state and
//     the provider and be unexpired; the callback clears it, so a sign-in
//     completes once in a browser, and the provider redeems a code once.
//  3. flint redeems the code with the verifier, verifies the ID token and
//     its nonce, applies the provider's restrictions, finds or creates the
//     user, syncs the user's groups, starts a session, and redirects to
//     the return path.
//
// flint keeps no state for pending sign-ins: the cookie is sealed with
// AES-256-GCM under the OIDC state key, so a sign-in in progress survives
// a restart, and replacing the key invalidates them all.

// Paths of the OIDC endpoints, under /auth/oidc/<provider>/.
const (
	oidcPathPrefix = "/auth/oidc/"
	oidcLoginPath  = "/login"
	oidcCallback   = "/callback"
)

// oidcBindingCookie holds a pending sign-in, sealed, in the browser that
// started it.
const oidcBindingCookie = "flint_oidc"

// oidcStateKeyFileName is the file in the key directory of the key that
// seals pending sign-ins.
const oidcStateKeyFileName = "oidc-state.key"

// pendingTTL bounds how long a user may take at the provider.
const pendingTTL = 10 * time.Minute

// oidcService holds the configured providers and the key that seals
// pending sign-ins.
type oidcService struct {
	providers map[string]*oidcProvider
	order     []string // provider names, as configured
	aead      cipher.AEAD
}

// pendingSignIn is a sign-in waiting for the provider's callback.
type pendingSignIn struct {
	nonce       string
	verifier    string
	redirectURI string
	returnTo    string
	expires     time.Time
}

func newOIDCService(providers []config.OIDCProvider, stateKey []byte, transport http.RoundTripper, now func() time.Time, log *slog.Logger) (*oidcService, error) {
	block, err := aes.NewCipher(stateKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	o := &oidcService{providers: map[string]*oidcProvider{}, aead: aead}
	for _, cfg := range providers {
		p, err := newOIDCProvider(cfg, transport, now, log)
		if err != nil {
			return nil, err
		}
		o.providers[cfg.Name] = p
		o.order = append(o.order, cfg.Name)
	}
	return o, nil
}

// seal returns ps sealed for the cookie, bound to provider and state.
func (o *oidcService) seal(provider, state string, ps *pendingSignIn) string {
	plain := binary.AppendVarint(nil, ps.expires.Unix())
	for _, f := range []string{ps.nonce, ps.verifier, ps.redirectURI, ps.returnTo} {
		plain = binary.AppendUvarint(plain, uint64(len(f)))
		plain = append(plain, f...)
	}
	nonce := make([]byte, o.aead.NonceSize())
	rand.Read(nonce)
	return b64.EncodeToString(o.aead.Seal(nonce, nonce, plain, sealedData(provider, state)))
}

// open returns the pending sign-in sealed in v, or nil if v was not
// sealed by seal for provider and state.
func (o *oidcService) open(provider, state, v string) *pendingSignIn {
	b, err := b64.DecodeString(v)
	n := o.aead.NonceSize()
	if err != nil || len(b) < n {
		return nil
	}
	plain, err := o.aead.Open(nil, b[:n], b[n:], sealedData(provider, state))
	if err != nil {
		return nil
	}
	expires, k := binary.Varint(plain)
	if k <= 0 {
		return nil
	}
	plain = plain[k:]
	var f [4]string
	for i := range f {
		l, k := binary.Uvarint(plain)
		if k <= 0 || l > uint64(len(plain)-k) {
			return nil
		}
		f[i], plain = string(plain[k:k+int(l)]), plain[k+int(l):]
	}
	return &pendingSignIn{nonce: f[0], verifier: f[1], redirectURI: f[2], returnTo: f[3], expires: time.Unix(expires, 0)}
}

// sealedData is the additional data a pending sign-in for provider and
// state is sealed with.
func sealedData(provider, state string) []byte {
	return []byte("flint oidc\x00" + provider + "\x00" + state)
}

// providerFor returns the provider an OIDC endpoint's path names.
func (s *Service) providerFor(w http.ResponseWriter, r *http.Request) *oidcProvider {
	var p *oidcProvider
	if s.oidc != nil {
		p = s.oidc.providers[r.PathValue("provider")]
	}
	if p == nil {
		s.signInError(w, r, http.StatusNotFound, "There is no such sign-in provider.")
	}
	return p
}

// handleOIDCLogin starts a sign-in through a provider.
func (s *Service) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := s.providerFor(w, r)
	if p == nil {
		return
	}
	d, err := p.discovery(r.Context())
	if err != nil {
		p.log.Error("OIDC sign-in failed: the provider is unavailable", "err", err)
		s.signInError(w, r, http.StatusBadGateway, "The sign-in provider is unavailable. Try again later.")
		return
	}
	state, nonce, verifier := rand.Text(), rand.Text(), randomURLSafe(32)
	ps := &pendingSignIn{
		nonce:       nonce,
		verifier:    verifier,
		redirectURI: server.BaseURL(r) + oidcPathPrefix + p.cfg.Name + oidcCallback,
		returnTo:    returnPath(r, r.URL.Query().Get("return")),
		expires:     s.now().Add(pendingTTL),
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcBindingCookie,
		Value:    s.oidc.seal(p.cfg.Name, state, ps),
		Path:     bindingPath(r, p),
		MaxAge:   int(pendingTTL / time.Second),
		Secure:   secureCookie(r),
		HttpOnly: true,
		// The provider's redirect back is a top-level navigation from
		// another site, which Lax cookies accompany.
		SameSite: http.SameSiteLaxMode,
	})
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {ps.redirectURI},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {b64.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	if hd := p.cfg.HostedDomains; len(hd) == 1 && len(p.cfg.AllowedEmails) == 0 {
		// A hint for Google's account chooser, which would hide the
		// accounts allowedEmails admits; the ID token's hd claim is what
		// flint checks.
		q.Set("hd", hd[0])
	}
	target := d.AuthorizationEndpoint
	if strings.Contains(target, "?") {
		target += "&" + q.Encode()
	} else {
		target += "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// bindingPath is the path of p's binding cookie, as the browser sees
// it: under the public URL's path, if a reverse proxy serves flint under
// one.
func bindingPath(r *http.Request, p *oidcProvider) string {
	prefix := ""
	if u, err := url.Parse(server.BaseURL(r)); err == nil {
		prefix = strings.TrimSuffix(u.Path, "/")
	}
	return prefix + oidcPathPrefix + p.cfg.Name + "/"
}

// randomURLSafe returns n random bytes in base64url, as a PKCE code
// verifier.
func randomURLSafe(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return b64.EncodeToString(b)
}

// handleOIDCCallback completes a sign-in through a provider.
func (s *Service) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := s.providerFor(w, r)
	if p == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcBindingCookie, Value: "", Path: bindingPath(r, p), MaxAge: -1,
		Secure: secureCookie(r), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	q := r.URL.Query()
	c, cerr := r.Cookie(oidcBindingCookie)
	var ps *pendingSignIn
	if cerr == nil {
		ps = s.oidc.open(p.cfg.Name, q.Get("state"), c.Value)
	}
	const stale = "This sign-in has expired, was already used, or was started in another browser. Sign in again."
	switch {
	case cerr != nil:
		s.oidcFailure(w, r, p, "the browser has no sign-in in progress", stale)
		return
	case ps == nil:
		s.oidcFailure(w, r, p, "the browser's sign-in is not for this state", stale)
		return
	case !s.now().Before(ps.expires):
		s.oidcFailure(w, r, p, "the sign-in expired", stale)
		return
	case q.Get("error") != "":
		s.oidcFailure(w, r, p, "the provider refused: "+printable(q.Get("error"))+" "+printable(q.Get("error_description")),
			"The sign-in provider did not sign you in.")
		return
	case q.Get("code") == "":
		s.oidcFailure(w, r, p, "the callback has no code", "The sign-in provider did not sign you in.")
		return
	}
	// An issuer parameter, if sent, must be the provider's (RFC 9207).
	if iss := q.Get("iss"); iss != "" && iss != p.cfg.Issuer {
		s.oidcFailure(w, r, p, "the callback names issuer "+printable(iss), "The sign-in provider did not sign you in.")
		return
	}
	d, err := p.discovery(r.Context())
	if err != nil {
		s.oidcFailure(w, r, p, err.Error(), "The sign-in provider is unavailable. Try again later.")
		return
	}
	raw, err := p.exchange(r.Context(), d, q.Get("code"), ps.verifier, ps.redirectURI)
	if err != nil {
		s.oidcFailure(w, r, p, err.Error(), "The sign-in could not be completed. Sign in again.")
		return
	}
	claims, err := p.verifyIDToken(r.Context(), d, raw, ps.nonce)
	if err != nil {
		s.oidcFailure(w, r, p, err.Error(), "The sign-in could not be completed. Sign in again.")
		return
	}
	name, err := s.oidcUser(r.Context(), p, claims)
	var denied *signInDenied
	switch {
	case errors.As(err, &denied):
		s.oidcFailure(w, r, p, denied.reason, denied.msg)
		return
	case err != nil:
		p.log.Error("OIDC sign-in failed", "subject", claims.Subject, "err", err)
		s.signInError(w, r, http.StatusInternalServerError, "The sign-in failed because of an internal error.")
		return
	}
	if err := s.startSession(r.Context(), w, r, name, "oidc:"+p.cfg.Name); err != nil {
		p.log.Error("starting a session failed", "user", name, "err", err)
		s.signInError(w, r, http.StatusInternalServerError, "The sign-in failed because of an internal error.")
		return
	}
	s.attempts.With("oidc", "success").Inc()
	p.log.Info("signed in through OIDC", "user", name, "subject", claims.Subject)
	http.Redirect(w, r, ps.returnTo, http.StatusSeeOther)
}

// oidcFailure logs why a sign-in through p failed and shows the user msg.
func (s *Service) oidcFailure(w http.ResponseWriter, r *http.Request, p *oidcProvider, reason, msg string) {
	s.attempts.With("oidc", "failure").Inc()
	p.log.Warn("OIDC sign-in refused", "reason", reason)
	s.signInError(w, r, http.StatusForbidden, msg)
}

// signInDenied is a sign-in the provider's settings or flint's users
// refuse. reason is logged; msg is shown to the user.
type signInDenied struct{ reason, msg string }

func (e *signInDenied) Error() string { return e.reason }

// oidcUser applies p's restrictions to a verified identity, then finds
// the user the identity signs in as, linking the user an administrator
// assigned its verified Google email to or creating one on the first
// sign-in, and syncs its groups and, with adminGroups, its admin flag. It
// returns the user's name.
func (s *Service) oidcUser(ctx context.Context, p *oidcProvider, c *idClaims) (string, error) {
	cfg := &p.cfg
	var idpGroups []string
	if cfg.SyncsGroups() {
		var err error
		if idpGroups, err = c.Groups(cfg.GroupsClaim); err != nil {
			return "", &signInDenied{err.Error(), "The sign-in provider sent invalid group information."}
		}
	}
	email := strings.ToLower(c.String("email"))
	verified := email != "" && c.EmailVerified()
	if cfg.IsGoogle() && !verified {
		return "", &signInDenied{fmt.Sprintf("email %q is missing or not verified", printable(email)),
			"Your Google account's email address is not verified."}
	}
	if !admitted(cfg, c, email, verified) {
		return "", &signInDenied{fmt.Sprintf("email %q (verified: %t, hosted domain %q) is not allowed", printable(email), verified,
			printable(c.String("hd"))), "Your account is not allowed to sign in here."}
	}
	if len(cfg.AllowedGroups) > 0 && !slices.ContainsFunc(idpGroups, func(g string) bool { return slices.Contains(cfg.AllowedGroups, g) }) {
		return "", &signInDenied{"the user is in none of the allowed groups", "Your account is not allowed to sign in here."}
	}
	groups, admin, setAdmin := mapGroups(cfg, idpGroups)

	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.store.View()
	defer v.Release()
	b := new(meta.Batch)
	var u *user
	var ver meta.Seq
	var err error
	action := "auth.oidc.user.sync"
	if rec, ok := v.Get(oidcKey(cfg.Issuer, c.Subject)); ok {
		name := string(rec.Value)
		b.Require(oidcKey(cfg.Issuer, c.Subject), rec.Version)
		if u, ver, err = readUser(v, name); err != nil {
			return "", err
		}
	} else if rec, ok := v.Get(oidcEmailKey(cfg.Issuer, email)); ok && cfg.IsGoogle() && verified {
		// An administrator assigned this verified Google email to a user,
		// which this identity's first sign-in links it to. Other providers
		// match identities by issuer and subject only.
		name := string(rec.Value)
		if u, ver, err = readUser(v, name); err != nil {
			return "", err
		}
		if u.OIDC == nil || u.OIDC.Issuer != cfg.Issuer || u.OIDC.Subject != "" || u.OIDC.Email != email {
			return "", fmt.Errorf("user %q is not assigned the email that names it", name)
		}
		b.Require(oidcEmailKey(cfg.Issuer, email), rec.Version)
		b.Delete(oidcEmailKey(cfg.Issuer, email))
		b.Require(oidcKey(cfg.Issuer, c.Subject), 0)
		b.Put(oidcKey(cfg.Issuer, c.Subject), []byte(name))
		u.OIDC.Subject, u.OIDC.Email = c.Subject, ""
		action = "auth.oidc.user.link"
	} else {
		name := c.String(cfg.UsernameClaim)
		if cfg.UsernameClaim == "email" && !verified {
			name = ""
		}
		name = strings.ToLower(name)
		if !config.ValidUserName(name) {
			return "", &signInDenied{fmt.Sprintf("claim %s gives no valid user name: %q", cfg.UsernameClaim, printable(name)),
				"Your account has no user name flint can use. Ask an administrator."}
		}
		if _, _, err := readUser(v, name); err == nil {
			return "", &signInDenied{fmt.Sprintf("user %q already exists and is not this identity", name),
				"The user name " + name + " is taken by another user. Ask an administrator."}
		} else if !errors.Is(err, errNoSuchUser) {
			return "", err
		}
		u = &user{Name: name, Created: s.now().Truncate(time.Second),
			OIDC: &oidcIdentity{Provider: cfg.Name, Issuer: cfg.Issuer, Subject: c.Subject}}
		b.Require(oidcKey(cfg.Issuer, c.Subject), 0)
		b.Put(oidcKey(cfg.Issuer, c.Subject), []byte(name))
		action = "auth.oidc.user.create"
	}
	if u.OIDC == nil || u.OIDC.Issuer != cfg.Issuer || u.OIDC.Subject != c.Subject {
		return "", fmt.Errorf("user %q is not linked to the OIDC identity that names it", u.Name)
	}
	before := u.encode()
	if cfg.SyncsGroups() {
		u.Groups = groups
	}
	u.OIDC.Provider = cfg.Name
	if setAdmin && u.Admin && !admin {
		n, err := requireAdmins(v, b)
		if err != nil {
			return "", err
		}
		if n <= 1 {
			p.log.Warn("not demoting the last administrator, who is no longer in an admin group", "user", u.Name)
			admin = true
		}
	}
	if setAdmin {
		u.Admin = admin
	}
	after := u.encode()
	if action == "auth.oidc.user.sync" && string(before) == string(after) {
		return u.Name, nil
	}
	b.Require(userKey(u.Name), ver)
	b.Put(userKey(u.Name), after)
	if err := s.commit(ctx, b, &Principal{User: u.Name}, action, "user "+u.Name); err != nil {
		return "", err
	}
	return u.Name, nil
}

// admitted reports whether p's allowedDomains, or Google's allowedEmails
// and hostedDomains, admit a user: if any is set, the user must match one
// of them, with a verified email for the first two.
func admitted(cfg *config.OIDCProvider, c *idClaims, email string, verified bool) bool {
	if len(cfg.AllowedDomains) == 0 && len(cfg.AllowedEmails) == 0 && len(cfg.HostedDomains) == 0 {
		return true
	}
	_, domain, _ := strings.Cut(email, "@")
	return verified && (slices.Contains(cfg.AllowedDomains, domain) || slices.Contains(cfg.AllowedEmails, email)) ||
		slices.Contains(cfg.HostedDomains, c.String("hd"))
}

// mapGroups maps a user's groups at a provider to flint groups, and
// reports whether they make the user an administrator and whether the
// provider manages the admin flag at all.
func mapGroups(cfg *config.OIDCProvider, idpGroups []string) (groups []string, admin, setAdmin bool) {
	groups = []string{}
	for _, g := range idpGroups {
		groups = append(groups, cfg.GroupMappings[g]...)
		if lg := strings.ToLower(g); cfg.ImportGroups && config.ValidUserName(lg) {
			groups = append(groups, lg)
		}
		if slices.Contains(cfg.AdminGroups, g) {
			admin = true
		}
	}
	slices.Sort(groups)
	return slices.Compact(groups), admin, len(cfg.AdminGroups) > 0
}

// returnPath returns where to send the browser after signing in: ret if
// it is a path on this server, or else the sign-in page.
func returnPath(r *http.Request, ret string) string {
	if ret != "" && len(ret) <= 2048 && strings.HasPrefix(ret, "/") && !strings.HasPrefix(ret, "//") &&
		!strings.ContainsAny(ret, "\\\x00\r\n\t") {
		if u, err := url.Parse(ret); err == nil && u.Scheme == "" && u.Host == "" {
			return ret
		}
	}
	return server.BaseURL(r) + SignInPath
}
