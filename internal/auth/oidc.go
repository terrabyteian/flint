package auth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/config"
)

// flint is an OpenID Connect relying party for its sign-in page, with the
// authorization code flow, PKCE (S256), state, and nonce. A provider's
// discovery document and key set are fetched when a user first signs in
// through it, not at startup, so flint starts while a provider is down.
// The ID token from the token endpoint is verified by hand: its
// signature with a key from the provider's key set (jose.go), its
// issuer, audience, authorized party, expiry, issue time, not-before
// time, and nonce. Users are identified by the issuer and the subject,
// never by email.

// Bounds of the OIDC client.
const (
	// oidcTimeout bounds each request to a provider.
	oidcTimeout = 15 * time.Second
	// maxOIDCResponse bounds a provider's discovery document, key set,
	// and token response.
	maxOIDCResponse = 1 << 20
	// discoveryTTL is how long a discovery document is used before it is
	// fetched again.
	discoveryTTL = time.Hour
	// jwksTTL is how long a key set is used before it is fetched again.
	jwksTTL = time.Hour
	// jwksMinRefresh is how soon after a fetch a token signed with an
	// unknown key may fetch the key set again, so tokens with made-up
	// key IDs cannot make flint hammer the provider.
	jwksMinRefresh = 30 * time.Second
	// oidcClockSkew is how far the provider's clock may be from flint's.
	oidcClockSkew = time.Minute
	// maxIDTokenAge bounds how long ago an ID token may have been issued:
	// flint verifies it right after the token endpoint issued it.
	maxIDTokenAge = 10 * time.Minute
	// maxSubjectLen is the longest subject accepted, as OIDC Core allows.
	maxSubjectLen = 255
)

// googleBareIssuer is the other form of Google's issuer that its ID
// tokens may carry.
const googleBareIssuer = "accounts.google.com"

// oidcProvider is one configured provider.
type oidcProvider struct {
	cfg    config.OIDCProvider
	client *http.Client
	now    func() time.Time
	log    *slog.Logger

	// fetch serializes fetching the discovery document and the key set.
	fetch sync.Mutex

	mu      sync.Mutex
	disc    *discovery
	discAt  time.Time
	keys    []verifyKey
	keysAt  time.Time
	keysURI string
}

// discovery is a provider's discovery document (OpenID Connect Discovery
// 1.0), as far as flint uses it.
type discovery struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	SigningAlgs              []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

func newOIDCProvider(cfg config.OIDCProvider, transport http.RoundTripper, now func() time.Time, log *slog.Logger) (*oidcProvider, error) {
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("auth: OIDC provider %s: reading caFile: %w", cfg.Name, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("auth: OIDC provider %s: caFile %s holds no PEM certificates", cfg.Name, cfg.CAFile)
			}
			t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
		transport = t
	}
	return &oidcProvider{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   oidcTimeout,
			// A provider's endpoints answer directly; following a redirect
			// could send the client secret elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: now,
		log: log.With("oidc_provider", cfg.Name),
	}, nil
}

// discovery returns the provider's discovery document, fetching it if it
// has none or its copy is older than discoveryTTL. If a refetch fails, it
// keeps using the copy it has.
func (p *oidcProvider) discovery(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	d, at := p.disc, p.discAt
	p.mu.Unlock()
	if d != nil && p.now().Sub(at) < discoveryTTL {
		return d, nil
	}
	p.fetch.Lock()
	defer p.fetch.Unlock()
	p.mu.Lock()
	d, at = p.disc, p.discAt
	p.mu.Unlock()
	if d != nil && p.now().Sub(at) < discoveryTTL {
		return d, nil
	}
	nd, err := p.fetchDiscovery(ctx)
	if err != nil {
		if d != nil {
			p.log.Warn("refreshing the OIDC discovery document failed; using the previous one", "err", err)
			return d, nil
		}
		return nil, err
	}
	p.mu.Lock()
	p.disc, p.discAt = nd, p.now()
	p.mu.Unlock()
	return nd, nil
}

func (p *oidcProvider) fetchDiscovery(ctx context.Context) (*discovery, error) {
	u := strings.TrimSuffix(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	b, err := p.get(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("fetching the discovery document: %w", err)
	}
	var d discovery
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("the discovery document at %s is not valid JSON: %w", u, err)
	}
	if d.Issuer != p.cfg.Issuer {
		// OIDC Discovery 4.3: the issuer must be exactly the one the
		// document was fetched for.
		return nil, fmt.Errorf("the discovery document names issuer %q, not %q", d.Issuer, p.cfg.Issuer)
	}
	for _, e := range []struct{ name, url string }{
		{"authorization_endpoint", d.AuthorizationEndpoint},
		{"token_endpoint", d.TokenEndpoint},
		{"jwks_uri", d.JWKSURI},
	} {
		if err := checkEndpoint(e.url); err != nil {
			return nil, fmt.Errorf("the discovery document's %s %q %v", e.name, e.url, err)
		}
	}
	return &d, nil
}

// checkEndpoint checks a provider endpoint's URL: https, or http to a
// loopback address, with a host and no credentials or fragment.
func checkEndpoint(s string) error {
	u, err := url.Parse(s)
	switch {
	case s == "":
		return errors.New("is missing")
	case err != nil:
		return errors.New("is not a URL")
	case u.Host == "":
		return errors.New("has no host")
	case u.User != nil || u.Fragment != "":
		return errors.New("must not have credentials or a fragment")
	case u.Scheme == "https", u.Scheme == "http" && config.IsLoopback(u.Hostname()):
		return nil
	}
	return errors.New("must be an https URL")
}

// get fetches a provider document.
func (p *oidcProvider) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := readLimited(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return b, nil
}

// readLimited reads a provider response of at most maxOIDCResponse bytes.
func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxOIDCResponse+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxOIDCResponse {
		return nil, fmt.Errorf("the response is larger than %d bytes", maxOIDCResponse)
	}
	return b, nil
}

// keySet returns the provider's signing keys from the key set at uri,
// fetching it if it has none from uri or its copy is older than jwksTTL,
// or, with refresh, if its copy is older than jwksMinRefresh. If a
// refetch fails, it keeps using the copy it has.
func (p *oidcProvider) keySet(ctx context.Context, uri string, refresh bool) ([]verifyKey, error) {
	fresh := func() ([]verifyKey, bool) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.keysURI != uri || p.keysAt.IsZero() {
			return nil, false
		}
		age := p.now().Sub(p.keysAt)
		return p.keys, age < jwksTTL && (!refresh || age < jwksMinRefresh)
	}
	keys, ok := fresh()
	if ok {
		return keys, nil
	}
	p.fetch.Lock()
	defer p.fetch.Unlock()
	if keys, ok = fresh(); ok {
		return keys, nil
	}
	b, err := p.get(ctx, uri)
	var nk []verifyKey
	if err == nil {
		nk, err = parseJWKS(b)
	}
	if err != nil {
		err = fmt.Errorf("fetching the key set: %w", err)
		if keys != nil {
			p.log.Warn("refreshing the OIDC key set failed; using the previous one", "err", err)
			return keys, nil
		}
		return nil, err
	}
	p.mu.Lock()
	p.keys, p.keysAt, p.keysURI = nk, p.now(), uri
	p.mu.Unlock()
	return nk, nil
}

// allowedAlgs returns the ID token signature algorithms accepted: the
// configured ones, or else those the discovery document lists that flint
// supports, or else RS256, which every provider must support.
func (p *oidcProvider) allowedAlgs(d *discovery) []string {
	if p.cfg.SigningAlgorithms != nil {
		return p.cfg.SigningAlgorithms
	}
	var algs []string
	for _, a := range d.SigningAlgs {
		if slices.Contains(supportedAlgs, a) {
			algs = append(algs, a)
		}
	}
	if len(d.SigningAlgs) == 0 {
		algs = []string{"RS256"}
	}
	return algs
}

// clientSecret reads the client secret, or returns "" for a public
// client.
func (p *oidcProvider) clientSecret() (string, error) {
	if p.cfg.ClientSecretFile == "" {
		return "", nil
	}
	b, err := os.ReadFile(p.cfg.ClientSecretFile)
	if err != nil {
		return "", fmt.Errorf("reading the client secret: %w", err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}

// exchange redeems an authorization code at the token endpoint and
// returns the ID token.
func (p *oidcProvider) exchange(ctx context.Context, d *discovery, code, verifier, redirectURI string) (string, error) {
	secret, err := p.clientSecret()
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	// client_secret_basic is the default; client_secret_post is used
	// only for a provider that says it supports that and not the other.
	post := secret != "" && len(d.TokenEndpointAuthMethods) > 0 &&
		!slices.Contains(d.TokenEndpointAuthMethods, "client_secret_basic") &&
		slices.Contains(d.TokenEndpointAuthMethods, "client_secret_post")
	if secret == "" || post {
		form.Set("client_id", p.cfg.ClientID)
	}
	if post {
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if secret != "" && !post {
		// RFC 6749, section 2.3.1: the client ID and secret are
		// form-encoded before they are joined for basic authentication.
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(secret))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	b, err := readLimited(resp.Body)
	if err != nil {
		return "", fmt.Errorf("token response: %w", err)
	}
	var tr struct {
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	jerr := json.Unmarshal(b, &tr)
	switch {
	case resp.StatusCode != http.StatusOK && tr.Error != "":
		return "", fmt.Errorf("the token endpoint refused the code: %s %s", printable(tr.Error), printable(tr.Description))
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("the token endpoint answered %s", resp.Status)
	case jerr != nil:
		return "", fmt.Errorf("the token response is not valid JSON: %w", jerr)
	case tr.IDToken == "":
		return "", errors.New("the token response has no ID token")
	}
	return tr.IDToken, nil
}

// printable shortens a provider's error text for the log, keeping
// printable ASCII only.
func printable(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// idClaims are a verified ID token's claims.
type idClaims struct {
	Subject string
	// all holds every claim, for the configured username and groups
	// claims.
	all map[string]json.RawMessage
}

// verifyIDToken verifies an ID token and returns its claims.
func (p *oidcProvider) verifyIDToken(ctx context.Context, d *discovery, raw, nonce string) (*idClaims, error) {
	keys, err := p.keySet(ctx, d.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	algs := p.allowedAlgs(d)
	payload, err := verifyJWS(raw, keys, algs)
	if errors.Is(err, errUnknownKey) {
		// The provider may have rotated its keys since the set was
		// fetched.
		if keys, err = p.keySet(ctx, d.JWKSURI, true); err != nil {
			return nil, err
		}
		payload, err = verifyJWS(raw, keys, algs)
	}
	if err != nil {
		return nil, fmt.Errorf("the ID token: %w", err)
	}
	c, err := p.checkClaims(payload, nonce)
	if err != nil {
		return nil, fmt.Errorf("the ID token: %w", err)
	}
	return c, nil
}

// checkClaims checks a verified ID token's claims (OpenID Connect Core
// 1.0, section 3.1.3.7).
func (p *oidcProvider) checkClaims(payload []byte, nonce string) (*idClaims, error) {
	var all map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&all); err != nil || all == nil {
		return nil, errors.New("the claims are not a JSON object")
	}
	str := func(name string) (string, bool) {
		var s string
		raw, ok := all[name]
		return s, ok && json.Unmarshal(raw, &s) == nil
	}
	date := func(name string) (int64, bool, error) {
		raw, ok := all[name]
		if !ok {
			return 0, false, nil
		}
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return 0, true, fmt.Errorf("%s is not a number", name)
		}
		f, err := n.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1e15 {
			return 0, true, fmt.Errorf("%s is not a valid time", name)
		}
		return int64(math.Floor(f)), true, nil
	}

	// Google's ID tokens may name its issuer without the scheme.
	if iss, _ := str("iss"); iss != p.cfg.Issuer && !(p.cfg.IsGoogle() && iss == googleBareIssuer) {
		return nil, fmt.Errorf("issuer %q is not %q", iss, p.cfg.Issuer)
	}
	var aud []string
	if raw, ok := all["aud"]; ok {
		var one string
		if json.Unmarshal(raw, &one) == nil {
			aud = []string{one}
		} else if json.Unmarshal(raw, &aud) != nil {
			return nil, errors.New("aud is not a string or an array of strings")
		}
	}
	if !slices.Contains(aud, p.cfg.ClientID) {
		return nil, fmt.Errorf("the audience %q does not include client ID %q", aud, p.cfg.ClientID)
	}
	azp, hasAZP := str("azp")
	if _, present := all["azp"]; present && (!hasAZP || azp != p.cfg.ClientID) || len(aud) > 1 && !hasAZP {
		return nil, fmt.Errorf("the authorized party %q is not client ID %q", azp, p.cfg.ClientID)
	}

	now := p.now()
	skew := int64(oidcClockSkew / time.Second)
	t := now.Unix()
	exp, ok, err := date("exp")
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, errors.New("exp is missing")
	case t >= exp+skew:
		return nil, errors.New("it has expired")
	}
	iat, ok, err := date("iat")
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, errors.New("iat is missing")
	case iat > t+skew:
		return nil, errors.New("it was issued in the future")
	case iat < t-int64(maxIDTokenAge/time.Second)-skew:
		return nil, errors.New("it was issued too long ago")
	}
	if nbf, ok, err := date("nbf"); err != nil {
		return nil, err
	} else if ok && nbf > t+skew {
		return nil, errors.New("it is not valid yet")
	}
	got, _ := str("nonce")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, errors.New("the nonce does not match this sign-in")
	}
	sub, _ := str("sub")
	if sub == "" || len(sub) > maxSubjectLen || strings.ContainsFunc(sub, func(r rune) bool { return r < ' ' }) {
		return nil, errors.New("sub is missing or invalid")
	}
	return &idClaims{Subject: sub, all: all}, nil
}

// String returns a string claim, or "" if it is missing or not a string.
func (c *idClaims) String(name string) string {
	var s string
	if raw, ok := c.all[name]; ok && json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// EmailVerified reports whether the email_verified claim is true, as a
// boolean or, as some providers send it, a string.
func (c *idClaims) EmailVerified() bool {
	raw, ok := c.all["email_verified"]
	if !ok {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	return json.Unmarshal(raw, &s) == nil && s == "true"
}

// Groups returns a claim that lists groups: an array of strings, or one
// string. A missing claim is no groups; a claim of another type is an
// error.
func (c *idClaims) Groups(name string) ([]string, error) {
	raw, ok := c.all[name]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("the %s claim is not a string or an array of strings", name)
	}
	return list, nil
}
