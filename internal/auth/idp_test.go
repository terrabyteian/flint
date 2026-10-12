package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/config"
)

// testKey is a signing key of the test provider.
type testKey struct {
	kid  string
	alg  string
	priv crypto.Signer
}

var (
	rsaKeyOnce sync.Once
	rsaKeys    [2]*rsa.PrivateKey
)

// testRSAKey returns one of two RSA keys, generated once per test run.
func testRSAKey(i int) *rsa.PrivateKey {
	rsaKeyOnce.Do(func() {
		for j := range rsaKeys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			rsaKeys[j] = k
		}
	})
	return rsaKeys[i]
}

func newRSATestKey(kid, alg string, i int) testKey {
	return testKey{kid: kid, alg: alg, priv: testRSAKey(i)}
}

func newECTestKey(t *testing.T, kid string, curve elliptic.Curve, alg string) testKey {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{kid: kid, alg: alg, priv: k}
}

func newEdTestKey(t *testing.T, kid string) testKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{kid: kid, alg: "EdDSA", priv: k}
}

// jwkOf returns the public JWK of a key.
func jwkOf(k testKey) map[string]any {
	m := map[string]any{"kid": k.kid, "use": "sig", "alg": k.alg}
	switch pub := k.priv.Public().(type) {
	case *rsa.PublicKey:
		m["kty"] = "RSA"
		m["n"] = b64.EncodeToString(pub.N.Bytes())
		m["e"] = b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().BitSize + 7) / 8
		b, _ := pub.Bytes()
		m["kty"] = "EC"
		m["crv"] = pub.Curve.Params().Name
		m["x"] = b64.EncodeToString(b[1 : 1+size])
		m["y"] = b64.EncodeToString(b[1+size:])
	case ed25519.PublicKey:
		m["kty"] = "OKP"
		m["crv"] = "Ed25519"
		m["x"] = b64.EncodeToString(pub)
	}
	return m
}

// signJWT signs claims with k, with header fields hdr added.
func signJWT(t *testing.T, k testKey, claims map[string]any, hdr map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": k.alg, "kid": k.kid, "typ": "JWT"}
	for name, v := range hdr {
		if v == nil {
			delete(h, name)
		} else {
			h[name] = v
		}
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	msg := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	return msg + "." + b64.EncodeToString(rawSign(t, k, []byte(msg)))
}

// rawSign makes a JWS signature over msg with k's algorithm.
func rawSign(t *testing.T, k testKey, msg []byte) []byte {
	t.Helper()
	if k.alg == "EdDSA" {
		return ed25519.Sign(k.priv.(ed25519.PrivateKey), msg)
	}
	hash := algHash(k.alg)
	h := hash.New()
	h.Write(msg)
	digest := h.Sum(nil)
	switch priv := k.priv.(type) {
	case *rsa.PrivateKey:
		var sig []byte
		var err error
		if strings.HasPrefix(k.alg, "PS") {
			sig, err = rsa.SignPSS(rand.Reader, priv, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, priv, hash, digest)
		}
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			t.Fatal(err)
		}
		size := (priv.Curve.Params().BitSize + 7) / 8
		sig := make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
		return sig
	}
	t.Fatalf("unsupported key %T", k.priv)
	return nil
}

// idp is an in-test OpenID Connect provider. Its authorization endpoint
// signs in the configured user at once and redirects back with a code.
type idp struct {
	t   *testing.T
	srv *httptest.Server
	now func() time.Time

	mu sync.Mutex
	// keys are published in the key set; signer signs ID tokens.
	keys   []testKey
	signer testKey
	// subject and claims are the user signed in next; claims are added
	// to the standard ones, and a nil value removes one.
	subject string
	claims  map[string]any
	// header fields added to the ID token's header.
	header map[string]any
	// clientID and secret are the registered client; a token request
	// must authenticate with them.
	clientID, secret string
	// authMethods, if set, are the token endpoint auth methods the
	// discovery document lists.
	authMethods []string
	// discoveryIssuer, if set, replaces the issuer in the discovery
	// document.
	discoveryIssuer string
	// algs, if set, are the signing algorithms discovery lists.
	algs []string
	// authError, if set, is returned by the authorization endpoint.
	authError string
	// google makes the provider mimic Google: its issuer, endpoints,
	// discovery document, and ID token claims (newGoogleIdP).
	google bool
	// tokenIssuer, if set, replaces the issuer in ID tokens.
	tokenIssuer string

	codes        map[string]idpCode
	discoveries  int
	keyFetches   int
	tokenReqs    int
	lastAuthReq  url.Values
	lastTokenReq url.Values
	lastBasic    [2]string
}

type idpCode struct {
	clientID, redirectURI, nonce, challenge string
}

func newIdP(t *testing.T, now func() time.Time) *idp {
	p := &idp{
		t: t, now: now, subject: "user-1",
		claims:   map[string]any{"email": "alice@example.com", "email_verified": true, "groups": []string{"eng"}},
		clientID: "flint", secret: "client-secret",
		codes: map[string]idpCode{},
	}
	k := newRSATestKey("rsa-1", "RS256", 0)
	p.keys, p.signer = []testKey{k}, k
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /keys", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	// Google's paths, at its hosts (googleTransport).
	mux.HandleFunc("GET /oauth2/v3/certs", p.jwks)
	mux.HandleFunc("GET /o/oauth2/v2/auth", p.authorize)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// Google's endpoints, as its discovery document lists them.
const (
	googleAuthEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint = "https://oauth2.googleapis.com/token"
	googleJWKSURI       = "https://www.googleapis.com/oauth2/v3/certs"
)

// newGoogleIdP returns an in-test provider that mimics Google: it
// answers at Google's issuer and endpoints through googleTransport,
// publishes a discovery document shaped like Google's, and issues ID
// tokens with Google's claims, including the hosted domain (hd) and a
// numeric subject. Its client ID looks like a Google one.
func newGoogleIdP(t *testing.T, now func() time.Time) *idp {
	p := newIdP(t, now)
	p.google = true
	p.subject = "110169484474386276334"
	p.clientID = "1234567890-abc.apps.googleusercontent.com"
	p.secret = "GOCSPX-client-secret"
	p.authMethods = []string{"client_secret_post", "client_secret_basic"}
	p.algs = []string{"RS256"}
	p.claims = map[string]any{
		"email": "alice@example.com", "email_verified": true, "hd": "example.com",
		"azp": p.clientID, "at_hash": "HK6E_P6Dh8Y93mRNtsDB1Q",
		"name": "Alice Example", "given_name": "Alice", "family_name": "Example",
		"picture": "https://lh3.googleusercontent.com/a/photo",
	}
	return p
}

// googleTransport carries requests to Google's hosts to the in-test
// provider p, and every other request as usual.
func googleTransport(p *idp) http.RoundTripper {
	target, _ := url.Parse(p.srv.URL)
	return roundTripper(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com":
			r = r.Clone(r.Context())
			r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		}
		return http.DefaultTransport.RoundTrip(r)
	})
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (p *idp) issuer() string {
	if p.google {
		return config.GoogleIssuer
	}
	return p.srv.URL
}

func (p *idp) discovery(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.discoveries++
	iss := p.issuer()
	if p.discoveryIssuer != "" {
		iss = p.discoveryIssuer
	}
	doc := map[string]any{
		"issuer":                 iss,
		"authorization_endpoint": p.issuer() + "/authorize",
		"token_endpoint":         p.issuer() + "/token",
		"jwks_uri":               p.issuer() + "/keys",
	}
	if p.google {
		doc = map[string]any{
			"issuer":                           iss,
			"authorization_endpoint":           googleAuthEndpoint,
			"device_authorization_endpoint":    "https://oauth2.googleapis.com/device/code",
			"token_endpoint":                   googleTokenEndpoint,
			"userinfo_endpoint":                "https://openidconnect.googleapis.com/v1/userinfo",
			"revocation_endpoint":              "https://oauth2.googleapis.com/revoke",
			"jwks_uri":                         googleJWKSURI,
			"response_types_supported":         []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token", "none"},
			"subject_types_supported":          []string{"public"},
			"scopes_supported":                 []string{"openid", "email", "profile"},
			"claims_supported":                 []string{"aud", "email", "email_verified", "exp", "family_name", "given_name", "iat", "iss", "name", "picture", "sub"},
			"code_challenge_methods_supported": []string{"plain", "S256"},
			"grant_types_supported":            []string{"authorization_code", "refresh_token"},
		}
	}
	if p.algs != nil {
		doc["id_token_signing_alg_values_supported"] = p.algs
	}
	if p.authMethods != nil {
		doc["token_endpoint_auth_methods_supported"] = p.authMethods
	}
	json.NewEncoder(w).Encode(doc)
}

func (p *idp) jwks(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keyFetches++
	var keys []map[string]any
	for _, k := range p.keys {
		keys = append(keys, jwkOf(k))
	}
	json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func (p *idp) authorize(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	q := r.URL.Query()
	p.lastAuthReq = q
	target, _ := url.Parse(q.Get("redirect_uri"))
	back := url.Values{"state": {q.Get("state")}}
	if p.authError != "" {
		back.Set("error", p.authError)
	} else {
		code := rand.Text()
		p.codes[code] = idpCode{clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
		back.Set("code", code)
	}
	target.RawQuery = back.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenReqs++
	r.ParseForm()
	p.lastTokenReq = r.PostForm
	user, pass, basic := r.BasicAuth()
	if basic {
		user, _ = url.QueryUnescape(user)
		pass, _ = url.QueryUnescape(pass)
		p.lastBasic = [2]string{user, pass}
	} else {
		user, pass = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	fail := func(code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	if user != p.clientID || pass != p.secret {
		fail("invalid_client")
		return
	}
	c, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case !ok, r.PostForm.Get("grant_type") != "authorization_code", c.redirectURI != r.PostForm.Get("redirect_uri"):
		fail("invalid_grant")
		return
	case b64.EncodeToString(sum[:]) != c.challenge:
		fail("invalid_grant")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
		"id_token": signJWT(p.t, p.signer, p.idClaims(c.nonce), p.header),
	})
}

// idClaims returns the next ID token's claims. p.mu is held.
func (p *idp) idClaims(nonce string) map[string]any {
	now := p.now()
	c := map[string]any{
		"iss": p.issuer(), "sub": p.subject, "aud": p.clientID,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": nonce,
	}
	if p.tokenIssuer != "" {
		c["iss"] = p.tokenIssuer
	}
	for k, v := range p.claims {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

// set changes the provider under its lock.
func (p *idp) set(f func(p *idp)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

// browser is a client with a cookie jar that follows redirects, as a
// browser would.
type browser struct {
	t      *testing.T
	client *http.Client
	// stop, if set, is a URL prefix whose redirect the browser does not
	// follow, leaving the response to the caller.
	stop string
}

func newBrowser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	b := &browser{t: t}
	b.client = &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if b.stop != "" && strings.HasPrefix(req.URL.String(), b.stop) {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	return b
}

func (b *browser) do(req *http.Request) response {
	b.t.Helper()
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return response{status: resp.StatusCode, header: resp.Header, body: sb.String()}
}

func (b *browser) get(u string) response {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.do(req)
}
