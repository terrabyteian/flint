package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

// The JSON Web Tokens of the Docker token service are hand-written: an
// Ed25519 (EdDSA, RFC 8037) signature over a fixed header and the claims.
// Verification accepts only the exact algorithm and key this server
// issues with, so a token cannot choose its own algorithm or key.

const (
	jwtAlg = "EdDSA"
	// maxJWTLen bounds the work spent on a presented token.
	maxJWTLen = 16 << 10
	// clockLeeway tolerates a small backwards clock step between issuing
	// and checking a token's issue and not-before times.
	clockLeeway = time.Minute
)

var b64 = base64.RawURLEncoding

// jwtHeader is the JOSE header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// claims are a Docker registry token's claims.
type claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"` // the user, or "" for an anonymous client
	Audience  string `json:"aud"`
	Expiry    int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	ID        string `json:"jti"`
	// TokenID names the API token the client authenticated with, so the
	// token keeps limiting what the JWT allows, and revoking it ends it.
	TokenID string   `json:"tid,omitempty"`
	Access  []access `json:"access"`
}

// access is one granted resource of a Docker token scope.
type access struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// allows reports whether the claims grant action on repository repo. An
// entry for a path within a flint repository also counts for the flint
// repository itself, because permissions apply to flint repositories.
func (c *claims) allows(repo, action string) bool {
	for _, a := range c.Access {
		if a.Type != "repository" || (a.Name != repo && (strings.Contains(repo, "/") || repoOf(a.Name) != repo)) {
			continue
		}
		for _, x := range a.Actions {
			if x == action {
				return true
			}
		}
	}
	return false
}

// allowsCatalog reports whether the claims grant listing repositories.
func (c *claims) allowsCatalog() bool {
	for _, a := range c.Access {
		if a.Type == "registry" && a.Name == "catalog" && slices.Contains(a.Actions, "*") {
			return true
		}
	}
	return false
}

// signer signs and verifies tokens with an Ed25519 key.
type signer struct {
	key ed25519.PrivateKey
	pub ed25519.PublicKey
	kid string
}

func newSigner(key ed25519.PrivateKey) *signer {
	pub := key.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &signer{key: key, pub: pub, kid: strings.ToLower(base32.StdEncoding.EncodeToString(sum[:15]))}
}

func (s *signer) sign(c *claims) (string, error) {
	h, err := json.Marshal(jwtHeader{Alg: jwtAlg, Typ: "JWT", Kid: s.kid})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	msg := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	return msg + "." + b64.EncodeToString(ed25519.Sign(s.key, []byte(msg))), nil
}

var errInvalidToken = errors.New("invalid token")

// verify checks a token's form, signature, issuer, audience, and validity
// period, and returns its claims.
func (s *signer) verify(tok, issuer, audience string, now time.Time) (*claims, error) {
	if len(tok) > maxJWTLen {
		return nil, errInvalidToken
	}
	h64, rest, ok := strings.Cut(tok, ".")
	p64, sig64, ok2 := strings.Cut(rest, ".")
	if !ok || !ok2 {
		return nil, errInvalidToken
	}
	sig, err := b64.DecodeString(sig64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errInvalidToken
	}
	if !ed25519.Verify(s.pub, []byte(tok[:len(h64)+1+len(p64)]), sig) {
		return nil, errInvalidToken
	}
	var h jwtHeader
	if err := decodeSegment(h64, &h); err != nil || h.Alg != jwtAlg || h.Kid != s.kid || (h.Typ != "" && h.Typ != "JWT") {
		return nil, errInvalidToken
	}
	var c claims
	if err := decodeSegment(p64, &c); err != nil {
		return nil, errInvalidToken
	}
	t := now.Unix()
	switch {
	case c.Issuer != issuer, c.Audience != audience:
		return nil, errInvalidToken
	case t >= c.Expiry:
		return nil, fmt.Errorf("%w: expired", errInvalidToken)
	case c.NotBefore > t+int64(clockLeeway/time.Second), c.IssuedAt > t+int64(clockLeeway/time.Second):
		return nil, fmt.Errorf("%w: not yet valid", errInvalidToken)
	}
	return &c, nil
}

// decodeSegment decodes one base64url JSON segment strictly.
func decodeSegment(seg string, v any) error {
	b, err := b64.DecodeString(seg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// keyFileName is the signing key's file in the key directory.
const keyFileName = "token-signing.key"

// loadOrCreateKey reads the Ed25519 signing key from dir, or generates
// one and stores it durably if there is none yet.
func loadOrCreateKey(fsy fsys.FS, dir string) (ed25519.PrivateKey, bool, error) {
	path := filepath.Join(dir, keyFileName)
	if f, err := fsy.Open(path); err == nil {
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, false, fmt.Errorf("auth: reading the signing key: %w", err)
		}
		key, err := parseKey(b)
		if err != nil {
			return nil, false, fmt.Errorf("auth: %s: %w", path, err)
		}
		return key, false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("auth: opening the signing key: %w", err)
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, false, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeFileDurably(fsy, path, data); err != nil {
		return nil, false, fmt.Errorf("auth: storing the signing key: %w", err)
	}
	return key, true, nil
}

func parseKey(b []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the key is a %T, not an Ed25519 key", k)
	}
	return key, nil
}

// writeFileDurably creates path with data, readable only by its owner,
// through a synced temporary file and a rename, so a crash leaves either
// no file or the whole file. Its directory is created if missing.
func writeFileDurably(fsy fsys.FS, path string, data []byte) error {
	dir := filepath.Dir(path)
	if _, err := fsy.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := fsy.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := fsy.SyncDir(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	f, err := fsy.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = fsy.Rename(tmp, path)
	}
	if err != nil {
		fsy.Remove(tmp)
		return err
	}
	return fsy.SyncDir(dir)
}
