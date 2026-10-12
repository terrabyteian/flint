package auth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256" // the SHA-256 hash of RS256, PS256, and ES256
	_ "crypto/sha512" // the SHA-384 and SHA-512 hashes of the other algorithms
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/terrabyteian/flint/internal/config"
)

// OIDC providers sign ID tokens with keys they publish as a JSON Web Key
// Set (RFC 7517). Verification is hand-written like the token service's:
// it accepts only asymmetric algorithms from an allowed list, takes the
// key from the provider's published set, never from the token, and
// requires the key's type, curve, and declared algorithm to match the
// token's algorithm, so a token cannot choose a weaker algorithm or turn
// a public key into an HMAC secret.

// minRSABits is the smallest RSA modulus accepted.
const minRSABits = 2048

// maxRSABits bounds the work a published key can make verification do.
const maxRSABits = 8192

// jwk is a JSON Web Key as providers publish it in their key sets.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// verifyKey is a provider's public signing key.
type verifyKey struct {
	kid string
	alg string // the algorithm the key is restricted to, or ""
	pub crypto.PublicKey
}

// parseJWKS parses a JSON Web Key Set, keeping the public signing keys
// flint can verify with and skipping the rest, such as encryption keys or
// keys of unsupported types. A malformed set or a malformed supported key
// is an error.
func parseJWKS(b []byte) ([]verifyKey, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("invalid key set: %w", err)
	}
	var keys []verifyKey
	for i, raw := range set.Keys {
		var k jwk
		if err := json.Unmarshal(raw, &k); err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if errors.Is(err, errUnsupportedKey) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("key %d (kid %q): %w", i, k.Kid, err)
		}
		keys = append(keys, verifyKey{kid: k.Kid, alg: k.Alg, pub: pub})
	}
	return keys, nil
}

var errUnsupportedKey = errors.New("unsupported key")

// publicKey decodes the key's public part.
func (k *jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("invalid RSA key")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		switch bits := pub.N.BitLen(); {
		case bits < minRSABits:
			return nil, fmt.Errorf("the RSA key has %d bits, fewer than %d", bits, minRSABits)
		case bits > maxRSABits:
			return nil, fmt.Errorf("the RSA key has %d bits, more than %d", bits, maxRSABits)
		case pub.E < 3 || pub.E%2 == 0:
			return nil, errors.New("invalid RSA public exponent")
		}
		return pub, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errUnsupportedKey
		}
		size := (curve.Params().BitSize + 7) / 8
		x, err1 := b64.DecodeString(k.X)
		y, err2 := b64.DecodeString(k.Y)
		if err1 != nil || err2 != nil || len(x) != size || len(y) != size {
			return nil, errors.New("invalid EC key")
		}
		// ParseUncompressedPublicKey checks that the point is on the curve.
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, slices.Concat([]byte{4}, x, y))
		if err != nil {
			return nil, fmt.Errorf("invalid EC key: %w", err)
		}
		return pub, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, errUnsupportedKey
		}
		x, err := b64.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, errUnsupportedKey
}

// joseHeader is a JWS header's fields that verification reads.
type joseHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Typ  string          `json:"typ"`
	Crit json.RawMessage `json:"crit"`
}

// Errors of verifyJWS.
var (
	// errUnknownKey means the token names a key the set does not hold,
	// which a provider that rotated its keys after the set was fetched
	// signs with.
	errUnknownKey   = errors.New("signed with an unknown key")
	errBadSignature = errors.New("invalid signature")
)

// verifyJWS verifies a JWS in compact serialization against keys, with
// one of the allowed algorithms, and returns its payload.
func verifyJWS(tok string, keys []verifyKey, allowed []string) ([]byte, error) {
	if len(tok) > maxJWTLen {
		return nil, errors.New("the token is too long")
	}
	h64, rest, ok := strings.Cut(tok, ".")
	p64, sig64, ok2 := strings.Cut(rest, ".")
	if !ok || !ok2 || strings.Contains(sig64, ".") {
		return nil, errors.New("not a signed JWT")
	}
	hb, err := b64.DecodeString(h64)
	if err != nil {
		return nil, errors.New("invalid header encoding")
	}
	var h joseHeader
	dec := json.NewDecoder(bytes.NewReader(hb))
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}
	switch {
	case h.Crit != nil:
		// No extension is understood, so none may be critical.
		return nil, errors.New("the header has critical extensions")
	case h.Typ != "" && !strings.EqualFold(h.Typ, "JWT"):
		return nil, fmt.Errorf("unexpected token type %q", h.Typ)
	case !slices.Contains(allowed, h.Alg) || !slices.Contains(supportedAlgs, h.Alg):
		return nil, fmt.Errorf("algorithm %q is not allowed", h.Alg)
	}
	sig, err := b64.DecodeString(sig64)
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}
	payload, err := b64.DecodeString(p64)
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}
	signed := []byte(tok[:len(h64)+1+len(p64)])
	found := false
	for _, k := range keys {
		if h.Kid != "" && k.kid != h.Kid || k.alg != "" && k.alg != h.Alg || !keyFits(k.pub, h.Alg) {
			continue
		}
		found = true
		if verifySignature(k.pub, h.Alg, signed, sig) {
			return payload, nil
		}
	}
	if !found {
		return nil, errUnknownKey
	}
	return nil, errBadSignature
}

// supportedAlgs are the algorithms verifySignature implements.
var supportedAlgs = config.OIDCSigningAlgorithms

// algHash returns the hash of an RSA or ECDSA algorithm.
func algHash(alg string) crypto.Hash {
	switch alg[len(alg)-3:] {
	case "256":
		return crypto.SHA256
	case "384":
		return crypto.SHA384
	}
	return crypto.SHA512
}

// keyFits reports whether pub is a key for alg: an RSA key for RS* and
// PS*, an ECDSA key on the algorithm's curve for ES*, and an Ed25519 key
// for EdDSA.
func keyFits(pub crypto.PublicKey, alg string) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		switch alg {
		case "ES256":
			return k.Curve == elliptic.P256()
		case "ES384":
			return k.Curve == elliptic.P384()
		case "ES512":
			return k.Curve == elliptic.P521()
		}
	case ed25519.PublicKey:
		return alg == "EdDSA"
	}
	return false
}

// verifySignature checks a JWS signature over signed with pub, which
// keyFits for alg.
func verifySignature(pub crypto.PublicKey, alg string, signed, sig []byte) bool {
	if alg == "EdDSA" {
		return ed25519.Verify(pub.(ed25519.PublicKey), signed, sig)
	}
	hash := algHash(alg)
	hh := hash.New()
	hh.Write(signed)
	digest := hh.Sum(nil)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(k, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
		return rsa.VerifyPKCS1v15(k, hash, digest, sig) == nil
	case *ecdsa.PublicKey:
		// A JWS ECDSA signature is r and s, each as long as the curve's
		// order, concatenated (RFC 7518, section 3.4).
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(k, digest, r, s)
	}
	return false
}
