package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

// Signed download URLs serve clients that never send credentials for the
// downloads named in the metadata they fetch. A format puts a signed URL
// in the metadata it serves an authenticated client; the URL then works
// without credentials until it expires, and only while the client that
// requested the metadata may still read the repository.
//
// The signature is an HMAC-SHA256, keyed by a secret generated on first
// start, over the URL's path, its expiry, and that principal: its user
// and, if it authenticated with an API token, the token.

// DefaultSignedURLTTL is how long a signed URL is valid unless the signer
// asks otherwise.
const DefaultSignedURLTTL = 10 * time.Minute

// The query parameters of a signed URL.
const (
	signedExpiresParam = "flint-expires"
	signedUserParam    = "flint-user"
	signedTokenParam   = "flint-token"
	signedSigParam     = "flint-signature"
)

// urlKeyFileName is the URL-signing key's file in the key directory.
const urlKeyFileName = "url-signing.key"

// secretKeyLen is the length in bytes of the URL-signing key and the
// OIDC state key.
const secretKeyLen = 32

// Errors of VerifySignedURL.
var (
	// ErrNotSigned means a URL carries no signature.
	ErrNotSigned = errors.New("the URL is not signed")
	// ErrDenied means a principal lacks the permission a request needs.
	ErrDenied = errors.New("access denied")
)

// SignURL returns the query string that signs a download URL with path
// path for principal p, such as the principal PrincipalOf returns for the
// request whose response names the URL; nil means an anonymous client.
// path is the URL's path, unescaped, as the request for it will see it in
// URL.Path. The signature expires after ttl, or DefaultSignedURLTTL if
// ttl is not positive. It covers only the path: other query parameters
// the URL carries are not signed.
func (s *Service) SignURL(p *Principal, path string, ttl time.Duration) string {
	if p == nil {
		p = anonymous
	}
	if ttl <= 0 {
		ttl = DefaultSignedURLTTL
	}
	exp := strconv.FormatInt(s.now().Add(ttl).Unix(), 10)
	q := url.Values{signedExpiresParam: {exp}}
	if p.User != "" {
		q.Set(signedUserParam, p.User)
	}
	if p.TokenID != "" {
		q.Set(signedTokenParam, p.TokenID)
	}
	q.Set(signedSigParam, b64.EncodeToString(s.urlMAC(path, exp, p.User, p.TokenID)))
	return q.Encode()
}

// urlMAC is the signature over a signed URL's fields.
func (s *Service) urlMAC(path, exp, user, tokenID string) []byte {
	m := hmac.New(sha256.New, s.urlKey)
	var b []byte
	for _, f := range []string{"flint signed URL v1", path, exp, user, tokenID} {
		b = appendBytes(b, []byte(f))
	}
	m.Write(b)
	return m.Sum(nil)
}

// VerifySignedURL checks the signature SignURL put on r's URL for reading
// repository repo, a flint repository or a path within one. It returns
// ErrNotSigned if the URL carries no signature; ErrInvalidCredentials if
// the signature is wrong or has expired, or the principal it was issued
// for no longer exists (a deleted user, or a revoked or expired token);
// and ErrDenied if that principal may no longer read repo. When it
// returns nil, it records the principal in r's context for PrincipalOf
// and Actor.
//
// A signed URL stands in for read access only: a format verifies it only
// for downloads.
func (s *Service) VerifySignedURL(r *http.Request, repo string) error {
	q := r.URL.Query()
	if !q.Has(signedSigParam) && !q.Has(signedExpiresParam) {
		return ErrNotSigned
	}
	p, err := s.checkSignedURL(r.URL.Path, q)
	if err != nil {
		s.attempts.With("url", "failure").Inc()
		return err
	}
	s.attempts.With("url", "success").Inc()
	if s.Role(p, repo) < RoleRead {
		return ErrDenied
	}
	admit(r, p)
	return nil
}

// checkSignedURL verifies a signed URL's query parameters for path and
// resolves the principal it was issued for as it is now.
func (s *Service) checkSignedURL(path string, q url.Values) (*Principal, error) {
	var f [4]string
	for i, name := range []string{signedExpiresParam, signedUserParam, signedTokenParam, signedSigParam} {
		switch v := q[name]; len(v) {
		case 0:
		case 1:
			f[i] = v[0]
		default:
			return nil, ErrInvalidCredentials
		}
	}
	exp, user, tokenID, sig64 := f[0], f[1], f[2], f[3]
	sig, err := b64.DecodeString(sig64)
	if err != nil || !hmac.Equal(sig, s.urlMAC(path, exp, user, tokenID)) {
		return nil, ErrInvalidCredentials
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || s.now().Unix() >= t {
		return nil, ErrInvalidCredentials
	}
	switch {
	case tokenID != "":
		tok, err := s.getToken(tokenID)
		if errors.Is(err, errNoSuchToken) || err == nil && tok.Owner != user {
			return nil, ErrInvalidCredentials
		}
		if err != nil {
			return nil, err
		}
		return s.tokenPrincipal(tok)
	case user != "":
		u, err := s.getUser(user)
		if errors.Is(err, errNoSuchUser) {
			return nil, ErrInvalidCredentials
		}
		if err != nil {
			return nil, err
		}
		return userPrincipal(u), nil
	}
	return anonymous, nil
}

// loadOrCreateSecretKey reads the secret key in file in dir, or
// generates one and stores it durably if there is none yet. The file
// holds the key in hexadecimal.
func loadOrCreateSecretKey(fsy fsys.FS, dir, file string) ([]byte, bool, error) {
	path := filepath.Join(dir, file)
	if f, err := fsy.Open(path); err == nil {
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, false, fmt.Errorf("auth: reading %s: %w", path, err)
		}
		key, err := hex.DecodeString(string(bytes.TrimSpace(b)))
		if err != nil || len(key) != secretKeyLen {
			return nil, false, fmt.Errorf("auth: %s: not a %d-byte key in hexadecimal", path, secretKeyLen)
		}
		return key, false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("auth: opening %s: %w", path, err)
	}

	key := make([]byte, secretKeyLen)
	rand.Read(key)
	if err := writeFileDurably(fsy, path, []byte(hex.EncodeToString(key)+"\n")); err != nil {
		return nil, false, fmt.Errorf("auth: storing %s: %w", path, err)
	}
	return key, true, nil
}
