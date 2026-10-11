package blob

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Digest errors.
var (
	// ErrDigestInvalid means a string is not a well-formed digest.
	ErrDigestInvalid = errors.New("blob: invalid digest")
	// ErrDigestUnsupported means a digest is well formed but uses an
	// algorithm other than sha256.
	ErrDigestUnsupported = errors.New("blob: unsupported digest algorithm")
)

// Digest is a validated content digest. v1 supports only
// "sha256:<64 lowercase hex>". The zero Digest is not a valid digest; it
// stands for "no digest", for example in [Upload.Commit].
//
// Digests are comparable with ==.
type Digest struct {
	sum [sha256.Size]byte
	set bool
}

// ParseDigest parses s as an OCI digest (algorithm ":" encoded). It returns
// ErrDigestUnsupported for a well-formed digest whose algorithm is not
// sha256, and ErrDigestInvalid for anything else that is not
// "sha256:" followed by 64 lowercase hex characters.
func ParseDigest(s string) (Digest, error) {
	alg, enc, ok := strings.Cut(s, ":")
	if !ok || !validAlgorithm(alg) || !validEncoded(enc) {
		return Digest{}, fmt.Errorf("%w %q", ErrDigestInvalid, abbrev(s))
	}
	if alg != "sha256" {
		return Digest{}, fmt.Errorf("%w %q in %q: only sha256 is supported", ErrDigestUnsupported, abbrev(alg), abbrev(s))
	}
	var d Digest
	if len(enc) != 2*sha256.Size || !isLowerHex(enc) {
		return Digest{}, fmt.Errorf("%w %q: sha256 needs 64 lowercase hex characters", ErrDigestInvalid, abbrev(s))
	}
	hex.Decode(d.sum[:], []byte(enc))
	d.set = true
	return d, nil
}

// FromBytes returns the digest of b.
func FromBytes(b []byte) Digest {
	return Digest{sum: sha256.Sum256(b), set: true}
}

// fromSum returns the digest with the given sha256 sum.
func fromSum(sum []byte) Digest {
	var d Digest
	copy(d.sum[:], sum)
	d.set = true
	return d
}

// String returns the digest as "sha256:<hex>", or "" for the zero Digest.
func (d Digest) String() string {
	if !d.set {
		return ""
	}
	return "sha256:" + d.Hex()
}

// Hex returns the hex-encoded sum, or "" for the zero Digest.
func (d Digest) Hex() string {
	if !d.set {
		return ""
	}
	return hex.EncodeToString(d.sum[:])
}

// IsZero reports whether d is the zero Digest.
func (d Digest) IsZero() bool { return !d.set }

// MarshalText returns the digest as String does, so a Digest encodes as a
// JSON string.
func (d Digest) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// UnmarshalText parses a digest as ParseDigest does.
func (d *Digest) UnmarshalText(b []byte) error {
	v, err := ParseDigest(string(b))
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// validAlgorithm reports whether s matches the OCI algorithm grammar:
// components of [a-z0-9]+ joined by single separators from [+._-].
func validAlgorithm(s string) bool {
	if s == "" {
		return false
	}
	prevSep := true // no leading separator
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
			prevSep = false
		case c == '+' || c == '.' || c == '_' || c == '-':
			if prevSep {
				return false
			}
			prevSep = true
		default:
			return false
		}
	}
	return !prevSep
}

// validEncoded reports whether s matches the OCI encoded grammar [a-zA-Z0-9=_-]+.
func validEncoded(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '=', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// abbrev shortens s for error messages, so a hostile input cannot flood logs.
func abbrev(s string) string {
	const max = 100
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
