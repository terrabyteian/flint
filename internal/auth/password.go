package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultPasswordIterations is the PBKDF2-HMAC-SHA256 iteration count for
// new password hashes, as OWASP recommends. Each hash records its own
// count, so raising it later leaves existing hashes verifiable.
const DefaultPasswordIterations = 600_000

// Password length limits, in bytes.
const (
	MinPasswordLen = 8
	MaxPasswordLen = 1024
)

const (
	hashAlgPBKDF2SHA256 = 1
	saltLen             = 16
	keyLen              = 32
)

// checkPassword reports why a new password is unacceptable, or nil.
func checkPassword(pw string) error {
	switch {
	case len(pw) < MinPasswordLen:
		return fmt.Errorf("the password must be at least %d characters", MinPasswordLen)
	case len(pw) > MaxPasswordLen:
		return fmt.Errorf("the password must be at most %d bytes", MaxPasswordLen)
	}
	return nil
}

// hashPassword derives a password hash with a new random salt and encodes
// it with its algorithm, iteration count, and salt.
func hashPassword(pw string, iterations int) ([]byte, error) {
	salt := make([]byte, saltLen)
	rand.Read(salt)
	key, err := pbkdf2.Key(sha256.New, pw, salt, iterations, keyLen)
	if err != nil {
		return nil, err
	}
	b := []byte{hashAlgPBKDF2SHA256}
	b = binary.AppendUvarint(b, uint64(iterations))
	b = appendBytes(b, salt)
	return appendBytes(b, key), nil
}

// verifyPassword reports whether pw matches the encoded hash.
func verifyPassword(pw string, encoded []byte) (bool, error) {
	d := decoder{b: encoded}
	if alg := d.byte(); alg != hashAlgPBKDF2SHA256 {
		return false, fmt.Errorf("auth: unknown password hash algorithm %d", alg)
	}
	iter := d.uvarint()
	salt := d.bytes()
	want := d.bytes()
	if err := d.done(); err != nil {
		return false, err
	}
	if iter == 0 || iter > 1<<30 || len(want) == 0 {
		return false, errors.New("auth: invalid password hash")
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, int(iter), len(want))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// verifiedCache remembers recently verified passwords, so a client that
// sends a password with every request, as registry clients do, costs one
// PBKDF2 derivation every few minutes instead of one per request. It
// stores only keyed hashes of the credentials. The stored password hash
// is part of the key, so changing a password invalidates its entries.
type verifiedCache struct {
	key [32]byte
	ttl time.Duration
	max int

	mu      sync.Mutex
	entries map[[32]byte]time.Time // expiry
}

func newVerifiedCache(ttl time.Duration, max int) *verifiedCache {
	c := &verifiedCache{ttl: ttl, max: max, entries: map[[32]byte]time.Time{}}
	rand.Read(c.key[:])
	return c
}

func (c *verifiedCache) id(name string, hash []byte, pw string) [32]byte {
	m := hmac.New(sha256.New, c.key[:])
	var n [binary.MaxVarintLen64]byte
	for _, part := range [][]byte{[]byte(name), hash, []byte(pw)} {
		m.Write(n[:binary.PutUvarint(n[:], uint64(len(part)))])
		m.Write(part)
	}
	var id [32]byte
	m.Sum(id[:0])
	return id
}

func (c *verifiedCache) has(id [32]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.entries[id]
	if ok && !now.Before(exp) {
		delete(c.entries, id)
		return false
	}
	return ok
}

func (c *verifiedCache) add(id [32]byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		for k, exp := range c.entries {
			if !now.Before(exp) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.max {
			clear(c.entries)
		}
	}
	c.entries[id] = now.Add(c.ttl)
}
