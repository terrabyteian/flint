// Package sumdb reads what the Go checksum database serves: its public
// keys, the signed notes that carry its tree heads, and the records its
// lookup endpoint answers with. flint uses it to verify Go modules before
// it caches them, and configuration validation uses it to check a
// checksum database's key.
//
// A signed note is a text, ending in a newline, followed by a blank line
// and one or more signature lines:
//
//	go.sum database tree
//	68282237
//	CkJ9OT8kwb49hwTY6DRvIIG46oUnBURc0WZN0Mb9JDs=
//
//	— sum.golang.org Az3grrSXR7em2M8DIpz/M1EAD6VmLyr9yKEG...
//
// Each signature line is an em dash, a space, the signer's name, a space,
// and the base64 encoding of the signer's 4-byte key hash followed by
// the signature. A key is written "<name>+<hash>+<key>", where hash is
// the key hash in hexadecimal and key the base64 encoding of an
// algorithm byte, 1 for Ed25519, and the public key; the key hash is the
// first four bytes of the SHA-256 of the name, a newline, and the
// algorithm byte and public key.
//
// A lookup answer is a record's number on a line of its own, the
// record's text (the go.sum lines of one module version), a blank line,
// and a signed note of a tree that contains the record. This package
// checks the note's signature, but not that the record is in the tree:
// the go command, which fetches the tiles that prove it, always does.
package sumdb

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// DefaultKey is the public key of sum.golang.org, the checksum database
// the go command uses by default.
const DefaultKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"

// algEd25519 is the algorithm byte of an Ed25519 key.
const algEd25519 = 1

// ErrBadNote means a signed note or lookup answer is malformed or not
// signed by the expected key.
var ErrBadNote = errors.New("sumdb: malformed or unverified note")

// Verifier verifies the signatures of one checksum database.
type Verifier struct {
	name string
	hash uint32
	key  ed25519.PublicKey
}

// ParseKey parses a checksum database's public key, such as DefaultKey.
func ParseKey(s string) (*Verifier, error) {
	name, rest, ok1 := strings.Cut(s, "+")
	hexHash, b64, ok2 := strings.Cut(rest, "+")
	if !ok1 || !ok2 || !validName(name) || len(hexHash) != 8 {
		return nil, fmt.Errorf("sumdb: %q is not a key of the form <name>+<hash>+<key>", s)
	}
	h, err := strconv.ParseUint(hexHash, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("sumdb: the key hash %q is not hexadecimal", hexHash)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	switch {
	case err != nil:
		return nil, fmt.Errorf("sumdb: the key of %s is not base64", name)
	case len(raw) != 1+ed25519.PublicKeySize || raw[0] != algEd25519:
		return nil, fmt.Errorf("sumdb: the key of %s is not an Ed25519 public key", name)
	case keyHash(name, raw) != uint32(h):
		return nil, fmt.Errorf("sumdb: the key hash of %s is %08x, not %s", name, keyHash(name, raw), hexHash)
	}
	return &Verifier{name: name, hash: uint32(h), key: ed25519.PublicKey(raw[1:])}, nil
}

// Name returns the checksum database's name, such as "sum.golang.org",
// which clients use in its URLs.
func (v *Verifier) Name() string { return v.name }

// keyHash returns the key hash of a key, its algorithm byte included.
func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// validName reports whether s is a signer's name: non-empty, printable,
// and without spaces or "+".
func validName(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == '+' || r == 0x7f {
			return false
		}
	}
	return true
}

// sigPrefix starts a signature line: an em dash and a space.
const sigPrefix = "— "

// Open returns the text of a signed note msg if one of its signatures is
// v's and verifies; signatures by other keys are ignored. It fails with
// an error wrapping ErrBadNote otherwise.
func (v *Verifier) Open(msg []byte) ([]byte, error) {
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		return nil, fmt.Errorf("%w: no signatures", ErrBadNote)
	}
	text, sigs := msg[:i+1], msg[i+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, fmt.Errorf("%w: the signatures do not end in a newline", ErrBadNote)
	}
	if !utf8.Valid(text) {
		return nil, fmt.Errorf("%w: the text is not UTF-8", ErrBadNote)
	}
	for len(sigs) > 0 {
		line, rest, _ := bytes.Cut(sigs, []byte("\n"))
		sigs = rest
		s, ok := strings.CutPrefix(string(line), sigPrefix)
		if !ok {
			return nil, fmt.Errorf("%w: a signature line does not start with an em dash", ErrBadNote)
		}
		name, b64, ok := strings.Cut(s, " ")
		sig, err := base64.StdEncoding.DecodeString(b64)
		if !ok || err != nil || !validName(name) || len(sig) < 5 {
			return nil, fmt.Errorf("%w: a malformed signature line", ErrBadNote)
		}
		if name != v.name || binary.BigEndian.Uint32(sig) != v.hash {
			continue
		}
		if ed25519.Verify(v.key, text, sig[4:]) {
			return text, nil
		}
		return nil, fmt.Errorf("%w: the signature of %s does not verify", ErrBadNote, v.name)
	}
	return nil, fmt.Errorf("%w: not signed by %s", ErrBadNote, v.name)
}

// treePrefix starts the text of a checksum database's tree head.
const treePrefix = "go.sum database tree\n"

// Tree is a tree head of a checksum database's log.
type Tree struct {
	// N is the number of records in the log.
	N int64
	// Hash is the root hash of the log's tree.
	Hash [sha256.Size]byte
}

// OpenTree returns the tree head of signed note msg, as the checksum
// database's latest endpoint and lookups serve it, if v signed it.
func (v *Verifier) OpenTree(msg []byte) (Tree, error) {
	text, err := v.Open(msg)
	if err != nil {
		return Tree{}, err
	}
	rest, ok := bytes.CutPrefix(text, []byte(treePrefix))
	if !ok {
		return Tree{}, fmt.Errorf("%w: the note is not a tree head", ErrBadNote)
	}
	lines := strings.SplitN(string(rest), "\n", 3)
	if len(lines) < 3 {
		return Tree{}, fmt.Errorf("%w: a tree head without a size and a hash", ErrBadNote)
	}
	var t Tree
	n, err := strconv.ParseInt(lines[0], 10, 64)
	h, herr := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || n < 0 || lines[0] != strconv.FormatInt(n, 10) || herr != nil || len(h) != sha256.Size {
		return Tree{}, fmt.Errorf("%w: a malformed tree head", ErrBadNote)
	}
	t.N = n
	copy(t.Hash[:], h)
	return t, nil
}

// Record is a checksum database's record of one module version, as its
// lookup endpoint answers.
type Record struct {
	// ID is the record's number in the log.
	ID int64
	// Path and Version are the module path and version it is for.
	Path, Version string
	// Zip and Mod are the h1: hashes of the module zip and go.mod file.
	Zip, Mod string
	// Tree is the tree head the answer came with.
	Tree Tree
}

// OpenLookup reads a lookup answer for module path at version, checking
// that v signed its tree head and that its record names the module
// version and both its hashes.
func (v *Verifier) OpenLookup(b []byte, path, version string) (*Record, error) {
	idLine, rest, ok := bytes.Cut(b, []byte("\n"))
	id, err := strconv.ParseInt(string(idLine), 10, 64)
	if !ok || err != nil || id < 0 {
		return nil, fmt.Errorf("%w: a lookup answer without a record number", ErrBadNote)
	}
	text, note, ok := bytes.Cut(rest, []byte("\n\n"))
	if !ok {
		return nil, fmt.Errorf("%w: a lookup answer without a tree head", ErrBadNote)
	}
	tree, err := v.OpenTree(note)
	if err != nil {
		return nil, err
	}
	if id >= tree.N {
		return nil, fmt.Errorf("%w: record %d is not in a tree of %d records", ErrBadNote, id, tree.N)
	}
	r := &Record{ID: id, Path: path, Version: version, Tree: tree}
	for _, line := range strings.Split(string(text), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != path || !strings.HasPrefix(f[2], "h1:") {
			continue
		}
		switch f[1] {
		case version:
			r.Zip = f[2]
		case version + "/go.mod":
			r.Mod = f[2]
		}
	}
	if r.Zip == "" || r.Mod == "" {
		return nil, fmt.Errorf("%w: the record does not give both hashes of %s@%s", ErrBadNote, path, version)
	}
	return r, nil
}
