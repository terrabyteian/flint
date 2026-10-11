package upstream

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"
)

// Algorithms of the digests, other than the blob store's sha256, that a
// fetch by path can compute and verify.
const (
	SHA1    = "sha1"
	SHA512  = "sha512"
	MD5     = "md5"
	GitSHA1 = "git-sha1" // a git blob object's id: sha1 of "blob <size>\x00" and the content
)

// Sums are the digests computed of content, by algorithm (SHA1 and so
// on), each the raw hash.
type Sums map[string][]byte

// Hex returns the digest of algorithm alg in lowercase hex, or "".
func (s Sums) Hex(alg string) string {
	if b := s[alg]; b != nil {
		return hex.EncodeToString(b)
	}
	return ""
}

// Expect is what content fetched by path must match before it is cached
// and before any client receives its final byte. Content that fails is
// never cached; the fetch fails with ErrDigestMismatch.
type Expect struct {
	// Size is the content's size, or -1 if unknown. Zero is a valid
	// size, so callers that do not know it must say -1.
	Size int64
	// SHA256, if not zero-valued, is the content's sha256 digest, which
	// the blob store verifies at commit, as for a fetch by digest.
	SHA256 string // lowercase hex
	// Sums are expected digests by algorithm (SHA1, SHA512, MD5,
	// GitSHA1), each the raw hash.
	Sums Sums
	// Compute lists further algorithms to compute while staging and
	// report in the fetch's result, without expecting a value, such as
	// the digests a format serves next to a file.
	Compute []string
	// Check, if not nil, inspects the staged content after the digests
	// match, such as computing the Go h1: hash of a module zip. It reads
	// the content through r, size bytes long. An error fails the fetch;
	// one that should count as a mismatch wraps ErrDigestMismatch.
	Check func(ctx context.Context, r io.ReaderAt, size int64) error
}

// hashers computes the digests an Expect needs while content streams
// through it.
type hashers struct {
	algs []string
	hs   []hash.Hash
}

// newHashers returns hashers for the expected and computed digests of e,
// or an error naming an unknown algorithm.
func newHashers(e *Expect) (*hashers, error) {
	h := &hashers{}
	var algs []string
	for alg := range e.Sums {
		algs = append(algs, alg)
	}
	algs = append(algs, e.Compute...)
	slices.Sort(algs)
	for _, alg := range slices.Compact(algs) {
		var hh hash.Hash
		switch alg {
		case SHA1:
			hh = sha1.New()
		case SHA512:
			hh = sha512.New()
		case MD5:
			hh = md5.New()
		case GitSHA1:
			if e.Size < 0 {
				return nil, errors.New("upstream: a git blob hash needs the content's size in advance")
			}
			hh = sha1.New()
			fmt.Fprintf(hh, "blob %d\x00", e.Size)
		default:
			return nil, fmt.Errorf("upstream: unknown digest algorithm %q", alg)
		}
		h.algs = append(h.algs, alg)
		h.hs = append(h.hs, hh)
	}
	return h, nil
}

func (h *hashers) Write(p []byte) (int, error) {
	for _, hh := range h.hs {
		hh.Write(p)
	}
	return len(p), nil
}

// sums returns the digests computed.
func (h *hashers) sums() Sums {
	out := Sums{}
	for i, alg := range h.algs {
		out[alg] = h.hs[i].Sum(nil)
	}
	return out
}

// verify checks the computed digests against e's.
func (h *hashers) verify(e *Expect, label string) (Sums, error) {
	got := h.sums()
	for _, alg := range slices.Sorted(func(yield func(string) bool) {
		for k := range e.Sums {
			if !yield(k) {
				return
			}
		}
	}) {
		if !bytes.Equal(got[alg], e.Sums[alg]) {
			return nil, fmt.Errorf("%w: %s of %s is %x, want %x", ErrDigestMismatch, alg, label, got[alg], e.Sums[alg])
		}
	}
	return got, nil
}

// ParseIntegrity parses a Subresource Integrity value, as npm's
// dist.integrity holds: one or more "<alg>-<base64>" entries separated
// by spaces. It returns the strongest digest it knows, sha512 before
// sha1 (sha256 and sha384 are skipped: sha256 is the blob store's
// digest, which callers pass as Expect.SHA256 instead, and npm never
// uses sha384), as an algorithm and raw hash.
func ParseIntegrity(s string) (alg string, sum []byte, ok bool) {
	for f := range strings.FieldsSeq(s) {
		a, b64, found := strings.Cut(f, "-")
		if !found {
			continue
		}
		if i := strings.IndexByte(b64, '?'); i >= 0 { // options are ignored
			b64 = b64[:i]
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		switch {
		case a == SHA512 && len(raw) == sha512.Size:
			return SHA512, raw, true
		case a == SHA1 && len(raw) == sha1.Size && alg == "":
			alg, sum = SHA1, raw
		case a == "sha256" && len(raw) == sha256.Size && alg == "":
			alg, sum = "sha256", raw
		}
	}
	return alg, sum, alg != ""
}

// Go module hashes. The go command records a module version's content
// as an "h1:" hash: sha256 over a summary listing the sha256 of every
// file with its name, one "<hex>  <name>\n" line each, sorted by name,
// encoded in base64. A module zip's names start with
// "<module>@<version>/"; a go.mod file is hashed as the single file
// "go.mod".

// GoModH1 returns the h1: hash of a go.mod file's content.
func GoModH1(mod []byte) string {
	sum := sha256.Sum256(mod)
	return goH1([]goFile{{"go.mod", sum}})
}

// GoZipH1 returns the h1: hash of a module zip, size bytes read
// through r.
func GoZipH1(r io.ReaderAt, size int64) (string, error) {
	z, err := zip.NewReader(r, size)
	if err != nil {
		return "", fmt.Errorf("upstream: reading the module zip: %w", err)
	}
	files := make([]goFile, 0, len(z.File))
	for _, f := range z.File {
		if strings.Contains(f.Name, "\n") {
			return "", fmt.Errorf("upstream: the module zip names a file with a line break: %q", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("upstream: reading %s in the module zip: %w", f.Name, err)
		}
		h := sha256.New()
		_, err = io.Copy(h, rc)
		rc.Close()
		if err != nil {
			return "", fmt.Errorf("upstream: reading %s in the module zip: %w", f.Name, err)
		}
		gf := goFile{name: f.Name}
		h.Sum(gf.sum[:0])
		files = append(files, gf)
	}
	return goH1(files), nil
}

type goFile struct {
	name string
	sum  [sha256.Size]byte
}

func goH1(files []goFile) string {
	slices.SortFunc(files, func(a, b goFile) int { return strings.Compare(a.name, b.name) })
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%x  %s\n", f.sum, f.name)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// CheckGoZipH1 returns an Expect.Check that requires a module zip's h1:
// hash to be want.
func CheckGoZipH1(want string) func(ctx context.Context, r io.ReaderAt, size int64) error {
	return func(_ context.Context, r io.ReaderAt, size int64) error {
		got, err := GoZipH1(r, size)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrDigestMismatch, err)
		}
		if got != want {
			return fmt.Errorf("%w: the module zip's hash is %s, want %s", ErrDigestMismatch, got, want)
		}
		return nil
	}
}

// CheckGoModH1 returns an Expect.Check that requires a go.mod file's h1:
// hash to be want. go.mod files are small; one over maxGoMod fails.
func CheckGoModH1(want string) func(ctx context.Context, r io.ReaderAt, size int64) error {
	return func(_ context.Context, r io.ReaderAt, size int64) error {
		if size > maxGoMod {
			return fmt.Errorf("%w: a go.mod file of %d bytes", ErrTooLarge, size)
		}
		b := make([]byte, size)
		if _, err := r.ReadAt(b, 0); err != nil && err != io.EOF {
			return err
		}
		if got := GoModH1(b); got != want {
			return fmt.Errorf("%w: the go.mod file's hash is %s, want %s", ErrDigestMismatch, got, want)
		}
		return nil
	}
}

// maxGoMod bounds a go.mod file CheckGoModH1 reads, as the go command's
// own limit does.
const maxGoMod = 16 << 20
