package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"github.com/terrabyteian/flint/internal/blob"
)

// Verifier reads content and checks it against a digest and size. At
// the end of the content, Read returns io.EOF only if the content
// matches; otherwise it returns an error wrapping ErrDigestMismatch.
// Content longer than the expected size fails as soon as it is read.
type Verifier struct {
	r    io.Reader
	want blob.Digest
	size int64 // -1 if unknown
	h    hash.Hash
	n    int64
	err  error
}

// NewVerifier returns a Verifier reading r, which must hold the content
// of digest d, size bytes long (-1 if unknown).
func NewVerifier(r io.Reader, d blob.Digest, size int64) *Verifier {
	return &Verifier{r: r, want: d, size: size, h: sha256.New()}
}

func (v *Verifier) Read(p []byte) (int, error) {
	if v.err != nil {
		return 0, v.err
	}
	n, err := v.r.Read(p)
	v.h.Write(p[:n])
	v.n += int64(n)
	if v.size >= 0 && v.n > v.size {
		v.err = fmt.Errorf("%w: more than the %d bytes expected of %s", ErrDigestMismatch, v.size, v.want)
		return 0, v.err
	}
	if err == io.EOF {
		got := "sha256:" + hex.EncodeToString(v.h.Sum(nil))
		switch {
		case v.size >= 0 && v.n != v.size:
			err = fmt.Errorf("%w: %d bytes, want %d of %s", io.ErrUnexpectedEOF, v.n, v.size, v.want)
		case got != v.want.String():
			err = fmt.Errorf("%w: got %s, want %s", ErrDigestMismatch, got, v.want)
		}
		v.err = err
	} else if err != nil {
		// Wrapped, so a reader's own io.ErrUnexpectedEOF can never be
		// mistaken for the clean end CopyVerified looks for.
		v.err = fmt.Errorf("%w: reading %s: %w", ErrUnavailable, v.want, err)
		err = v.err
	}
	return n, err
}

// copyChunk is the read size of CopyVerified.
const copyChunk = 64 << 10

// CopyVerified copies r to w, holding back each chunk until
// the next read succeeds, so the final chunk is written only after r
// reports a clean end. A client therefore never receives the whole of
// content that fails verification: on failure the caller aborts the
// response, and the client sees a truncated body.
func CopyVerified(w io.Writer, r *Verifier) (int64, error) { return copyHeld(w, r) }

// copyHeld is CopyVerified for any reader that returns io.EOF only once
// the content it read verified.
func copyHeld(w io.Writer, r io.Reader) (int64, error) {
	cur := make([]byte, copyChunk)
	next := make([]byte, copyChunk)
	var pending []byte
	var total int64
	for {
		// io.ReadFull turns a clean io.EOF from r into io.EOF or, after
		// a partial chunk, io.ErrUnexpectedEOF; any other error is a
		// failure of r.
		n, err := io.ReadFull(r, next)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return total, err
		}
		m, werr := w.Write(pending)
		total += int64(m)
		if werr != nil {
			return total, werr
		}
		if err != nil { // the content ended and verified
			m, werr = w.Write(next[:n])
			return total + int64(m), werr
		}
		cur, next = next, cur
		pending = cur[:n]
	}
}
