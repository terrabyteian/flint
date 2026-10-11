// Package blake2b implements unkeyed BLAKE2b (RFC 7693) with digests of 1
// to 64 bytes, which the Go standard library lacks. PyPI clients send a
// BLAKE2b-256 digest with every upload, and PyPI's JSON API reports one
// for every file.
package blake2b

import (
	"encoding/binary"
	"errors"
	"hash"
	"math/bits"
)

// BlockSize is BLAKE2b's block size in bytes.
const BlockSize = 128

// Size256 is the size of a BLAKE2b-256 digest in bytes.
const Size256 = 32

var iv = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var sigma = [12][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

// digest is the hash state.
type digest struct {
	size int
	h    [8]uint64
	t    [2]uint64 // bytes compressed so far, a 128-bit counter
	buf  [BlockSize]byte
	n    int // bytes in buf
}

// New returns a BLAKE2b hash with a digest of size bytes, from 1 to 64.
func New(size int) (hash.Hash, error) {
	if size < 1 || size > 64 {
		return nil, errors.New("blake2b: the digest size must be 1 to 64 bytes")
	}
	d := &digest{size: size}
	d.Reset()
	return d, nil
}

// New256 returns a BLAKE2b-256 hash.
func New256() hash.Hash {
	h, _ := New(Size256)
	return h
}

// Sum256 returns the BLAKE2b-256 digest of b.
func Sum256(b []byte) [Size256]byte {
	h := New256()
	h.Write(b)
	var out [Size256]byte
	h.Sum(out[:0])
	return out
}

func (d *digest) Size() int      { return d.size }
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() {
	d.h = iv
	d.h[0] ^= 0x01010000 ^ uint64(d.size) // no key, fanout and depth 1
	d.t = [2]uint64{}
	d.n = 0
}

func (d *digest) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		// The last block is compressed only in Sum, with the final flag,
		// so a full buffer waits until more data arrives.
		if d.n == BlockSize {
			d.add(BlockSize)
			d.compress(&d.buf, false)
			d.n = 0
		}
		c := copy(d.buf[d.n:], p)
		d.n += c
		p = p[c:]
	}
	return n, nil
}

func (d *digest) Sum(b []byte) []byte {
	c := *d
	c.add(uint64(c.n))
	clear(c.buf[c.n:])
	c.compress(&c.buf, true)
	var out [64]byte
	for i, v := range c.h {
		binary.LittleEndian.PutUint64(out[8*i:], v)
	}
	return append(b, out[:c.size]...)
}

// add counts n more bytes.
func (d *digest) add(n uint64) {
	var carry uint64
	d.t[0], carry = bits.Add64(d.t[0], n, 0)
	d.t[1] += carry
}

// compress mixes one block into the state.
func (d *digest) compress(block *[BlockSize]byte, final bool) {
	var m [16]uint64
	for i := range m {
		m[i] = binary.LittleEndian.Uint64(block[8*i:])
	}
	var v [16]uint64
	copy(v[:8], d.h[:])
	copy(v[8:], iv[:])
	v[12] ^= d.t[0]
	v[13] ^= d.t[1]
	if final {
		v[14] = ^v[14]
	}
	for i := range sigma {
		s := &sigma[i]
		g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := range d.h {
		d.h[i] ^= v[i] ^ v[i+8]
	}
}

// g is the mixing function G.
func g(v *[16]uint64, a, b, c, d int, x, y uint64) {
	v[a] += v[b] + x
	v[d] = bits.RotateLeft64(v[d]^v[a], -32)
	v[c] += v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -24)
	v[a] += v[b] + y
	v[d] = bits.RotateLeft64(v[d]^v[a], -16)
	v[c] += v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -63)
}
