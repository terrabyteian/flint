package blake2b

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The expected digests come from Python's hashlib.blake2b.
func TestVectors(t *testing.T) {
	seq := bytes.Repeat(func() []byte {
		b := make([]byte, 256)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}(), 5)
	for _, tt := range []struct {
		in   []byte
		size int
		want string
	}{
		{nil, 32, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
		{[]byte("abc"), 32, "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
		{bytes.Repeat([]byte("a"), 127), 32, "59e2f1aba240f20aa591016f5ef429990bc9c2131dcd0d30f0ffd75ed18f317d"},
		{bytes.Repeat([]byte("a"), 128), 32, "ae2aa48507885c4c950fb809b2076f959cde9f8ea6da260d9a3587df33dac450"},
		{bytes.Repeat([]byte("a"), 129), 32, "2f64744a6de0d2c0b56e64cf6e29a5aaa255010d415d51c75ccc82f73dccd865"},
		{bytes.Repeat([]byte("a"), 256), 32, "eae4d3a7627549b383179dc18049964f91a6fed14c9f3fb26705eda3eeda5558"},
		{seq, 32, "82628cbfc9689e234b0923a531f4578fe2e7138a03e2f81ed6cde97517336650"},
		{[]byte("abc"), 64, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"},
		{[]byte("abc"), 20, "384264f676f39536840523f284921cdc68b6846b"},
	} {
		h, err := New(tt.size)
		if err != nil {
			t.Fatal(err)
		}
		// Write in uneven pieces to exercise the buffering.
		for p := tt.in; len(p) > 0; {
			n := min(len(p), 1+len(p)%61)
			h.Write(p[:n])
			p = p[n:]
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != tt.want {
			t.Errorf("BLAKE2b-%d of %d bytes = %s, want %s", tt.size*8, len(tt.in), got, tt.want)
		}
		if h.Size() != tt.size || h.BlockSize() != BlockSize {
			t.Errorf("Size, BlockSize = %d, %d", h.Size(), h.BlockSize())
		}
		if tt.size == 32 {
			if got := Sum256(tt.in); hex.EncodeToString(got[:]) != tt.want {
				t.Errorf("Sum256 of %d bytes = %x", len(tt.in), got)
			}
		}
	}
}

func TestSumDoesNotChangeState(t *testing.T) {
	h := New256()
	h.Write([]byte("ab"))
	h.Sum(nil)
	h.Write([]byte("c"))
	if got := hex.EncodeToString(h.Sum(nil)); got != "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319" {
		t.Errorf("after an intermediate Sum: %s", got)
	}
	h.Reset()
	if got := hex.EncodeToString(h.Sum(nil)); got != "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8" {
		t.Errorf("after Reset: %s", got)
	}
}

func TestBadSize(t *testing.T) {
	for _, n := range []int{0, 65, -1} {
		if _, err := New(n); err == nil {
			t.Errorf("New(%d) succeeded", n)
		}
	}
}
