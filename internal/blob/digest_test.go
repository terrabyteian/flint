package blob

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestParseDigest(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	tests := []struct {
		in   string
		want error // nil means valid
	}{
		{"sha256:" + hex64, nil},
		{"sha256:" + strings.Repeat("f", 64), nil},
		{"sha256:" + strings.ToUpper(hex64), ErrDigestInvalid},
		{"sha256:" + hex64[:63], ErrDigestInvalid},
		{"sha256:" + hex64 + "0", ErrDigestInvalid},
		{"sha256:" + hex64[:63] + "g", ErrDigestInvalid},
		{"sha256:", ErrDigestInvalid},
		{"sha256", ErrDigestInvalid},
		{":" + hex64, ErrDigestInvalid},
		{"", ErrDigestInvalid},
		{"SHA256:" + hex64, ErrDigestInvalid},
		{"sha256::" + hex64, ErrDigestInvalid},
		{"sha256:" + hex64 + " ", ErrDigestInvalid},
		{"sha512:" + strings.Repeat("ab", 64), ErrDigestUnsupported},
		{"sha384:" + strings.Repeat("ab", 48), ErrDigestUnsupported},
		{"blake3:abc", ErrDigestUnsupported},
		{"multihash+base58:QmRZxt2b1FVZPNqd8hsiykDL3TdBDeTSPX9Kv46HmX4Gx8", ErrDigestUnsupported},
		{"sha256+b64u:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564", ErrDigestUnsupported},
		{"a.b_c-d+e:x=_-", ErrDigestUnsupported},
		{"+sha256:" + hex64, ErrDigestInvalid},
		{"sha256+:" + hex64, ErrDigestInvalid},
		{"sha..256:" + hex64, ErrDigestInvalid},
		{"sha256:abc/def", ErrDigestInvalid},
		{"sha256:" + hex64 + "\n", ErrDigestInvalid},
	}
	for _, tt := range tests {
		d, err := ParseDigest(tt.in)
		if tt.want == nil {
			if err != nil {
				t.Errorf("ParseDigest(%q) = %v", tt.in, err)
			} else if d.String() != tt.in || d.IsZero() {
				t.Errorf("ParseDigest(%q).String() = %q", tt.in, d.String())
			}
			continue
		}
		if !errors.Is(err, tt.want) {
			t.Errorf("ParseDigest(%q) error = %v, want %v", tt.in, err, tt.want)
		}
		if !d.IsZero() {
			t.Errorf("ParseDigest(%q) returned a non-zero digest with an error", tt.in)
		}
	}
}

func TestParseDigestLongInputAbbreviated(t *testing.T) {
	_, err := ParseDigest(strings.Repeat("x", 10000))
	if !errors.Is(err, ErrDigestInvalid) || len(err.Error()) > 200 {
		t.Fatalf("error for a long input = %d bytes, %v", len(err.Error()), errors.Unwrap(err))
	}
}

func TestDigestBasics(t *testing.T) {
	var zero Digest
	if !zero.IsZero() || zero.String() != "" || zero.Hex() != "" {
		t.Fatalf("zero Digest: IsZero %v, String %q, Hex %q", zero.IsZero(), zero.String(), zero.Hex())
	}
	sum := sha256.Sum256([]byte("hello"))
	want := "sha256:" + hex.EncodeToString(sum[:])
	d := FromBytes([]byte("hello"))
	if d.String() != want || d.Hex() != want[len("sha256:"):] {
		t.Fatalf("FromBytes = %s, want %s", d, want)
	}
	p, err := ParseDigest(want)
	if err != nil || p != d {
		t.Fatalf("ParseDigest(%s) = %v, %v; want it equal to FromBytes", want, p, err)
	}
	if FromBytes([]byte("other")) == d {
		t.Fatal("different contents produced equal digests")
	}
}
