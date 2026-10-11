package sumdb

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestRealAnswers verifies answers sum.golang.org served, with its
// published key.
func TestRealAnswers(t *testing.T) {
	v, err := ParseKey(DefaultKey)
	if err != nil {
		t.Fatal(err)
	}
	if v.Name() != "sum.golang.org" {
		t.Errorf("name %q", v.Name())
	}
	latest, err := os.ReadFile("testdata/latest")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := v.OpenTree(latest)
	if err != nil {
		t.Fatalf("the latest tree head: %v", err)
	}
	if tree.N != 68325086 {
		t.Errorf("tree size %d", tree.N)
	}
	lookup, err := os.ReadFile("testdata/lookup-uuid-v1.6.0")
	if err != nil {
		t.Fatal(err)
	}
	r, err := v.OpenLookup(lookup, "github.com/google/uuid", "v1.6.0")
	if err != nil {
		t.Fatalf("the lookup: %v", err)
	}
	want := Record{ID: 22152757, Path: "github.com/google/uuid", Version: "v1.6.0",
		Zip: "h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=", Mod: "h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo="}
	if r.ID != want.ID || r.Path != want.Path || r.Version != want.Version || r.Zip != want.Zip || r.Mod != want.Mod {
		t.Errorf("record %+v, want %+v", r, want)
	}
	if _, err := v.OpenLookup(lookup, "github.com/google/uuid", "v1.5.0"); !errors.Is(err, ErrBadNote) {
		t.Errorf("the lookup read as another version's: %v", err)
	}
	// One flipped byte of the record's tree head breaks the signature.
	bad := bytes.Replace(lookup, []byte("go.sum database tree\n6"), []byte("go.sum database tree\n7"), 1)
	if _, err := v.OpenLookup(bad, "github.com/google/uuid", "v1.6.0"); !errors.Is(err, ErrBadNote) {
		t.Errorf("a tampered tree head verified: %v", err)
	}
}

func TestParseKey(t *testing.T) {
	_, key := newKey(t, "example.com")
	if v, err := ParseKey(key); err != nil || v.Name() != "example.com" {
		t.Fatalf("ParseKey(%q) = %v, %v", key, v, err)
	}
	name, rest, _ := strings.Cut(key, "+")
	hash, b64, _ := strings.Cut(rest, "+")
	for _, s := range []string{
		"",
		"sum.golang.org",
		"sum.golang.org+033de0ae",
		name + "+" + hash,
		name + "+00000000+" + b64,           // wrong hash
		name + "+zzzzzzzz+" + b64,           // not hexadecimal
		name + "+" + hash + "+!!!",          // not base64
		"other.example+" + hash + "+" + b64, // the hash covers the name
		name + "+" + hash + "+" + base64.StdEncoding.EncodeToString(make([]byte, 33)), // algorithm 0
		"has space+" + hash + "+" + b64,
	} {
		if _, err := ParseKey(s); err == nil {
			t.Errorf("ParseKey(%q) succeeded", s)
		}
	}
}

func TestOpen(t *testing.T) {
	priv, key := newKey(t, "example.com")
	otherPriv, _ := newKey(t, "other.example")
	v, err := ParseKey(key)
	if err != nil {
		t.Fatal(err)
	}
	text := "go.sum database tree\n5\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	signed := sign(text, "example.com", priv)
	if got, err := v.Open([]byte(signed)); err != nil || string(got) != text {
		t.Fatalf("Open = %q, %v", got, err)
	}
	// Signatures by other keys are skipped.
	both := signed + sigLine(text, "other.example", otherPriv)
	if _, err := v.Open([]byte(both)); err != nil {
		t.Errorf("a note with two signatures: %v", err)
	}
	for name, msg := range map[string]string{
		"unsigned":         text,
		"other signer":     sign(text, "other.example", otherPriv),
		"wrong key":        sign(text, "example.com", otherPriv),
		"tampered text":    strings.Replace(signed, "\n5\n", "\n6\n", 1),
		"no final newline": strings.TrimSuffix(signed, "\n"),
		"no em dash":       strings.Replace(signed, "—", "-", 1),
		"not base64":       text + "\n— example.com !!!\n",
		"short signature":  text + "\n— example.com AAAA\n",
	} {
		if _, err := v.Open([]byte(msg)); !errors.Is(err, ErrBadNote) {
			t.Errorf("%s: Open = %v, want ErrBadNote", name, err)
		}
	}
	if _, err := v.OpenTree([]byte(sign("not a tree\n", "example.com", priv))); !errors.Is(err, ErrBadNote) {
		t.Errorf("a note that is not a tree head: %v", err)
	}
	if _, err := v.OpenTree([]byte(sign("go.sum database tree\n05\nAAAA\n", "example.com", priv))); !errors.Is(err, ErrBadNote) {
		t.Errorf("a malformed tree head: %v", err)
	}
}

func TestOpenLookup(t *testing.T) {
	priv, key := newKey(t, "example.com")
	v, err := ParseKey(key)
	if err != nil {
		t.Fatal(err)
	}
	tree := sign("go.sum database tree\n10\n"+base64.StdEncoding.EncodeToString(make([]byte, 32))+"\n", "example.com", priv)
	record := "example.com/m v1.0.0 h1:zip=\nexample.com/m v1.0.0/go.mod h1:mod=\n"
	r, err := v.OpenLookup([]byte("3\n"+record+"\n"+tree), "example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != 3 || r.Zip != "h1:zip=" || r.Mod != "h1:mod=" || r.Tree.N != 10 {
		t.Errorf("record %+v", r)
	}
	for name, b := range map[string]string{
		"no number":       record + "\n" + tree,
		"beyond the tree": "10\n" + record + "\n" + tree,
		"no tree":         "3\n" + record,
		"no zip hash":     "3\nexample.com/m v1.0.0/go.mod h1:mod=\n\n" + tree,
		"other module":    "3\n" + strings.ReplaceAll(record, "example.com/m ", "example.com/n ") + "\n" + tree,
	} {
		if _, err := v.OpenLookup([]byte(b), "example.com/m", "v1.0.0"); !errors.Is(err, ErrBadNote) {
			t.Errorf("%s: OpenLookup = %v, want ErrBadNote", name, err)
		}
	}
}

// newKey returns a new private key and its public key in the
// "<name>+<hash>+<key>" form.
func newKey(t *testing.T, name string) (ed25519.PrivateKey, string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte{algEd25519}, pub...)
	return priv, fmt.Sprintf("%s+%08x+%s", name, keyHash(name, raw), base64.StdEncoding.EncodeToString(raw))
}

// sign returns text signed as name with priv.
func sign(text, name string, priv ed25519.PrivateKey) string {
	return text + "\n" + sigLine(text, name, priv)
}

func sigLine(text, name string, priv ed25519.PrivateKey) string {
	raw := append([]byte{algEd25519}, priv.Public().(ed25519.PublicKey)...)
	sig := binary.BigEndian.AppendUint32(nil, keyHash(name, raw))
	sig = append(sig, ed25519.Sign(priv, []byte(text))...)
	return "— " + name + " " + base64.StdEncoding.EncodeToString(sig) + "\n"
}
