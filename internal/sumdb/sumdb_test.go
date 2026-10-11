package sumdb

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
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
	if tree.N != 68336369 {
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

// TestRealProof proves a record sum.golang.org served with the tiles it
// served, and the record's tree head consistent with a later one.
func TestRealProof(t *testing.T) {
	v, err := ParseKey(DefaultKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/latest")
	if err != nil {
		t.Fatal(err)
	}
	latest, err := v.OpenTree(b)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := os.ReadFile("testdata/lookup-uuid-v1.6.0")
	if err != nil {
		t.Fatal(err)
	}
	r, err := v.OpenLookup(lookup, "github.com/google/uuid", "v1.6.0")
	if err != nil {
		t.Fatal(err)
	}
	read := func(_ context.Context, path string, check func([]byte) error) ([]byte, error) {
		return os.ReadFile("testdata/" + path)
	}
	p, err := NewProver(ctx, r.Tree, read)
	if err != nil {
		t.Fatalf("the record's tree head: %v", err)
	}
	if err := p.Includes(ctx, r); err != nil {
		t.Errorf("the record: %v", err)
	}
	lp, err := NewProver(ctx, latest, read)
	if err != nil {
		t.Fatalf("the latest tree head: %v", err)
	}
	if err := lp.Consistent(ctx, r.Tree); err != nil {
		t.Errorf("the record's tree head and the latest: %v", err)
	}
	if err := lp.Includes(ctx, r); err != nil {
		t.Errorf("the record in the latest tree: %v", err)
	}
	// A record with other hashes, under the genuine signed tree head,
	// is not in the tree.
	forged := bytes.Replace(lookup, []byte("h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr"), []byte("h1:AAAAJDMOsjHA8n1jAhLSgzrAzy1Hgr"), 1)
	fr, err := v.OpenLookup(forged, "github.com/google/uuid", "v1.6.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Includes(ctx, fr); !errors.Is(err, ErrBadNote) {
		t.Errorf("a forged record: %v, want ErrBadNote", err)
	}
	// Neither is the genuine record under another number.
	fr.ID--
	fr.data = r.data
	if err := p.Includes(ctx, fr); !errors.Is(err, ErrBadNote) {
		t.Errorf("a record under another number: %v, want ErrBadNote", err)
	}
}

var ctx = context.Background()

// testLog is a checksum database's log, built from scratch with RFC
// 6962's definitions, which serves its tiles.
type testLog struct {
	records [][]byte
}

func newTestLog(n int) *testLog {
	l := &testLog{}
	for i := 0; i < n; i++ {
		l.records = append(l.records, fmt.Appendf(nil, "example.com/m%d v1.0.0 h1:zip=\nexample.com/m%d v1.0.0/go.mod h1:mod=\n", i, i))
	}
	return l
}

// mth returns the Merkle tree hash of records [lo, hi).
func (l *testLog) mth(lo, hi int64) Hash {
	if hi-lo == 1 {
		return sha256.Sum256(append([]byte{0}, l.records[lo]...))
	}
	k := int64(1)
	for k*2 < hi-lo {
		k *= 2
	}
	left, right := l.mth(lo, lo+k), l.mth(lo+k, hi)
	return sha256.Sum256(append(append([]byte{1}, left[:]...), right[:]...))
}

func (l *testLog) tree(n int64) Tree {
	if n == 0 {
		return Tree{}
	}
	return Tree{N: n, Hash: l.mth(0, n)}
}

// reader returns a TileReader of the log's tiles, recording the paths
// read and whether each came with a check; with noPartial, only full
// tiles are served.
func (l *testLog) reader(reads *[]string, noPartial bool) TileReader {
	return func(_ context.Context, path string, check func([]byte) error) ([]byte, error) {
		*reads = append(*reads, fmt.Sprintf("%s %v", path, check != nil))
		var level, w int
		var idx string
		rest, _ := strings.CutPrefix(path, "tile/8/")
		lv, rest, _ := strings.Cut(rest, "/")
		fmt.Sscan(lv, &level)
		idx, ws, partial := strings.Cut(rest, ".p/")
		w = tileWidth
		if partial {
			if noPartial {
				return nil, errors.New("no partial tiles")
			}
			fmt.Sscan(ws, &w)
		}
		i, _ := strconv.ParseInt(strings.ReplaceAll(strings.ReplaceAll(idx, "x", ""), "/", ""), 10, 64)
		size := int64(1) << (tileHeight * level)
		var b []byte
		for j := i * tileWidth; j < i*tileWidth+int64(w); j++ {
			if (j+1)*size > int64(len(l.records)) {
				return nil, errors.New("not found")
			}
			h := l.mth(j*size, (j+1)*size)
			b = append(b, h[:]...)
		}
		return b, nil
	}
}

func TestProver(t *testing.T) {
	const n = 1<<16 + 300
	l := newTestLog(n)
	for _, size := range []int64{1, 2, 3, 255, 256, 257, 1000, 1 << 16, n} {
		var reads []string
		p, err := NewProver(ctx, l.tree(size), l.reader(&reads, false))
		if err != nil {
			t.Fatalf("tree of %d: %v", size, err)
		}
		for _, id := range []int64{0, size / 3, size - 1} {
			r := &Record{ID: id, Path: "example.com/m", Version: "v1.0.0", data: l.records[id]}
			if err := p.Includes(ctx, r); err != nil {
				t.Errorf("record %d of %d: %v", id, size, err)
			}
			if id > 0 {
				r.data = l.records[id-1]
				if err := p.Includes(ctx, r); !errors.Is(err, ErrBadNote) {
					t.Errorf("record %d of %d with record %d's text: %v", id, size, id-1, err)
				}
			}
		}
		for _, other := range []int64{1, size / 2, size - 1, size} {
			if other == 0 {
				continue
			}
			if err := p.Consistent(ctx, l.tree(other)); err != nil {
				t.Errorf("trees of %d and %d: %v", size, other, err)
			}
		}
		if size < n {
			if err := p.Consistent(ctx, l.tree(size+1)); err == nil || errors.Is(err, ErrBadNote) {
				t.Errorf("tree of %d proving a larger tree: %v", size, err)
			}
		}
		// Partial tiles come without a check, full ones with one.
		for _, rd := range reads {
			if strings.Contains(rd, ".p/") != strings.HasSuffix(rd, "false") {
				t.Errorf("tree of %d: read %s", size, rd)
			}
		}
	}
	// A partial tile that is gone is read from the full tile.
	var reads []string
	p, err := NewProver(ctx, l.tree(1000), l.reader(&reads, true))
	if err != nil {
		t.Fatalf("without partial tiles: %v", err)
	}
	if err := p.Includes(ctx, &Record{ID: 999, data: l.records[999]}); err != nil {
		t.Errorf("without partial tiles: %v", err)
	}
	// A signed tree head of another log is not consistent.
	if p, err = NewProver(ctx, l.tree(1000), l.reader(&reads, false)); err != nil {
		t.Fatal(err)
	}
	fork := newTestLog(n)
	fork.records[500] = []byte("example.com/evil v1.0.0 h1:zip=\n")
	for _, size := range []int64{501, 1000} {
		if err := p.Consistent(ctx, fork.tree(size)); !errors.Is(err, ErrBadNote) {
			t.Errorf("a fork of %d records: %v, want ErrBadNote", size, err)
		}
	}
	fp, err := NewProver(ctx, fork.tree(n), fork.reader(&reads, false))
	if err != nil {
		t.Fatal(err)
	}
	if err := fp.Consistent(ctx, l.tree(1000)); !errors.Is(err, ErrBadNote) {
		t.Errorf("a fork's tiles and a tree of the log: %v, want ErrBadNote", err)
	}
	if err := p.Consistent(ctx, Tree{N: 1000, Hash: fork.tree(1000).Hash}); !errors.Is(err, ErrBadNote) {
		t.Errorf("another hash of the same size: %v", err)
	}
	// Tiles that do not compute the tree's hash prove nothing.
	if _, err := NewProver(ctx, fork.tree(1000), l.reader(&reads, false)); !errors.Is(err, ErrBadNote) {
		t.Errorf("tiles of another tree: %v", err)
	}
	// A full tile that does not match the tile above it is refused,
	// even if its reader skipped the check.
	p, err = NewProver(ctx, l.tree(n), l.reader(&reads, false))
	if err != nil {
		t.Fatal(err)
	}
	// A long-lived Prover keeps only its tree's partial tiles: the full
	// tiles its proofs read are read again from the reader, which caches
	// them.
	kept := len(p.tiles)
	reads = nil
	for id := int64(0); id < n; id += n / 40 {
		if err := p.Includes(ctx, &Record{ID: id, data: l.records[id]}); err != nil {
			t.Fatalf("record %d: %v", id, err)
		}
	}
	if len(p.tiles) != kept {
		t.Errorf("the Prover keeps %d tiles after proving records, want its %d partial tiles", len(p.tiles), kept)
	}
	if err := p.Includes(ctx, &Record{ID: 0, data: l.records[0]}); err != nil || reads[len(reads)-1] != "tile/8/0/000 true" {
		t.Errorf("proving record 0 again: %v, last read %q", err, reads[len(reads)-1])
	}
	// It is safe for concurrent use.
	var mu sync.Mutex
	locked := l.reader(&reads, false)
	p.read = func(c context.Context, path string, check func([]byte) error) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return locked(c, path, check)
	}
	var wg sync.WaitGroup
	for id := int64(0); id < n; id += n / 16 {
		wg.Go(func() {
			if err := p.Includes(ctx, &Record{ID: id, data: l.records[id]}); err != nil {
				t.Errorf("record %d, concurrently: %v", id, err)
			}
		})
	}
	wg.Wait()
	p, err = NewProver(ctx, l.tree(n), l.reader(&reads, false))
	if err != nil {
		t.Fatal(err)
	}
	tampered := func(c context.Context, path string, check func([]byte) error) ([]byte, error) {
		b, err := l.reader(&reads, false)(c, path, check)
		if err == nil && path == "tile/8/0/000" {
			b[0] ^= 1
			if check == nil || check(b) == nil {
				t.Errorf("the check passed a tampered tile")
			}
		}
		return b, err
	}
	p.read = tampered
	if err := p.Includes(ctx, &Record{ID: 0, data: l.records[0]}); !errors.Is(err, ErrBadNote) {
		t.Errorf("a tampered full tile: %v, want ErrBadNote", err)
	}
}

func TestTilePath(t *testing.T) {
	for want, tile := range map[string]struct {
		t int
		i int64
		w int
	}{
		"tile/8/0/000":            {0, 0, 256},
		"tile/8/1/x001/234.p/12":  {1, 1234, 12},
		"tile/8/2/x001/x000/000":  {2, 1000000, 256},
		"tile/8/0/x266/891.p/230": {0, 266891, 230},
	} {
		if got := tilePath(tile.t, tile.i, tile.w); got != want {
			t.Errorf("tilePath(%v) = %q, want %q", tile, got, want)
		}
	}
}
