package repo

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

func TestDecide(t *testing.T) {
	a, b := blob.FromBytes([]byte("a")), blob.FromBytes([]byte("b"))
	for _, tt := range []struct {
		name      string
		e         *Existing
		d         blob.Digest
		unchanged bool
		err       error
	}{
		{"free name", nil, a, false, nil},
		{"identical re-upload", &Existing{Digest: a}, a, true, nil},
		{"different content", &Existing{Digest: a}, b, false, ErrPublished},
		{"tombstone, different content", &Existing{Tombstone: true}, b, false, ErrTombstoned},
		{"tombstone, identical content", &Existing{Tombstone: true, Digest: a}, a, false, ErrTombstoned},
	} {
		unchanged, err := Decide(tt.e, tt.d)
		if unchanged != tt.unchanged || err != tt.err {
			t.Errorf("%s: Decide = %v, %v; want %v, %v", tt.name, unchanged, err, tt.unchanged, tt.err)
		}
	}
}

// A test record: "T" for a tombstone, or "L" and the digest.
func readRecord(v []byte) (Existing, error) {
	switch {
	case len(v) == 1 && v[0] == 'T':
		return Existing{Tombstone: true}, nil
	case len(v) > 1 && v[0] == 'L':
		d, err := blob.ParseDigest(string(v[1:]))
		return Existing{Digest: d}, err
	}
	return Existing{}, errors.New("bad record")
}

func openStore(t *testing.T) meta.Store {
	t.Helper()
	s, err := meta.Open("/meta", meta.Options{FS: fsys.NewMem(), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestPublish checks the rule against the store: a first upload writes,
// an identical one changes nothing, a different one is refused, and once
// the name is a tombstone, no upload is accepted.
func TestPublish(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	key := []byte("test\x00file\x00repo\x00com/acme/lib-1.0.jar")
	a, b := blob.FromBytes([]byte("a")), blob.FromBytes([]byte("b"))
	writes := 0
	publish := func(d blob.Digest) (bool, error) {
		return Publish(ctx, s, key, d, readRecord, func(_ meta.View, bt *meta.Batch) error {
			writes++
			bt.Put(key, []byte("L"+d.String()))
			return nil
		})
	}
	if changed, err := publish(a); !changed || err != nil {
		t.Fatalf("first upload = %v, %v", changed, err)
	}
	if changed, err := publish(a); changed || err != nil {
		t.Errorf("identical re-upload = %v, %v; want unchanged", changed, err)
	}
	if changed, err := publish(b); changed || !errors.Is(err, ErrPublished) {
		t.Errorf("different upload = %v, %v; want ErrPublished", changed, err)
	}
	if writes != 1 {
		t.Errorf("%d batches written, want 1", writes)
	}
	tomb := &meta.Batch{}
	tomb.Put(key, []byte("T"))
	if _, err := s.Commit(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	for _, d := range []blob.Digest{a, b} {
		if changed, err := publish(d); changed || !errors.Is(err, ErrTombstoned) {
			t.Errorf("upload of %s after delete = %v, %v; want ErrTombstoned", d, changed, err)
		}
	}
	wantErr := errors.New("doomed")
	other := []byte("test\x00file\x00repo\x00other")
	if _, err := Publish(ctx, s, other, a, readRecord, func(meta.View, *meta.Batch) error { return wantErr }); err != wantErr {
		t.Errorf("Publish with a failing write = %v", err)
	}
	if _, err := Publish(ctx, s, key, a, func([]byte) (Existing, error) { return Existing{}, wantErr }, nil); err != wantErr {
		t.Errorf("Publish over an unreadable record = %v", err)
	}
}

// TestPublishConcurrent checks that of concurrent uploads of one name,
// those with the winner's content succeed and the others are refused.
func TestPublishConcurrent(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	key := []byte("test\x00file\x00repo\x00race")
	digests := []blob.Digest{blob.FromBytes([]byte("a")), blob.FromBytes([]byte("b"))}
	const n = 16
	errs := make([]error, n)
	changed := make([]bool, n)
	var wg sync.WaitGroup
	for i := range n {
		d := digests[i%2]
		wg.Go(func() {
			changed[i], errs[i] = Publish(ctx, s, key, d, readRecord, func(_ meta.View, b *meta.Batch) error {
				b.Put(key, []byte("L"+d.String()))
				return nil
			})
		})
	}
	wg.Wait()
	v := s.View()
	rec, _ := v.Get(key)
	v.Release()
	won, err := readRecord(rec.Value)
	if err != nil {
		t.Fatal(err)
	}
	writers := 0
	for i := range n {
		if changed[i] {
			writers++
		}
		want := error(nil)
		if digests[i%2] != won.Digest {
			want = ErrPublished
		}
		if !errors.Is(errs[i], want) && !(want == nil && errs[i] == nil) {
			t.Errorf("upload %d = %v, want %v", i, errs[i], want)
		}
	}
	if writers != 1 {
		t.Errorf("%d uploads wrote the record, want 1", writers)
	}
}
