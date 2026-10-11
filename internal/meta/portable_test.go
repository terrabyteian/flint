package meta

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/terrabyteian/flint/internal/fsys"
)

// dump returns every record in v as "key=value@version" lines.
func dump(v View) []string {
	var out []string
	v.Scan(nil, nil, func(k []byte, r Record) bool {
		out = append(out, fmt.Sprintf("%s=%s@%d", k, r.Value, r.Version))
		return true
	})
	return out
}

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 5000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			fs := fsys.NewMem()
			s := openStore(t, fs, Options{})
			for i := range n {
				commit(t, s, fmt.Sprintf("k%05d", i), fmt.Sprintf("v%d", i))
			}
			if n > 0 {
				commit(t, s, "k00000", "<del>")
			}
			v := s.PinView()
			defer v.Release()
			// A write after the pin is not in the snapshot.
			commit(t, s, "later", "x")

			var buf bytes.Buffer
			if err := WriteSnapshot(&buf, v); err != nil {
				t.Fatal(err)
			}
			got, err := ReadSnapshot(bytes.NewReader(buf.Bytes()), "test.snap")
			if err != nil {
				t.Fatal(err)
			}
			if got.Seq() != v.Seq() {
				t.Fatalf("seq %d, want %d", got.Seq(), v.Seq())
			}
			want := dump(v)
			if d := dump(got); fmt.Sprint(d) != fmt.Sprint(want) {
				t.Fatalf("read back %d records, want %d", len(d), len(want))
			}

			dst := fsys.NewMem()
			if err := Restore(testDir, got, Options{FS: dst}); err != nil {
				t.Fatal(err)
			}
			// Restore makes every step durable.
			dst = dst.Restart(nil)
			r := openStore(t, dst, Options{})
			rv := r.View()
			if rv.Seq() != v.Seq() || fmt.Sprint(dump(rv)) != fmt.Sprint(want) {
				t.Fatalf("restored store at %d with %d records, want %d with %d", rv.Seq(), len(dump(rv)), v.Seq(), len(want))
			}
			rv.Release()
			// The log continues after the snapshot, and versions carry over,
			// so preconditions written against the original still hold.
			var b Batch
			if n > 0 {
				rec, _ := got.Get([]byte("k00001"))
				b.Require([]byte("k00001"), rec.Version)
			}
			b.Put([]byte("new"), []byte("y"))
			seq, err := r.Commit(context.Background(), &b)
			if err != nil || seq != v.Seq()+1 {
				t.Fatalf("commit after restore: seq %d, %v; want %d", seq, err, v.Seq()+1)
			}
			r = reopen(t, r, dst, Options{})
			if rec, ok := r.View().Get([]byte("new")); !ok || string(rec.Value) != "y" {
				t.Fatal("commit after restore lost on reopen")
			}

			if err := Restore(testDir, got, Options{FS: dst}); err == nil {
				t.Fatal("Restore over an existing store succeeded")
			}
		})
	}
}

func TestReadSnapshotCorrupt(t *testing.T) {
	s := openStore(t, fsys.NewMem(), Options{})
	for i := range 100 {
		commit(t, s, fmt.Sprintf("k%03d", i), "value")
	}
	v := s.View()
	defer v.Release()
	var buf bytes.Buffer
	if err := WriteSnapshot(&buf, v); err != nil {
		t.Fatal(err)
	}
	good := buf.Bytes()
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", good[:len(good)-3]},
		{"flipped", func() []byte { b := bytes.Clone(good); b[len(b)/2] ^= 1; return b }()},
		{"trailing", append(bytes.Clone(good), 0)},
	} {
		if _, err := ReadSnapshot(bytes.NewReader(tc.data), "x.snap"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: err %v, want ErrCorrupt", tc.name, err)
		}
	}
}
