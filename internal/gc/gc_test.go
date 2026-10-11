package gc

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

func TestGuard(t *testing.T) {
	ctx := context.Background()
	s, err := meta.Open("/meta", meta.Options{FS: fsys.NewMem(), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d := blob.FromBytes([]byte("x"))
	link := func() (*meta.Batch, error) {
		v := s.View()
		defer v.Release()
		var b meta.Batch
		err := Guard(v, &b, d)
		b.Put([]byte("link"), []byte{1})
		return &b, err
	}
	// Without a sweep, the batch commits.
	b, err := link()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, b); err != nil {
		t.Fatalf("a guarded batch failed: %v", err)
	}
	// A sweep that starts after the guard read fails the batch.
	b, _ = link()
	var start meta.Batch
	start.Put([]byte(EpochKey), []byte{1})
	if _, err := s.Commit(ctx, &start); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, b); !errors.Is(err, meta.ErrConflict) {
		t.Errorf("a batch guarded before a sweep started: %v, want ErrConflict", err)
	}
	// A running sweep that dooms the digest refuses the link.
	var doom meta.Batch
	doom.Put(DoomedKey(d), []byte{1})
	if _, err := s.Commit(ctx, &doom); err != nil {
		t.Fatal(err)
	}
	if _, err := link(); !errors.Is(err, ErrDoomed) {
		t.Errorf("linking a doomed digest: %v, want ErrDoomed", err)
	}
}
