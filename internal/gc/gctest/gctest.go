// Package gctest helps a format's tests prove that its garbage-collection
// marker covers every metadata record the format writes: a record under
// no registered prefix, or one its function cannot read, would make every
// garbage-collection run refuse to delete anything.
//
// A format's test writes every kind of record it can, such as by serving
// pushes, deletes, and uploads, and then calls CheckMarked or
// CheckStored on the store.
package gctest

import (
	"context"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
)

// CheckMarked fails t unless markers, with the gc package's own, cover
// every key in the store's latest state and read every record, and
// returns the digests the records reference.
func CheckMarked(t testing.TB, store meta.Store, markers ...gc.Marker) []blob.Digest {
	t.Helper()
	v := store.View()
	defer v.Release()
	refs, problems, err := gc.CheckMarker(v, markers...)
	if err != nil {
		t.Fatalf("marking the metadata: %v", err)
	}
	for _, p := range problems {
		t.Errorf("garbage collection would refuse to delete anything: %s", p)
	}
	return refs
}

// CheckStored is CheckMarked, and also fails t unless every blob the
// records reference is in blobs.
func CheckStored(t testing.TB, store meta.Store, blobs blob.Store, markers ...gc.Marker) []blob.Digest {
	t.Helper()
	refs := CheckMarked(t, store, markers...)
	for _, d := range refs {
		if _, err := blobs.Stat(context.Background(), d); err != nil {
			t.Errorf("blob %s, which the metadata references, is not stored: %v", d, err)
		}
	}
	return refs
}
