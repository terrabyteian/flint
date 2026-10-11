// Package gc holds garbage collection's metadata keys and the
// precondition that every batch linking a blob carries, so a link and a
// concurrent sweep can never both succeed (see "Cleanup and data safety"
// in docs/design.md). The mark-and-sweep collector itself arrives with
// milestone M4.
//
//	gc\0epoch               GC epoch counter, incremented when a sweep starts
//	gc\0doomed\0<digest>    doomed set of the running sweep
package gc

import (
	"errors"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

const (
	// EpochKey is the GC epoch counter's key.
	EpochKey = "gc\x00epoch"
	// DoomedPrefix starts the keys of the running sweep's doomed set.
	DoomedPrefix = "gc\x00doomed\x00"
)

// ErrDoomed means a blob is about to be swept, so a batch must not link
// it; the client should retry, which uploads or fetches it again.
var ErrDoomed = errors.New("gc: the blob is being reclaimed")

// DoomedKey returns the doomed-set key of digest d.
func DoomedKey(d blob.Digest) []byte { return []byte(DoomedPrefix + d.String()) }

// Guard applies the garbage-collection precondition to a batch that
// links digests: it reads the GC epoch and each digest's doomed entry
// from v, fails with ErrDoomed if a digest is doomed, and requires the
// epoch to be unchanged when b commits. The caller must read v before
// checking that the blobs exist, so a sweep that starts after this read
// fails the precondition, and one already running is caught by its
// doomed entry.
func Guard(v meta.View, b *meta.Batch, ds ...blob.Digest) error {
	for _, d := range ds {
		if _, doomed := v.Get(DoomedKey(d)); doomed {
			return ErrDoomed
		}
	}
	epoch, _ := v.Get([]byte(EpochKey))
	b.Require([]byte(EpochKey), epoch.Version) // version 0 requires it absent
	return nil
}
