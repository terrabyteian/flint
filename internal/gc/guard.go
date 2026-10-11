package gc

import (
	"errors"
	"fmt"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// Metadata keys. The gc package owns the "gc\x00" namespace:
//
//	gc\0epoch             GC epoch counter, incremented by each round's start batch
//	gc\0doomed\0<digest>  doomed set of the round in progress; cleared when it ends
//	gc\0last              report of the last run that was not a dry run
const (
	// EpochKey is the GC epoch counter's key. Link batches require it
	// unchanged; see Guard.
	EpochKey     = "gc\x00epoch"
	doomedPrefix = "gc\x00doomed\x00"
	lastKey      = "gc\x00last"
)

// recordFormat is the schema version byte that starts every value the
// package writes.
const recordFormat = 1

// DoomedKey returns the key of digest d's entry in the doomed set.
func DoomedKey(d blob.Digest) []byte { return []byte(doomedPrefix + d.String()) }

// ErrDoomed means a link batch would link a blob that a running sweep
// is about to delete. The link must fail with an error the client can
// retry; once the sweep ends, the blob can be stored and linked again.
var ErrDoomed = errors.New("gc: the blob is being garbage collected")

// Guard applies the garbage-collection precondition to a batch b that
// makes the blobs ds visible (a link batch). It reads the GC epoch and
// each digest's doomed entry from v, fails with ErrDoomed if a digest is
// doomed there, and requires the epoch to be unchanged when b commits.
//
// The caller must read v before checking that the blobs exist, such as
// by committing their upload or checking a mount's source, and must
// rebuild the batch from a new view if the precondition fails. Then a
// link and a sweep cannot both succeed: a sweep that starts after v was
// read changes the epoch, so b fails, and one already running has doomed
// the digest in v.
//
// A batch that writes a record referencing a blob without linking it,
// such as a manifest record that lists its layers, needs no Guard for
// that blob if it requires, at the version it read, another record that
// references the blob and was itself written under these rules, such as
// the layer's link: a sweep keeps every blob such a record references.
func Guard(v meta.View, b *meta.Batch, ds ...blob.Digest) error {
	for _, d := range ds {
		if _, doomed := v.Get(DoomedKey(d)); doomed {
			return fmt.Errorf("%w: %s", ErrDoomed, d)
		}
	}
	epoch, _ := v.Get([]byte(EpochKey))
	b.Require([]byte(EpochKey), epoch.Version) // version 0 requires it absent
	return nil
}
