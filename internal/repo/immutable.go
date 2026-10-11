package repo

import (
	"context"
	"errors"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// Path-shaped formats, such as Maven and generic files, publish content
// under names that never change once published:
//
//   - Uploading identical content to a published name again succeeds
//     without a change, because build tools retry individual file uploads
//     and a retried deploy must not fail.
//   - Uploading different content to a published name is refused.
//   - Deleting a published name leaves a tombstone, and the name is never
//     usable again, not even with identical content, because a name that
//     comes back with other bytes breaks every build that pinned the old
//     ones.
//
// Publish-shaped formats (npm, Cargo, PyPI) refuse a duplicate version as
// their public registries do, and keep tombstones under the same rule.

// Errors Publish returns for a name it refuses. Formats answer both with
// 409 Conflict.
var (
	ErrPublished  = errors.New("the name is already published with different content")
	ErrTombstoned = errors.New("the name was deleted and can never be published again")
)

// Existing describes what a hosted repository holds under an immutable
// name.
type Existing struct {
	// Tombstone reports that the name was deleted.
	Tombstone bool
	// Digest is the published content's digest, if not a tombstone.
	Digest blob.Digest
}

// Decide applies the rule to an upload of content with digest d under a
// name whose record is e, or nil if the name was never used: it returns
// true if the upload is identical to what is published, which succeeds
// without a change; false if the name is free; or ErrPublished or
// ErrTombstoned.
func Decide(e *Existing, d blob.Digest) (unchanged bool, err error) {
	switch {
	case e == nil:
		return false, nil
	case e.Tombstone:
		return false, ErrTombstoned
	case e.Digest != d:
		return false, ErrPublished
	}
	return true, nil
}

// maxPublishAttempts bounds how often Publish retries a batch whose
// precondition failed.
const maxPublishAttempts = 4

// Publish publishes content with digest d under the immutable name whose
// metadata record is key, applying Decide to what the store holds. read
// decodes a record under key. write adds the publishing to a batch, read
// in view v: the record under key, any other records, the origin, and
// the garbage-collection precondition on the content; Publish makes the
// batch require key absent. It reports whether the store was changed:
// false for an identical re-upload. If a concurrent change fails the
// batch's preconditions, Publish decides again on what the store then
// holds, so of concurrent uploads of one name with identical content all
// succeed, and with different content exactly one does. An error write
// returns is returned as it is.
func Publish(ctx context.Context, store meta.Store, key []byte, d blob.Digest,
	read func(value []byte) (Existing, error), write func(v meta.View, b *meta.Batch) error) (bool, error) {
	var err error
	for range maxPublishAttempts {
		var changed bool
		changed, err = publishOnce(ctx, store, key, d, read, write)
		if !errors.Is(err, meta.ErrConflict) {
			return changed, err
		}
	}
	return false, err
}

func publishOnce(ctx context.Context, store meta.Store, key []byte, d blob.Digest,
	read func([]byte) (Existing, error), write func(meta.View, *meta.Batch) error) (bool, error) {
	v := store.View()
	defer v.Release()
	var e *Existing
	if rec, ok := v.Get(key); ok {
		x, err := read(rec.Value)
		if err != nil {
			return false, err
		}
		e = &x
	}
	if unchanged, err := Decide(e, d); err != nil || unchanged {
		return false, err
	}
	b := &meta.Batch{}
	b.Require(key, 0)
	if err := write(v, b); err != nil {
		return false, err
	}
	if _, err := store.Commit(ctx, b); err != nil {
		return false, err
	}
	return true, nil
}
