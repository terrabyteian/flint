package upstream

import (
	"context"
	"errors"
	"fmt"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
)

// maxLinkAttempts bounds how often a linking batch is retried after a
// metadata precondition fails.
const maxLinkAttempts = 4

// ErrBusy means a batch linking a blob kept losing races with garbage
// collection or other writers; the client should retry.
var ErrBusy = errors.New("upstream: the cache is busy with this content; retry the request")

// commitLink commits a batch that links the blobs ds, under the
// garbage-collection precondition: the batch build fills is committed
// only if no sweep started since the blobs were found in the store, and
// retried when a precondition fails.
func commitLink(ctx context.Context, store meta.Store, blobs blob.Store, ds []blob.Digest, build func(v meta.View, b *meta.Batch)) error {
	for attempt := 0; ; attempt++ {
		v := store.View()
		var b meta.Batch
		err := gc.Guard(v, &b, ds...)
		if err == nil {
			build(v, &b)
		}
		v.Release()
		for _, d := range ds {
			if err != nil {
				break
			}
			if _, serr := blobs.Stat(ctx, d); errors.Is(serr, blob.ErrNotFound) {
				err = ErrBusy // swept since it was committed; the client asks again
			} else if serr != nil {
				err = fmt.Errorf("upstream: linking blob %s: %w", d, serr)
			}
		}
		if err == nil {
			_, err = store.Commit(ctx, &b)
		}
		switch {
		case err == nil:
			return nil
		case errors.Is(err, meta.ErrConflict) && attempt < maxLinkAttempts-1:
		case errors.Is(err, meta.ErrConflict), errors.Is(err, gc.ErrDoomed):
			return ErrBusy
		default:
			return err
		}
	}
}
