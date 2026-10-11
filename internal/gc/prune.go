package gc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
)

// A Pruner is a package's registration for records that keep blobs alive
// only for a while, such as an OCI repository's blob links, which are
// roots only while they are younger than the grace period or a manifest
// in their repository references their blob. A run removes the records
// that expired before it marks, so the blobs only they referenced become
// unreferenced and are swept as usual.
type Pruner interface {
	// Expired calls fn with each record in v that expired before cutoff,
	// until fn returns false.
	Expired(v meta.View, cutoff time.Time, fn func(Expired) bool)
	// Pruned is called with each record a run removed.
	Pruned(Expired)
}

// Expired is a record a Pruner found expired.
type Expired struct {
	Key []byte
	// Version is the version the record was found at. A run removes the
	// record only if it is still at that version when the removal
	// commits, so a record written meanwhile, such as a link a manifest
	// push rewrites when it references it, is kept.
	Version meta.Seq
	// Also lists keys removed with the record, such as records about it.
	Also [][]byte
	// Desc names the record in the log.
	Desc string
}

// expired is an expired record and the pruner that found it.
type expired struct {
	Expired
	p Pruner
}

// findExpired returns the records in v that expired before cutoff, and
// their keys and versions, which marking v skips.
func (c *Collector) findExpired(v meta.View, cutoff time.Time) ([]expired, map[string]meta.Seq) {
	var out []expired
	skip := map[string]meta.Seq{}
	for _, p := range c.pruners {
		p.Expired(v, cutoff, func(e Expired) bool {
			out = append(out, expired{e, p})
			skip[string(e.Key)] = e.Version
			return true
		})
	}
	return out, skip
}

// prune removes the expired records, in batches that require each record
// at the version it was found at. A batch that fails that precondition is
// committed again without the records that changed, which stay.
func (c *Collector) prune(ctx context.Context, r *Report, recs []expired) error {
	for len(recs) > 0 {
		chunk := recs[:min(len(recs), doomBatch)]
		recs = recs[len(chunk):]
		for len(chunk) > 0 {
			var b meta.Batch
			for _, e := range chunk {
				b.Require(e.Key, e.Version)
				b.Delete(e.Key)
				for _, k := range e.Also {
					b.Delete(k)
				}
			}
			b.SetOrigin(meta.Origin{Actor: r.Actor, Action: "gc.prune", Target: strconv.Itoa(len(chunk)) + " expired records"})
			_, err := c.meta.Commit(ctx, &b)
			if err == nil {
				break
			}
			if !errors.Is(err, meta.ErrConflict) {
				return fmt.Errorf("removing expired records: %w", err)
			}
			v := c.meta.View()
			chunk = slices.DeleteFunc(chunk, func(e expired) bool {
				rec, ok := v.Get(e.Key)
				return !ok || rec.Version != e.Version
			})
			v.Release()
		}
		for _, e := range chunk {
			c.log.Info("garbage collection removed an expired record", "record", e.Desc)
			e.p.Pruned(e.Expired)
		}
		c.update(r, func(r *Report) { r.Pruned += int64(len(chunk)) })
	}
	return nil
}
