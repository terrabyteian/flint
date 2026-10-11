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
// roots only while they are within the grace period or a manifest in
// their repository references their blob. A run removes the records that
// expired before it marks, so the blobs only they referenced become
// unreferenced and are swept as usual.
type Pruner interface {
	// Expired calls fn with each record in v that expired before cutoff,
	// until fn returns false.
	Expired(v meta.View, cutoff time.Time, fn func(Expired) bool)
	// Remove calls remove with those of es, records Expired found, that
	// are still expired before cutoff, and keeps them from becoming
	// unexpired until remove returns. remove returns the records it
	// removed.
	Remove(cutoff time.Time, es []Expired, remove func([]Expired) ([]Expired, error)) error
}

// Expired is a record a Pruner found expired.
type Expired struct {
	Key []byte
	// Version is the version the record was found at. A run removes the
	// record only if it and every record in Requires are still at the
	// versions found when the removal commits.
	Version meta.Seq
	// Requires lists records that a write which would make the record
	// unexpired changes, such as a key every manifest push in an OCI
	// repository name writes, at the versions found; 0 means absent.
	Requires []Required
	// Also lists keys removed with the record, such as records about it.
	Also [][]byte
	// Desc names the record in the log.
	Desc string
}

// Required is a record at a version.
type Required struct {
	Key     []byte
	Version meta.Seq
}

// expired is an expired record and the pruner that found it.
type expired struct {
	Expired
	p Pruner
}

// findExpired returns the records in v that expired before cutoff, each
// pruner's together, and their keys and versions, which marking v skips.
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

// prune removes the expired records in batches, each through the pruner
// that found its records.
func (c *Collector) prune(ctx context.Context, r *Report, cutoff time.Time, recs []expired) error {
	for len(recs) > 0 {
		p := recs[0].p
		n := 1
		for n < len(recs) && n < doomBatch && recs[n].p == p {
			n++
		}
		es := make([]Expired, n)
		for i, e := range recs[:n] {
			es[i] = e.Expired
		}
		recs = recs[n:]
		if err := p.Remove(cutoff, es, func(es []Expired) ([]Expired, error) { return c.remove(ctx, r, es) }); err != nil {
			return err
		}
	}
	return nil
}

// remove removes records in one batch that requires each, and what it
// requires, at the version found. A batch that fails that precondition is
// committed again without the records whose versions changed, which stay.
// It returns the records it removed.
func (c *Collector) remove(ctx context.Context, r *Report, es []Expired) ([]Expired, error) {
	for len(es) > 0 {
		var b meta.Batch
		for _, e := range es {
			b.Require(e.Key, e.Version)
			for _, q := range e.Requires {
				b.Require(q.Key, q.Version)
			}
			b.Delete(e.Key)
			for _, k := range e.Also {
				b.Delete(k)
			}
		}
		b.SetOrigin(meta.Origin{Actor: r.Actor, Action: "gc.prune", Target: strconv.Itoa(len(es)) + " expired records"})
		_, err := c.meta.Commit(ctx, &b)
		if err == nil {
			break
		}
		if !errors.Is(err, meta.ErrConflict) {
			return nil, fmt.Errorf("removing expired records: %w", err)
		}
		v := c.meta.View()
		changed := func(key []byte, version meta.Seq) bool {
			rec, _ := v.Get(key)
			return rec.Version != version
		}
		es = slices.DeleteFunc(es, func(e Expired) bool {
			return changed(e.Key, e.Version) || slices.ContainsFunc(e.Requires, func(q Required) bool { return changed(q.Key, q.Version) })
		})
		v.Release()
	}
	for _, e := range es {
		c.log.Info("garbage collection removed an expired record", "record", e.Desc)
	}
	c.update(r, func(r *Report) { r.Pruned += int64(len(es)) })
	return es, nil
}
