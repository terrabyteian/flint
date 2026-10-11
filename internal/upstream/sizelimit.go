package upstream

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
)

// Size-limit intervals and batch sizes.
const (
	// PullFlushInterval is how often last-pull times are persisted.
	PullFlushInterval = time.Minute
	// pullBatch bounds the pull times persisted in one batch.
	pullBatch = 1000
	// evictBatch bounds the items evicted in one batch.
	evictBatch = 100
)

// Limits does the bookkeeping of a format's size-limited proxy
// repositories, whose cached items are metadata records, each tracked
// by a CacheTracker: it persists their last-pull times in periodic
// batches rather than one metadata write per pull, and evicts the least
// recently pulled items of a repository over its limit by deleting their
// records. Eviction removes metadata only; garbage collection reclaims
// the bytes once nothing links them, as for any delete.
type Limits struct {
	meta      meta.Store
	m         *Metrics
	format    string
	formatOf  func(string) string
	pulledKey func([]byte) []byte
	evictMore func(v meta.View, b *meta.Batch, repo, key string, rec meta.Record)
	evicted   func(keys []string)
	now       func() time.Time
	kick      chan struct{}

	mu       sync.Mutex
	trackers []*CacheTracker // sorted by repository
}

// LimitsOptions configures Limits.
type LimitsOptions struct {
	// Meta is the metadata store. Required.
	Meta meta.Store
	// Metrics, if not nil, receives the cached bytes and evictions.
	Metrics *Metrics
	// Format names the format in the origins of the batches, as
	// "<format>.proxy.pulled" and "<format>.proxy.evict". FormatOf, if
	// not nil, names it by repository instead, for repositories of
	// several formats.
	Format   string
	FormatOf func(repo string) string
	// PulledKey returns the key that holds the last-pull time of the
	// item whose record is at key. Required.
	PulledKey func(key []byte) []byte
	// EvictMore, if not nil, adds to b the further deletions evicting
	// the item at key, whose record is rec, needs, such as the tags
	// pointing to an evicted manifest.
	EvictMore func(v meta.View, b *meta.Batch, repo, key string, rec meta.Record)
	// Evicted, if not nil, is called with the keys of items an eviction
	// removed from their tracker, whose records it deleted or found gone.
	Evicted func(keys []string)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// NewLimits returns a Limits without repositories.
func NewLimits(opts LimitsOptions) *Limits {
	l := &Limits{meta: opts.Meta, m: opts.Metrics, format: opts.Format, formatOf: opts.FormatOf, pulledKey: opts.PulledKey,
		evictMore: opts.EvictMore, evicted: opts.Evicted, now: opts.Now, kick: make(chan struct{}, 1)}
	if l.now == nil {
		l.now = time.Now
	}
	return l
}

// Add adds a size-limited repository's tracker, whose items the caller
// has loaded, and asks for an eviction if it is over its limit.
func (l *Limits) Add(c *CacheTracker) {
	l.mu.Lock()
	l.trackers = append(l.trackers, c)
	slices.SortFunc(l.trackers, func(a, b *CacheTracker) int { return strings.Compare(a.Repo(), b.Repo()) })
	l.mu.Unlock()
	l.gauge(c)
	if c.Size() > c.Limit() {
		l.Kick()
	}
}

// Trackers returns the repositories' trackers, sorted by repository.
func (l *Limits) Trackers() []*CacheTracker {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.trackers)
}

func (l *Limits) gauge(c *CacheTracker) {
	if l.m != nil {
		l.m.CachedBytes.With(c.Repo()).Set(float64(c.Size()))
	}
}

func (l *Limits) formatName(repo string) string {
	if l.formatOf != nil {
		return l.formatOf(repo)
	}
	return l.format
}

// Kick asks for an eviction.
func (l *Limits) Kick() {
	select {
	case l.kick <- struct{}{}:
	default:
	}
}

// Kicked is signalled when an eviction is asked for.
func (l *Limits) Kicked() <-chan struct{} { return l.kick }

// Track records an item newly cached in c's repository, and asks for an
// eviction if the repository is now over its limit. c may be nil, for a
// repository without a limit.
func (l *Limits) Track(c *CacheTracker, key []byte, size int64) {
	if c == nil {
		return
	}
	over := c.Add(key, size, l.now())
	l.gauge(c)
	if over {
		l.Kick()
	}
}

// Touch records a pull of an item cached in c's repository; c may be nil.
func (l *Limits) Touch(c *CacheTracker, key []byte) {
	if c != nil {
		c.Touch(key, l.now())
	}
}

// Remove forgets items of c's repository whose records were deleted
// other than by eviction, such as by garbage collection.
func (l *Limits) Remove(c *CacheTracker, keys []string) {
	c.Remove(keys)
	l.gauge(c)
}

// LoadPulled loads the persisted pull times of the items whose records
// are under prefix into c.
func (l *Limits) LoadPulled(c *CacheTracker, v meta.View, prefix []byte) error {
	var failure error
	pk := l.pulledKey(prefix)
	v.Scan(pk, nil, func(k []byte, rec meta.Record) bool {
		t, err := DecodePulled(rec.Value)
		if err != nil {
			failure = err
			return false
		}
		c.LoadPulled(string(prefix)+string(k[len(pk):]), t)
		return true
	})
	return failure
}

// EncodePulled encodes a last-pull time, in Unix seconds.
func EncodePulled(t int64) []byte { return newEnc().varint(t) }

// DecodePulled decodes a last-pull time.
func DecodePulled(b []byte) (int64, error) {
	d := newDec(b)
	t := d.varint()
	return t, d.done()
}

// Flush persists the last-pull times recorded since the last flush.
func (l *Limits) Flush(ctx context.Context) error {
	for _, c := range l.Trackers() {
		dirty := c.TakeDirty()
		keys := make([]string, 0, len(dirty))
		for k := range dirty {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for len(keys) > 0 {
			chunk := keys[:min(len(keys), pullBatch)]
			keys = keys[len(chunk):]
			var b meta.Batch
			for _, k := range chunk {
				b.Put(l.pulledKey([]byte(k)), EncodePulled(dirty[k]))
			}
			b.SetOrigin(meta.Origin{Actor: meta.ActorSystem, Action: l.formatName(c.Repo()) + ".proxy.pulled", Target: c.Repo()})
			if _, err := l.meta.Commit(ctx, &b); err != nil {
				c.MarkDirty(chunk)
				c.MarkDirty(keys)
				return err
			}
		}
	}
	return nil
}

// Evict evicts the least recently pulled items of every repository that
// exceeds its limit.
func (l *Limits) Evict(ctx context.Context) error {
	for _, c := range l.Trackers() {
		victims := c.Victims()
		for len(victims) > 0 {
			chunk := victims[:min(len(victims), evictBatch)]
			victims = victims[len(chunk):]
			if err := l.evict(ctx, c, chunk); err != nil {
				return err
			}
		}
		l.gauge(c)
	}
	return nil
}

// evict removes items of c's repository in one batch. Each item must
// still be at the version read, so an item cached again meanwhile is not
// removed behind the tracker's back; such a conflict fails the batch,
// and the next eviction decides again.
func (l *Limits) evict(ctx context.Context, c *CacheTracker, keys []string) error {
	var b meta.Batch
	var gone []string
	v := l.meta.View()
	for _, k := range keys {
		key := []byte(k)
		rec, ok := v.Get(key)
		if !ok {
			gone = append(gone, k)
			continue
		}
		b.Require(key, rec.Version)
		b.Delete(key)
		b.Delete(l.pulledKey(key))
		if l.evictMore != nil {
			l.evictMore(v, &b, c.Repo(), k, rec)
		}
	}
	v.Release()
	l.forget(c, gone)
	if len(gone) == len(keys) {
		return nil
	}
	b.SetOrigin(meta.Origin{Actor: meta.ActorSystem, Action: l.formatName(c.Repo()) + ".proxy.evict",
		Target: c.Repo() + ": least recently pulled content over the size limit"})
	if _, err := l.meta.Commit(ctx, &b); err != nil {
		if errors.Is(err, meta.ErrConflict) {
			return nil
		}
		return err
	}
	l.forget(c, keys)
	if l.m != nil {
		l.m.Evictions.With(c.Repo()).Add(float64(len(keys) - len(gone)))
	}
	return nil
}

// forget removes evicted items from c's tracker.
func (l *Limits) forget(c *CacheTracker, keys []string) {
	c.Remove(keys)
	if l.evicted != nil {
		l.evicted(keys)
	}
}

// Run persists pull times every PullFlushInterval, calling tick after
// each flush, and evicts when asked, until ctx is done; then it persists
// the pull times once more.
func (l *Limits) Run(ctx context.Context, log func(msg string, err error), tick func()) {
	t := time.NewTicker(PullFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := l.Flush(fctx); err != nil {
				log("persisting proxy pull times", err)
			}
			cancel()
			return
		case <-t.C:
			if err := l.Flush(ctx); err != nil && ctx.Err() == nil {
				log("persisting proxy pull times", err)
			}
			if tick != nil {
				tick()
			}
		case <-l.kick:
			if err := l.Evict(ctx); err != nil && ctx.Err() == nil {
				log("evicting proxy content over its size limit", err)
			}
		}
	}
}
