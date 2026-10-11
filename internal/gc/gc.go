// Package gc is flint's garbage collector: online mark-and-sweep of the
// blob store, run while the registry keeps serving reads and writes.
// docs/design.md (Cleanup and data safety) states the guarantees; this
// comment describes the algorithm that meets them.
//
// # Marking
//
// Every package that writes metadata registers a Marker: for each key
// prefix it owns, a function that returns the blobs a record under it
// references. Marking scans the keys under the registered prefixes of a
// metadata view and collects the referenced digests; it also scans the
// keys between the prefixes. A key under no registered prefix, or a
// record its function cannot read, makes the run refuse to delete
// anything and report why: nothing says which blobs such a record keeps
// alive, so a format that forgot to register can never lose data.
//
// # Sweeping
//
// A run marks a view M, then walks the blob store. A blob M does not
// reference whose commit is older than the grace period is a candidate.
// The grace period keeps blobs that are committed but not yet linked,
// such as an upload between its commit and its link batch, out of the
// doomed set, so links seldom have to retry.
//
// Candidates are swept in rounds of at most Options.RoundSize blobs:
//
//  1. Doom: the round's digests are written to the doomed set
//     (gc\0doomed\0<digest>) in batches, the last of which also
//     increments the GC epoch (gc\0epoch). That batch is the round's start
//     batch.
//  2. Verify: the round takes a view V, which follows the start batch,
//     and then reads the views pinned with the metadata store, such as a
//     running backup's, and scans each for references to doomed digests.
//  3. Delete: each doomed blob none of these views references is deleted
//     from the blob store and logged.
//  4. End: the doomed set is cleared.
//
// # Why a link and a sweep cannot both succeed
//
// Every link batch calls Guard with a view it read before checking that
// the blob exists, and is rebuilt from a new view if its precondition
// fails. Take a link of a digest that a round deletes:
//
//   - If the link commits before the start batch, V holds it, so the
//     blob is referenced and kept.
//   - If it commits after the start batch, the epoch it requires must be
//     the one the start batch wrote, so it read its view after the start
//     batch, where the digest is doomed, and Guard failed it.
//
// A record that references a blob without linking it must require,
// unchanged, a record that references the same blob, such as the link a
// manifest lists as a layer; that record was written by a batch these
// same rules cover, so the reference is in V or its batch failed.
//
// A view pinned before V was taken is among the pinned views the round
// reads after taking V. A view pinned later follows V, and every
// reference to a doomed digest it holds is in V too, since no reference
// to a doomed digest commits after the start batch. So the round deletes
// no blob a pinned view references, and a backup that pins its view
// finds every blob that view references.
//
// # Crashes
//
// A crash can leave a doomed set behind, which would fail every link of
// those digests. New clears it, and so does every run before it marks,
// so the interrupted round ends without further deletions and the next
// run starts over. A blob deleted before the crash was unreferenced in V
// and in every pinned view, and is no loss; one whose deletion was not
// yet durable may reappear, still unreferenced, for a later run.
//
// # Operation
//
// One run at a time: Run runs one and waits, Start runs one in the
// background, and RunSchedule starts one every Options.Interval. A dry
// run marks and checks like a real one but writes and deletes nothing,
// and reports the blobs it would delete. The report of the last run that
// was not a dry run is kept in the metadata (gc\0last), so the schedule
// and the status survive restarts.
package gc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
)

// Grace period, round, and schedule settings.
const (
	// DefaultGracePeriod is how long an unreferenced blob is kept after
	// its commit by default.
	DefaultGracePeriod = 24 * time.Hour
	// MinGracePeriod is the shortest grace period allowed. It covers the
	// time between a blob's commit and its link batch many times over,
	// and clock adjustments on the server.
	MinGracePeriod = time.Hour
	// DefaultRoundSize is how many blobs a sweep round dooms at most by
	// default.
	DefaultRoundSize = 50_000
	// doomBatch is how many doomed entries one metadata batch writes or
	// clears.
	doomBatch = 1000
	// clearTimeout bounds clearing a round's doomed set after its run
	// failed or was cancelled.
	clearTimeout = time.Minute
)

// scheduleDelay is the least time from startup to a scheduled run, so a
// restart loop does not run garbage collection on every start, and how
// long a scheduled run that found another run in progress waits after
// it. Tests shorten it.
var scheduleDelay = time.Minute

// Errors.
var (
	// ErrRunning means a run is already in progress.
	ErrRunning = errors.New("gc: a garbage collection run is already in progress")
	// ErrClosed means the collector is closed.
	ErrClosed = errors.New("gc: the garbage collector is shut down")
)

// errRefused ends a run that found metadata whose references are unknown.
var errRefused = errors.New("gc: refused to delete")

// Step names a point in a run, for Options.Hook.
type Step string

// Steps of a run, in order. The round steps repeat for each round.
const (
	StepMarked   Step = "marked"   // the metadata view is marked
	StepScanned  Step = "scanned"  // the blob store is walked; candidates are known
	StepDoomed   Step = "doomed"   // a round's start batch is committed
	StepViewed   Step = "viewed"   // a round took its view; it reads the pinned views next
	StepVerified Step = "verified" // a round's views are checked; deletions are next
	StepDeleted  Step = "deleted"  // a round's deletions are done; the doomed set is cleared next
)

// Options configures a Collector.
type Options struct {
	// Meta and Blobs are the stores. Required.
	Meta  meta.Store
	Blobs blob.Store
	// Markers are the markers of every package that writes metadata,
	// except the gc package's own.
	Markers []Marker
	// GracePeriod is how long an unreferenced blob is kept after its
	// commit. Zero means DefaultGracePeriod; less than MinGracePeriod is
	// an error.
	GracePeriod time.Duration
	// Interval, if positive, makes RunSchedule start a run this long
	// after the previous one that was not a dry run started.
	Interval time.Duration
	// RoundSize is how many blobs a sweep round dooms at most; zero
	// means DefaultRoundSize.
	RoundSize int
	// Logger receives the run logs; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the garbage-collection metrics.
	Metrics *metrics.Registry
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Hook, if set, is called at each step of a run, on the run's
	// goroutine, so tests can interleave other work with a run.
	Hook func(Step)
}

// RunOptions describes a run to start.
type RunOptions struct {
	// DryRun reports what the run would delete without changing anything.
	DryRun bool
	// Trigger is TriggerAPI or TriggerSchedule; empty means TriggerAPI.
	Trigger string
	// Actor names who started the run, for the report and the origin of
	// its metadata batches; empty means "system".
	Actor string
}

// Collector runs garbage collection.
type Collector struct {
	meta      meta.Store
	blobs     blob.Store
	reg       *registry
	grace     time.Duration
	interval  time.Duration
	roundSize int
	log       *slog.Logger
	now       func() time.Time
	hook      func(Step)
	created   time.Time

	ctx    context.Context // background runs; cancelled by Close
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.Mutex
	running   *Report // the run in progress, or nil
	last      *Report // the last finished run
	lastSweep time.Time
	closed    bool
	done      chan struct{} // closed when the run in progress ends

	runs        *metrics.Counter
	duration    *metrics.Histogram
	reclaimed   *metrics.CounterSeries
	reclaimedB  *metrics.CounterSeries
	lastSuccess *metrics.GaugeSeries
}

// New returns a Collector. It clears a doomed set an interrupted run
// left behind, so links of those blobs work again.
func New(opts Options) (*Collector, error) {
	if opts.Meta == nil || opts.Blobs == nil {
		return nil, errors.New("gc: Meta and Blobs are required")
	}
	marks, err := newRegistry(opts.Markers)
	if err != nil {
		return nil, err
	}
	switch {
	case opts.GracePeriod == 0:
		opts.GracePeriod = DefaultGracePeriod
	case opts.GracePeriod < MinGracePeriod:
		return nil, fmt.Errorf("gc: the grace period %s is shorter than the minimum %s", opts.GracePeriod, MinGracePeriod)
	}
	if opts.RoundSize <= 0 {
		opts.RoundSize = DefaultRoundSize
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Hook == nil {
		opts.Hook = func(Step) {}
	}
	c := &Collector{
		meta:      opts.Meta,
		blobs:     opts.Blobs,
		reg:       marks,
		grace:     opts.GracePeriod,
		interval:  max(opts.Interval, 0),
		roundSize: opts.RoundSize,
		log:       opts.Logger,
		now:       opts.Now,
		hook:      opts.Hook,
	}
	c.created = c.now()
	c.ctx, c.cancel = context.WithCancel(context.Background())

	v := c.meta.View()
	rec, ok := v.Get([]byte(lastKey))
	v.Release()
	if ok {
		if last, err := decodeReport(rec.Value); err != nil {
			c.log.Warn("gc: reading the report of the last garbage collection run", "err", err)
		} else {
			c.last, c.lastSweep = last, last.Started
		}
	}

	reg := opts.Metrics
	if reg == nil {
		reg = metrics.NewRegistry() // unexposed; keeps the metrics usable
	}
	c.runs = reg.Counter("flint_gc_runs_total",
		"Garbage collection runs, by mode (sweep, dry_run) and result (succeeded, refused, failed, cancelled).",
		"mode", "result")
	c.duration = reg.Histogram("flint_gc_duration_seconds", "Duration of garbage collection runs, by mode (sweep, dry_run).",
		[]float64{1, 5, 15, 60, 300, 900, 3600, 4 * 3600, 12 * 3600}, "mode")
	c.reclaimed = reg.Counter("flint_gc_reclaimed_blobs_total", "Blobs garbage collection deleted.").With()
	c.reclaimedB = reg.Counter("flint_gc_reclaimed_bytes_total", "Bytes of the blobs garbage collection deleted.").With()
	c.lastSuccess = reg.Gauge("flint_gc_last_success_timestamp_seconds",
		"Unix time the last successful garbage collection run that was not a dry run finished, or 0 if none has.").With()
	if c.last != nil && c.last.State == StateSucceeded {
		c.lastSuccess.Set(float64(c.last.Finished.Unix()))
	}
	reg.GaugeFunc("flint_gc_running", "1 while a garbage collection run is in progress, else 0.", func() float64 {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.running != nil {
			return 1
		}
		return 0
	})

	if n, err := c.clearDoomed(c.ctx, "system"); err != nil {
		c.log.Warn("gc: clearing the doomed set of an interrupted garbage collection run; the next run clears it",
			"err", err)
	} else if n > 0 {
		c.log.Warn("gc: cleared the doomed set of an interrupted garbage collection run", "blobs", n)
	}
	return c, nil
}

// GracePeriod returns the grace period.
func (c *Collector) GracePeriod() time.Duration { return c.grace }

// Status describes the run in progress, the last finished run, and the
// schedule.
type Status struct {
	Running     *Report    `json:"running"`
	Last        *Report    `json:"last"`
	GracePeriod string     `json:"gracePeriod"`
	Interval    string     `json:"interval,omitempty"`
	NextRun     *time.Time `json:"nextRun,omitempty"`
}

// Status returns the collector's status.
func (c *Collector) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := Status{GracePeriod: c.grace.String()}
	if c.running != nil {
		st.Running = c.running.clone()
	}
	if c.last != nil {
		st.Last = c.last.clone()
	}
	if c.interval > 0 {
		st.Interval = c.interval.String()
		next := c.nextRunLocked().UTC()
		st.NextRun = &next
	}
	return st
}

// nextRunLocked returns when the schedule runs next.
func (c *Collector) nextRunLocked() time.Time {
	next := c.created.Add(scheduleDelay)
	if !c.lastSweep.IsZero() {
		next = later(next, c.lastSweep.Add(c.interval))
	}
	return next
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// Run runs garbage collection and returns its report, which says how it
// ended. The error is ErrRunning or ErrClosed if no run started.
func (c *Collector) Run(ctx context.Context, opts RunOptions) (*Report, error) {
	r, err := c.begin(opts)
	if err != nil {
		return nil, err
	}
	return c.run(ctx, r), nil
}

// Start starts a run in the background and returns its report so far.
// Close cancels it.
func (c *Collector) Start(opts RunOptions) (*Report, error) {
	r, err := c.begin(opts)
	if err != nil {
		return nil, err
	}
	snapshot := c.snapshot()
	c.wg.Go(func() { c.run(c.ctx, r) })
	return snapshot, nil
}

// Wait waits until no run is in progress, or ctx is done.
func (c *Collector) Wait(ctx context.Context) error {
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close cancels a run in progress and waits for it to end. Later runs
// fail with ErrClosed.
func (c *Collector) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cancel()
	c.wg.Wait()
	c.Wait(context.Background())
}

// RunSchedule starts a run every Options.Interval until ctx is done; it
// returns at once if there is no interval. A run due while another is in
// progress waits for it.
func (c *Collector) RunSchedule(ctx context.Context) {
	if c.interval <= 0 {
		return
	}
	for {
		c.mu.Lock()
		wait := c.nextRunLocked().Sub(c.now())
		c.mu.Unlock()
		t := time.NewTimer(max(wait, 0))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		_, err := c.Run(ctx, RunOptions{Trigger: TriggerSchedule, Actor: "system"})
		switch {
		case errors.Is(err, ErrRunning):
			// A run started through the API; wait for it, then look again.
			c.Wait(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(scheduleDelay):
			}
		case errors.Is(err, ErrClosed):
			return
		}
	}
}

// begin registers a new run as the one in progress.
func (c *Collector) begin(opts RunOptions) (*Report, error) {
	if opts.Trigger == "" {
		opts.Trigger = TriggerAPI
	}
	if opts.Actor == "" {
		opts.Actor = "system"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrClosed
	}
	if c.running != nil {
		return nil, ErrRunning
	}
	r := &Report{
		DryRun:      opts.DryRun,
		Trigger:     opts.Trigger,
		Actor:       opts.Actor,
		State:       StateRunning,
		Phase:       PhaseMarking,
		Started:     c.now().UTC(),
		GracePeriod: c.grace.String(),
	}
	c.running = r
	c.done = make(chan struct{})
	return r, nil
}

// snapshot returns a copy of the report of the run in progress.
func (c *Collector) snapshot() *Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running == nil {
		return nil
	}
	return c.running.clone()
}

// update changes the report of the run in progress.
func (c *Collector) update(r *Report, f func(r *Report)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(r)
}

// run runs the registered run r and returns its final report.
func (c *Collector) run(ctx context.Context, r *Report) *Report {
	mode := "sweep"
	if r.DryRun {
		mode = "dry_run"
	}
	c.log.Info("garbage collection started", "dry_run", r.DryRun, "trigger", r.Trigger, "actor", r.Actor,
		"grace_period", r.GracePeriod)
	err := c.collect(ctx, r)

	c.mu.Lock()
	r.Phase = ""
	r.Finished = c.now().UTC()
	switch {
	case err == nil && len(r.Errors) > 0:
		r.State, r.Error = StateFailed, fmt.Sprintf("%d blobs could not be deleted", len(r.Errors))
	case err == nil:
		r.State = StateSucceeded
	case errors.Is(err, errRefused):
		r.State = StateRefused
	case ctx.Err() != nil && errors.Is(err, ctx.Err()):
		r.State, r.Error = StateCancelled, err.Error()
	default:
		r.State, r.Error = StateFailed, err.Error()
	}
	final := r.clone()
	c.mu.Unlock()

	if !r.DryRun {
		c.persist(final)
	}
	c.runs.With(mode, final.State).Inc()
	c.duration.With(mode).Observe(final.Finished.Sub(final.Started).Seconds())
	if final.State == StateSucceeded && !final.DryRun {
		c.lastSuccess.Set(float64(final.Finished.Unix()))
	}
	attrs := []any{"state", final.State, "dry_run", final.DryRun, "trigger", final.Trigger, "actor", final.Actor,
		"duration", final.Finished.Sub(final.Started).String(), "referenced", final.Referenced,
		"stored_blobs", final.Stored.Blobs, "stored_bytes", final.Stored.Bytes,
		"unreferenced_blobs", final.Unreferenced.Blobs, "in_grace_period_blobs", final.InGracePeriod.Blobs,
		"kept_blobs", final.Kept.Blobs, "deleted_blobs", final.Deleted.Blobs, "deleted_bytes", final.Deleted.Bytes}
	switch final.State {
	case StateSucceeded:
		c.log.Info("garbage collection finished", attrs...)
	case StateRefused:
		c.log.Warn("garbage collection refused to delete anything", append(attrs, "reasons", final.Refused)...)
	default:
		c.log.Error("garbage collection did not finish", append(attrs, "err", final.Error, "errors", final.Errors)...)
	}

	c.mu.Lock()
	c.running = nil
	c.last = final
	if !final.DryRun {
		c.lastSweep = final.Started
	}
	close(c.done)
	c.mu.Unlock()
	return final.clone()
}

// persist records the report of a run that was not a dry run.
func (c *Collector) persist(r *Report) {
	ctx, cancel := context.WithTimeout(context.Background(), clearTimeout)
	defer cancel()
	var b meta.Batch
	b.Put([]byte(lastKey), encodeReport(r))
	b.SetOrigin(meta.Origin{Actor: r.Actor, Action: "gc.report", Target: "garbage collection run " + r.State})
	if _, err := c.meta.Commit(ctx, &b); err != nil {
		c.log.Warn("gc: recording the report of the garbage collection run", "err", err)
	}
}

// collect marks, scans, and sweeps, recording what it finds in r.
func (c *Collector) collect(ctx context.Context, r *Report) error {
	// A doomed set left by an interrupted round would fail links for no
	// reason, and must not mix with this run's.
	if _, err := c.clearDoomed(ctx, r.Actor); err != nil {
		return fmt.Errorf("clearing a doomed set left behind: %w", err)
	}

	v := c.meta.View()
	marked := map[blob.Digest]struct{}{}
	s, err := c.reg.scan(ctx, v, func(d blob.Digest) { marked[d] = struct{}{} })
	v.Release()
	if err != nil {
		return err
	}
	refusal := s.refusal()
	c.update(r, func(r *Report) {
		r.Referenced = int64(len(marked))
		r.Phase = PhaseScanning
	})
	c.hook(StepMarked)

	cutoff := c.now().Add(-c.grace)
	var stored, unreferenced, inGrace Count
	var cands []blob.Info
	err = c.blobs.Walk(ctx, func(b blob.Info) error {
		stored.add(b.Size)
		if _, ok := marked[b.Digest]; ok {
			return nil
		}
		unreferenced.add(b.Size)
		if !b.ModTime.Before(cutoff) {
			inGrace.add(b.Size)
			return nil
		}
		cands = append(cands, b)
		return nil
	})
	marked = nil
	if err != nil {
		return fmt.Errorf("walking the blob store: %w", err)
	}
	c.update(r, func(r *Report) {
		r.Stored, r.Unreferenced, r.InGracePeriod = stored, unreferenced, inGrace
		r.Refused = refusal
		r.Phase = PhaseSweeping
	})
	c.hook(StepScanned)
	if refusal != nil {
		return errRefused
	}

	if r.DryRun {
		return c.dryRun(ctx, r, cands)
	}
	for len(cands) > 0 {
		round := cands[:min(len(cands), c.roundSize)]
		cands = cands[len(round):]
		if err := c.sweep(ctx, r, round); err != nil {
			return err
		}
	}
	return nil
}

// dryRun records which candidates a sweep would delete now.
func (c *Collector) dryRun(ctx context.Context, r *Report, cands []blob.Info) error {
	keep, pins, err := c.verify(ctx, r, digestSet(cands))
	if err != nil {
		return err
	}
	c.update(r, func(r *Report) {
		r.PinnedViews = max(r.PinnedViews, pins)
		for _, b := range cands {
			if keep[b.Digest] {
				r.Kept.add(b.Size)
				continue
			}
			r.Deleted.add(b.Size)
			if len(r.Blobs) < maxListed {
				r.Blobs = append(r.Blobs, blobInfo(b))
			} else {
				r.BlobsTruncated = true
			}
		}
	})
	return nil
}

func digestSet(bs []blob.Info) map[blob.Digest]bool {
	m := make(map[blob.Digest]bool, len(bs))
	for _, b := range bs {
		m[b.Digest] = true
	}
	return m
}

// sweep runs one round over the candidates in round.
func (c *Collector) sweep(ctx context.Context, r *Report, round []blob.Info) (err error) {
	defer func() {
		// End the round however it went: clear the doomed set, without
		// ctx's cancellation, so links of these blobs work again.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), clearTimeout)
		defer cancel()
		if _, cerr := c.clearDoomed(cctx, r.Actor); cerr != nil {
			c.log.Error("gc: clearing the doomed set; links of its blobs fail until a run or a restart clears it", "err", cerr)
			err = errors.Join(err, fmt.Errorf("clearing the doomed set: %w", cerr))
		}
	}()

	if err := c.doom(ctx, r, round); err != nil {
		return err
	}
	c.hook(StepDoomed)
	keep, pins, err := c.verify(ctx, r, digestSet(round))
	if err != nil {
		return err
	}
	c.update(r, func(r *Report) { r.PinnedViews = max(r.PinnedViews, pins) })
	c.hook(StepVerified)

	for _, b := range round {
		if keep[b.Digest] {
			c.log.Debug("gc: kept a blob that was linked again or that a pinned view references", "digest", b.Digest.String())
			c.update(r, func(r *Report) { r.Kept.add(b.Size) })
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		switch err := c.blobs.Delete(ctx, b.Digest); {
		case err == nil:
			c.log.Info("garbage collection deleted a blob", "digest", b.Digest.String(), "size", b.Size,
				"committed", b.ModTime.UTC())
			c.update(r, func(r *Report) { r.Deleted.add(b.Size) })
			c.reclaimed.Inc()
			c.reclaimedB.Add(float64(b.Size))
		case errors.Is(err, blob.ErrNotFound):
			// Already gone, such as deleted by hand.
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			c.log.Error("garbage collection could not delete a blob", "digest", b.Digest.String(), "err", err)
			c.update(r, func(r *Report) { r.addError(err.Error()) })
		}
	}
	c.hook(StepDeleted)
	return nil
}

// doom writes the round's doomed set and, in its last batch, the start
// batch, increments the GC epoch.
func (c *Collector) doom(ctx context.Context, r *Report, round []blob.Info) error {
	v := c.meta.View()
	epoch, _ := v.Get([]byte(EpochKey))
	v.Release()
	next := decodeEpoch(epoch.Value) + 1
	for i := 0; i < len(round); i += doomBatch {
		chunk := round[i:min(i+doomBatch, len(round))]
		var b meta.Batch
		for _, bl := range chunk {
			b.Put(DoomedKey(bl.Digest), []byte{recordFormat})
		}
		if i+len(chunk) == len(round) {
			// Only this collector writes the epoch; requiring it unchanged
			// keeps two collectors from interleaving all the same.
			b.Require([]byte(EpochKey), epoch.Version)
			b.Put([]byte(EpochKey), encodeEpoch(next))
		}
		b.SetOrigin(meta.Origin{Actor: r.Actor, Action: "gc.sweep.start",
			Target: strconv.Itoa(len(chunk)) + " unreferenced blobs, epoch " + strconv.FormatUint(next, 10)})
		if _, err := c.meta.Commit(ctx, &b); err != nil {
			return fmt.Errorf("writing the doomed set: %w", err)
		}
	}
	return nil
}

// verify takes a view, which follows the round's start batch, and then
// the pinned views, and returns which of the doomed digests they
// reference, and how many pinned views there were. The order matters: a
// view pinned after PinnedViews returns follows the first view, so it
// references no doomed digest the first view does not.
func (c *Collector) verify(ctx context.Context, r *Report, doomed map[blob.Digest]bool) (map[blob.Digest]bool, int, error) {
	views := []meta.View{c.meta.View()}
	c.hook(StepViewed)
	views = append(views, c.meta.PinnedViews()...)
	defer func() {
		for _, v := range views {
			v.Release()
		}
	}()
	keep := map[blob.Digest]bool{}
	mark := func(d blob.Digest) {
		if doomed[d] {
			keep[d] = true
		}
	}
	seen := map[meta.Seq]bool{}
	for _, v := range views {
		if seen[v.Seq()] {
			continue // the same state; its references are known
		}
		seen[v.Seq()] = true
		s, err := c.reg.scan(ctx, v, mark)
		if err != nil {
			return nil, 0, err
		}
		if refusal := s.refusal(); refusal != nil {
			c.update(r, func(r *Report) { r.Refused = refusal })
			return nil, 0, errRefused
		}
	}
	return keep, len(views) - 1, nil
}

// clearDoomed deletes every doomed entry and returns how many there were.
func (c *Collector) clearDoomed(ctx context.Context, actor string) (int, error) {
	n := 0
	for {
		var keys [][]byte
		v := c.meta.View()
		v.Scan([]byte(doomedPrefix), nil, func(k []byte, _ meta.Record) bool {
			keys = append(keys, bytes.Clone(k))
			return len(keys) < doomBatch
		})
		v.Release()
		if len(keys) == 0 {
			return n, nil
		}
		var b meta.Batch
		for _, k := range keys {
			b.Delete(k)
		}
		b.SetOrigin(meta.Origin{Actor: actor, Action: "gc.sweep.end", Target: strconv.Itoa(len(keys)) + " doomed blobs"})
		if _, err := c.meta.Commit(ctx, &b); err != nil {
			return n, err
		}
		n += len(keys)
	}
}

// An epoch value is the format byte and the counter as a uvarint.
func encodeEpoch(n uint64) []byte { return binary.AppendUvarint([]byte{recordFormat}, n) }

// decodeEpoch returns the counter, or 0 if v is absent or unreadable;
// links require the key's version, not its value, so the counter is
// only informative.
func decodeEpoch(v []byte) uint64 {
	if len(v) < 2 || v[0] != recordFormat {
		return 0
	}
	n, _ := binary.Uvarint(v[1:])
	return n
}
