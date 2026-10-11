package audit

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
)

// ConsumerName is the name the audit log registers as a durable consumer
// of the metadata log.
const ConsumerName = "audit"

// Defaults for zero Options fields.
const (
	DefaultSegmentSize  = 64 << 20
	DefaultSegmentAge   = 24 * time.Hour
	DefaultPollInterval = time.Second
)

const (
	// flushBytes is how many bytes of records a catch-up buffers before
	// it writes, fsyncs, and checkpoints them.
	flushBytes = 4 << 20
	// retainInterval is how often retention runs, besides after each
	// rotation, unless the segment age is shorter.
	retainInterval = time.Hour
	// minSegmentSize and minSegmentAge bound the segment limits derived
	// from the retention limits.
	minSegmentSize = 64 << 10
	minSegmentAge  = time.Minute
)

// ErrClosed means the audit log is closed.
var ErrClosed = errors.New("audit: closed")

// Options configures a Log.
type Options struct {
	// Store is the metadata store whose batches are audited. Required.
	Store meta.Store
	// Dir is the stream's directory, normally <data>/audit. Required.
	Dir string
	// FS is the filesystem of Dir; nil means fsys.OS.
	FS fsys.FS
	// MaxAge, if positive, deletes segments whose newest record is older,
	// a whole segment at a time, and seals the active segment once its
	// records span SegmentAge even if no new record comes. Zero keeps
	// records forever.
	MaxAge time.Duration
	// MaxSize, if positive, deletes the oldest segments while the stream
	// is larger. The active segment is never deleted. Zero means no limit.
	MaxSize int64
	// SegmentSize is the size at which the stream rotates to a new
	// segment. Default DefaultSegmentSize, or a quarter of MaxSize if that
	// is smaller, but at least 64 KiB, so retention keeps the stream near
	// MaxSize.
	SegmentSize int64
	// SegmentAge is how long a segment takes records, by their commit
	// times, before the stream rotates, so MaxAge can delete old records
	// of a quiet registry. Default DefaultSegmentAge, or a quarter of
	// MaxAge if that is shorter, but at least a minute, so retention
	// deletes records soon after they pass MaxAge.
	SegmentAge time.Duration
	// PollInterval is how often Run checks the metadata store for new
	// batches. Default DefaultPollInterval.
	PollInterval time.Duration
	// Logger receives faults; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the audit metrics.
	Metrics *metrics.Registry
	// Now is the clock for retention; nil means time.Now.
	Now func() time.Time
}

// segment is a segment file. size is its durable size: for the active
// segment, the bytes written and fsynced so far.
type segment struct {
	first meta.Seq
	path  string
	size  int64
}

// Log is the audit log: a durable consumer of the metadata log that writes
// one record per batch to its own append-only stream.
type Log struct {
	store   meta.Store
	fs      fsys.FS
	dir     string
	log     *slog.Logger
	now     func() time.Time
	maxAge  time.Duration
	maxSize int64
	segSize int64
	segAge  time.Duration
	poll    time.Duration

	// wsem serializes writing: catch-up, rotation, retention, and Close.
	// The fields below it are guarded by it. It is a semaphore rather
	// than a mutex so that waiting for it can be cancelled.
	wsem       chan struct{}
	f          fsys.File // the active segment; nil after a failure until reopened
	start      time.Time // commit time of the active segment's first record, zero if it has none
	last       meta.Seq  // the last batch whose record is durable
	buf        []byte
	fault      error // the failure that stopped the latest catch-up, if any
	lastRetain time.Time
	closed     bool

	mu   sync.Mutex // guards segs, which readers copy
	segs []segment  // oldest first; the last one is active

	// durable and failing publish last and fault for Stats.
	durable atomic.Uint64
	failing atomic.Pointer[error]

	writeErrors *metrics.CounterSeries
}

// Open opens the audit stream in opts.Dir, creating it if needed,
// registers it as a consumer of opts.Store, and recovers from a crash:
// a torn record at the end of the active segment is truncated, since the
// metadata log still holds every batch after the consumer's checkpoint.
// It does not start consuming; call Run.
func Open(opts Options) (*Log, error) {
	if opts.Store == nil || opts.Dir == "" {
		return nil, errors.New("audit: Options.Store and Options.Dir are required")
	}
	l := &Log{
		store:   opts.Store,
		fs:      opts.FS,
		dir:     opts.Dir,
		log:     opts.Logger,
		now:     opts.Now,
		maxAge:  opts.MaxAge,
		maxSize: opts.MaxSize,
		segSize: opts.SegmentSize,
		segAge:  opts.SegmentAge,
		poll:    opts.PollInterval,
		wsem:    make(chan struct{}, 1),
	}
	if l.fs == nil {
		l.fs = fsys.OS
	}
	if l.log == nil {
		l.log = slog.Default()
	}
	if l.now == nil {
		l.now = time.Now
	}
	if l.segSize <= 0 {
		l.segSize = DefaultSegmentSize
		if l.maxSize > 0 {
			l.segSize = min(l.segSize, max(l.maxSize/4, minSegmentSize))
		}
	}
	if l.segAge <= 0 {
		l.segAge = DefaultSegmentAge
		if l.maxAge > 0 {
			l.segAge = min(l.segAge, max(l.maxAge/4, minSegmentAge))
		}
	}
	if l.poll <= 0 {
		l.poll = DefaultPollInterval
	}
	if err := l.fs.MkdirAll(l.dir, 0o750); err != nil {
		return nil, err
	}
	for _, d := range []string{filepath.Dir(l.dir), l.dir} {
		if err := l.fs.SyncDir(d); err != nil {
			return nil, err
		}
	}
	cp, err := l.store.RegisterConsumer(ConsumerName)
	if err != nil {
		return nil, fmt.Errorf("audit: registering with the metadata store: %w", err)
	}
	if err := l.recover(cp); err != nil {
		return nil, err
	}
	l.lastRetain = l.now()
	l.registerMetrics(opts.Metrics)
	return l, nil
}

// recover loads the segment list, checks the active segment, and opens
// it for appending. cp is the consumer's checkpoint: every record up to
// it was durable before the checkpoint was written.
func (l *Log) recover(cp meta.Seq) error {
	ents, err := l.fs.ReadDir(l.dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		name := e.Name()
		first, err := strconv.ParseUint(strings.TrimSuffix(name, segExt), 10, 64)
		if !strings.HasSuffix(name, segExt) || len(name) != 20+len(segExt) || err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		l.segs = append(l.segs, segment{first: meta.Seq(first), path: filepath.Join(l.dir, name), size: info.Size()})
	}
	slices.SortFunc(l.segs, func(a, b segment) int { return cmp.Compare(a.first, b.first) })

	last := cp // the last durable record, or the checkpoint without one
	for len(l.segs) > 0 {
		sg := &l.segs[len(l.segs)-1]
		got, err := l.recoverActive(sg, cp)
		if errors.Is(err, errTornSegment) {
			// A segment whose creation a crash interrupted; the
			// previous one is the active segment.
			if err := l.fs.Remove(sg.path); err != nil {
				return err
			}
			if err := l.fs.SyncDir(l.dir); err != nil {
				return err
			}
			l.segs = l.segs[:len(l.segs)-1]
			continue
		}
		if err != nil {
			return err
		}
		if got < cp {
			l.log.Warn("audit: the stream lacks records the metadata store's checkpoint covers; they are missing from the audit log",
				"from", got+1, "to", cp)
		}
		last = max(got, cp)
		break
	}
	if latest := l.latest(); last > latest {
		return fmt.Errorf("audit: the stream in %s holds batches up to %d, past the metadata store's latest batch %d; "+
			"if the metadata store was restored from a backup, move the audit directory aside and start again", l.dir, last, latest)
	}
	l.setLast(last)
	if len(l.segs) == 0 {
		return l.createSegment(last + 1)
	}
	sg := l.segs[len(l.segs)-1]
	f, err := l.fs.OpenFile(sg.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	l.f = f
	return nil
}

// errTornSegment means the final segment's header is incomplete: its
// creation was interrupted, and it holds no records.
var errTornSegment = errors.New("torn segment")

// recoverActive reads the active segment sg, truncating a bad tail made
// of records after checkpoint cp, and returns the last record's sequence
// number, or the segment's first minus one if it has none. It also sets
// l.start.
func (l *Log) recoverActive(sg *segment, cp meta.Seq) (meta.Seq, error) {
	f, err := l.fs.Open(sg.path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var hdr [segHeaderSize]byte
	n, err := io.ReadFull(f, hdr[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return 0, err
	}
	first, herr := parseSegHeader(hdr[:n])
	switch {
	case herr != nil && sg.size <= segHeaderSize:
		return 0, errTornSegment
	case herr != nil:
		return 0, &CorruptionError{Path: sg.path, Reason: herr.Error()}
	case first != sg.first:
		return 0, &CorruptionError{Path: sg.path, Reason: fmt.Sprintf("header names first batch %d", first)}
	}
	last := first - 1
	rr := newRecordReader(f, sg.size)
	for {
		at := rr.off
		rec, err := rr.next()
		if err == io.EOF {
			return last, nil
		}
		if err == nil && rec.Seq <= last {
			err = fmt.Errorf("%w: batch %d after batch %d", errBadRecord, rec.Seq, last)
		}
		if errors.Is(err, errBadRecord) {
			if last < cp {
				// The damage reaches records the checkpoint says were durable.
				return 0, &CorruptionError{Path: sg.path, Offset: at, Reason: err.Error()}
			}
			// A write torn by a crash, after the checkpoint: drop it.
			// The metadata log still holds those batches.
			if err := l.truncate(sg.path, at); err != nil {
				return 0, err
			}
			l.log.Warn("audit: truncated a torn write at the end of the stream", "path", sg.path, "offset", at)
			sg.size = at
			return last, nil
		}
		if err != nil {
			return 0, err
		}
		if l.start.IsZero() {
			l.start = rec.Time
		}
		last = rec.Seq
	}
}

// truncate cuts the file at path to size and makes that durable.
func (l *Log) truncate(path string, size int64) error {
	f, err := l.fs.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	err = f.Truncate(size)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// latest returns the metadata store's latest fsynced batch.
func (l *Log) latest() meta.Seq {
	v := l.store.View()
	defer v.Release()
	return v.Seq()
}

// createSegment creates the segment for records from first on and makes
// it the active segment. The header and the directory entry are durable
// before any record goes into it. On failure the partial file is removed
// where possible, and the previous segment stays active.
func (l *Log) createSegment(first meta.Seq) error {
	path := filepath.Join(l.dir, segName(first))
	f, err := l.fs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	_, err = f.Write(appendSegHeader(nil, first))
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = l.fs.SyncDir(l.dir)
	}
	if err != nil {
		f.Close()
		if rerr := l.fs.Remove(path); rerr == nil {
			l.fs.SyncDir(l.dir)
		}
		return err
	}
	if l.f != nil {
		if err := l.f.Close(); err != nil {
			l.log.Warn("audit: closing a segment", "err", err)
		}
	}
	l.f = f
	l.start = time.Time{}
	l.mu.Lock()
	l.segs = append(l.segs, segment{first: first, path: path, size: segHeaderSize})
	l.mu.Unlock()
	return nil
}

// reopen opens the active segment again after a failed write, cutting it
// back to its durable size: after a failed write or fsync, nothing past
// it can be trusted to reach the disk.
func (l *Log) reopen() error {
	l.mu.Lock()
	sg := l.segs[len(l.segs)-1]
	l.mu.Unlock()
	f, err := l.fs.OpenFile(sg.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	err = f.Truncate(sg.size)
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		f.Close()
		return err
	}
	l.f = f
	return nil
}

// writeErr marks a failure to write the stream, as opposed to a failure
// to read the metadata log.
type writeErr struct{ err error }

func (e *writeErr) Error() string { return "audit: writing the stream: " + e.err.Error() }
func (e *writeErr) Unwrap() error { return e.err }

// Sync writes the records of every batch the metadata store has made
// durable so far, makes them durable, and checkpoints them.
func (l *Log) Sync(ctx context.Context) error {
	select {
	case l.wsem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-l.wsem }()
	if l.closed {
		return ErrClosed
	}
	err := l.catchUp(ctx)
	l.setFault(err)
	if err == nil && l.lastRetain.Add(min(retainInterval, l.segAge)).Before(l.now()) {
		l.retain()
	}
	return err
}

// setFault records the outcome of a catch-up, logging when the stream
// starts and stops failing.
func (l *Log) setFault(err error) {
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, meta.ErrClosed)) {
		return
	}
	switch {
	case err != nil && l.fault == nil:
		l.log.Error("audit: cannot write the audit log; retrying, and the metadata store keeps the batches meanwhile", "err", err)
	case err == nil && l.fault != nil:
		l.log.Info("audit: writing the audit log again", "seq", l.last)
	}
	l.fault = err
	if err == nil {
		l.failing.Store(nil)
	} else {
		l.failing.Store(&err)
	}
}

func (l *Log) setLast(s meta.Seq) {
	l.last = s
	l.durable.Store(uint64(s))
}

// catchUp appends the records of the batches after l.last. It runs with
// l.wsem held.
func (l *Log) catchUp(ctx context.Context) error {
	if l.f == nil {
		if err := l.reopen(); err != nil {
			l.writeErrors.Inc()
			return &writeErr{err}
		}
	}
	if l.latest() <= l.last {
		return nil
	}
	pending, pendingLast, rotated := l.buf[:0], l.last, false
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		n, err := l.f.Write(pending)
		if err == nil && n < len(pending) {
			err = io.ErrShortWrite
		}
		if err == nil {
			err = l.f.Sync()
		}
		if err != nil {
			return &writeErr{err}
		}
		l.mu.Lock()
		l.segs[len(l.segs)-1].size += int64(len(pending))
		l.mu.Unlock()
		l.setLast(pendingLast)
		pending = pending[:0]
		return nil
	}
	err := l.store.ReadLog(ctx, l.last, func(e meta.Entry) error {
		l.mu.Lock()
		size := l.segs[len(l.segs)-1].size
		l.mu.Unlock()
		size += int64(len(pending))
		if size > segHeaderSize && (size >= l.segSize || !l.start.IsZero() && e.Time.Sub(l.start) >= l.segAge) {
			if err := flush(); err != nil {
				return err
			}
			if err := l.createSegment(e.Seq); err != nil {
				return &writeErr{err}
			}
			rotated = true
		}
		pending = appendRecord(pending, &e)
		pendingLast = e.Seq
		if l.start.IsZero() {
			l.start = e.Time
		}
		if len(pending) >= flushBytes {
			if err := flush(); err != nil {
				return err
			}
			l.checkpoint()
		}
		return nil
	})
	var we *writeErr
	if !errors.As(err, &we) {
		// The records read so far are good whatever stopped the read.
		if ferr := flush(); ferr != nil {
			err = ferr
		}
	}
	if cap(pending) <= flushBytes*2 {
		l.buf = pending[:0]
	}
	if errors.As(err, &we) {
		l.writeErrors.Inc()
		if l.f != nil {
			l.f.Close()
			l.f = nil
		}
		l.mu.Lock()
		empty := l.segs[len(l.segs)-1].size == segHeaderSize
		l.mu.Unlock()
		if empty {
			// The active segment's start was a record that is now gone.
			l.start = time.Time{}
		}
	}
	l.checkpoint()
	if rotated {
		l.retain()
	}
	return err
}

// checkpoint tells the metadata store that every batch up to l.last is
// audited, so it may delete their log segments.
func (l *Log) checkpoint() {
	if err := l.store.Checkpoint(ConsumerName, l.last); err != nil && !errors.Is(err, meta.ErrClosed) {
		// The records are durable; the next checkpoint covers them.
		l.log.Warn("audit: checkpointing the audit log", "err", err)
	}
}

// Run keeps the stream caught up with the metadata store until ctx is
// done, checking for new batches every PollInterval.
func (l *Log) Run(ctx context.Context) {
	t := time.NewTicker(l.poll)
	defer t.Stop()
	for {
		if err := l.Sync(ctx); errors.Is(err, ErrClosed) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Close writes the records of the batches committed so far, as Sync does,
// and closes the stream. Later calls return ErrClosed.
func (l *Log) Close() error {
	l.wsem <- struct{}{}
	defer func() { <-l.wsem }()
	if l.closed {
		return ErrClosed
	}
	err := l.catchUp(context.Background())
	if errors.Is(err, meta.ErrClosed) {
		err = nil
	}
	l.closed = true
	if l.f != nil {
		if cerr := l.f.Close(); err == nil {
			err = cerr
		}
		l.f = nil
	}
	return err
}

// retain deletes the oldest segments that retention no longer keeps. It
// runs with l.wsem held.
func (l *Log) retain() {
	now := l.now()
	l.lastRetain = now
	if l.maxAge <= 0 && l.maxSize <= 0 {
		return
	}
	if l.maxAge > 0 && l.f != nil && !l.start.IsZero() && now.Sub(l.start) >= l.segAge {
		// No new record has rotated the active segment, so seal it for
		// maxAge to delete in time.
		if err := l.createSegment(l.last + 1); err != nil {
			l.log.Warn("audit: sealing a quiet segment", "err", err)
		}
	}
	l.mu.Lock()
	segs := slices.Clone(l.segs)
	l.mu.Unlock()
	var total int64
	for _, sg := range segs {
		total += sg.size
	}
	n := 0
	for _, sg := range segs[:len(segs)-1] {
		drop := l.maxSize > 0 && total > l.maxSize
		if !drop && l.maxAge > 0 {
			// A sealed segment was last written when its newest record was.
			info, err := l.fs.Stat(sg.path)
			drop = err == nil && now.Sub(info.ModTime()) > l.maxAge
		}
		if !drop {
			break
		}
		if err := l.fs.Remove(sg.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			l.log.Warn("audit: deleting an old segment", "path", sg.path, "err", err)
			break
		}
		total -= sg.size
		n++
	}
	if n == 0 {
		return
	}
	l.mu.Lock()
	l.segs = slices.Delete(l.segs, 0, n)
	l.mu.Unlock()
	if err := l.fs.SyncDir(l.dir); err != nil {
		l.log.Warn("audit: deleting old segments", "err", err)
	}
	l.log.Info("audit: deleted old segments under the retention settings", "segments", n)
}

// Stats is a point-in-time report of the stream.
type Stats struct {
	Seq      meta.Seq // the last batch whose record is durable
	Segments int
	Bytes    int64
	// Fault is the failure that stopped the latest catch-up, or nil.
	Fault error
}

// Stats reports the stream's position and size.
func (l *Log) Stats() Stats {
	st := Stats{Seq: meta.Seq(l.durable.Load())}
	if e := l.failing.Load(); e != nil {
		st.Fault = *e
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	st.Segments = len(l.segs)
	for _, sg := range l.segs {
		st.Bytes += sg.size
	}
	return st
}

func (l *Log) registerMetrics(reg *metrics.Registry) {
	if reg == nil {
		reg = metrics.NewRegistry()
	}
	l.writeErrors = reg.Counter("flint_audit_write_errors_total",
		"Failed writes or fsyncs of the audit log, each retried.").With()
	reg.GaugeFunc("flint_audit_sequence", "Sequence number of the latest metadata batch the audit log holds durably.",
		func() float64 { return float64(l.Stats().Seq) })
	reg.GaugeFunc("flint_audit_lag", "Metadata batches committed but not yet in the audit log.",
		func() float64 {
			latest, last := l.latest(), l.Stats().Seq
			if latest < last {
				return 0
			}
			return float64(latest - last)
		})
	reg.GaugeFunc("flint_audit_segments", "Audit log segments on disk.",
		func() float64 { return float64(l.Stats().Segments) })
	reg.GaugeFunc("flint_audit_bytes", "Bytes in audit log segments on disk.",
		func() float64 { return float64(l.Stats().Bytes) })
	reg.GaugeFunc("flint_audit_failing", "1 if the latest attempt to write the audit log failed, else 0.",
		func() float64 {
			if l.Stats().Fault != nil {
				return 1
			}
			return 0
		})
}
