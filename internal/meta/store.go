package meta

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

const (
	defaultSegmentSize   = 64 << 20
	defaultSnapshotBytes = 128 << 20
	// maxGroupBytes bounds one group commit's write, so a burst of
	// commits does not build one huge buffer. A single batch may exceed it.
	maxGroupBytes = 8 << 20
)

// published is an immutable state of the index that readers may see.
type published struct {
	t   tree
	seq Seq
}

type store struct {
	fs      fsys.FS
	walDir  string
	snapDir string
	consDir string
	log     *slog.Logger
	now     func() time.Time

	segmentSize   int64
	snapshotBytes int64
	maxBody       int

	// state is the latest fsynced state.
	state atomic.Pointer[published]

	// The commit queue.
	qmu     sync.Mutex
	queue   []*request
	closing bool
	wake    chan struct{}

	// Owned by the writer goroutine.
	active   fsys.File
	salt     uint32
	nextSeq  Seq
	groupBuf []byte

	poison atomic.Pointer[error]

	mu        sync.Mutex // guards the fields below
	segs      []segment  // segments on disk; the last one is active
	consumers map[string]Seq
	leases    map[*lease]struct{}
	pins      []*view
	snapSeq   Seq
	closed    bool

	consMu sync.Mutex // serializes consumer file updates
	snapMu sync.Mutex // serializes snapshots

	sinceSnap  atomic.Int64 // log bytes written since the last snapshot started
	maintWake  chan struct{}
	stop       chan struct{}
	writerDone chan struct{}
	maintDone  chan struct{}

	commits      atomic.Uint64
	conflicts    atomic.Uint64
	groups       atomic.Uint64
	snapshots    atomic.Uint64
	snapErrors   atomic.Uint64
	activeOffset atomic.Int64
}

// Open opens or creates the store in dir (the data directory's meta/),
// loading the latest snapshot and replaying the log.
func Open(dir string, opts Options) (Store, error) {
	s := &store{
		fs:            opts.FS,
		walDir:        filepath.Join(dir, "wal"),
		snapDir:       filepath.Join(dir, "snapshots"),
		consDir:       filepath.Join(dir, "consumers"),
		log:           opts.Logger,
		now:           opts.Now,
		segmentSize:   opts.SegmentSize,
		snapshotBytes: opts.SnapshotBytes,
		maxBody:       opts.MaxBatchBytes,
		wake:          make(chan struct{}, 1),
		maintWake:     make(chan struct{}, 1),
		stop:          make(chan struct{}),
		writerDone:    make(chan struct{}),
		maintDone:     make(chan struct{}),
		leases:        map[*lease]struct{}{},
	}
	if s.fs == nil {
		s.fs = fsys.OS
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.segmentSize <= 0 {
		s.segmentSize = defaultSegmentSize
	}
	if s.snapshotBytes == 0 {
		s.snapshotBytes = defaultSnapshotBytes
	}
	if s.maxBody <= 0 {
		s.maxBody = defaultMaxBody
	}
	s.maxBody = min(s.maxBody, maxBodySize)

	if err := s.mkdirs(dir); err != nil {
		return nil, err
	}
	var err error
	if s.consumers, err = s.loadConsumers(); err != nil {
		return nil, err
	}
	t, snap, snapErr := s.loadSnapshot()
	if t.root == nil {
		return nil, snapErr
	}
	acked, floor := snap, snap
	for _, cp := range s.consumers {
		acked = max(acked, cp)
		floor = min(floor, cp)
	}
	x := t.txn()
	rec, err := s.recoverLog(x, snap, acked, floor)
	if err != nil {
		// A skipped snapshot is part of the story if the log cannot make up for it.
		return nil, errors.Join(err, snapErr)
	}
	s.snapSeq = snap
	s.segs = rec.segs
	s.nextSeq = rec.last + 1
	s.state.Store(&published{t: x.tree(), seq: rec.last})

	if rec.active {
		last := s.segs[len(s.segs)-1]
		f, err := s.fs.OpenFile(last.path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return nil, err
		}
		s.active, s.salt = f, rec.salt
		s.activeOffset.Store(last.size)
	} else {
		f, sg, salt, err := s.createSegment(s.nextSeq)
		if err != nil {
			return nil, err
		}
		s.active, s.salt = f, salt
		s.segs = append(s.segs, sg)
		s.activeOffset.Store(sg.size)
	}
	if err := s.retain(); err != nil {
		s.log.Warn("meta: deleting old log segments at startup", "err", err)
	}
	go s.writer()
	go s.maintain()
	return s, nil
}

// mkdirs creates the store's directories and makes them durable.
func (s *store) mkdirs(dir string) error {
	for _, d := range []string{s.walDir, s.snapDir, s.consDir} {
		if err := s.fs.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := s.fs.SyncDir(d); err != nil {
			return err
		}
	}
	return nil
}

// request is one pending Commit.
type request struct {
	b     *Batch
	state atomic.Int32
	seq   Seq
	err   error
	done  chan struct{}
}

const (
	reqQueued int32 = iota
	reqClaimed
	reqCanceled
)

func (s *store) Commit(ctx context.Context, b *Batch) (Seq, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if b.size > s.maxBody {
		return 0, ErrBatchTooLarge
	}
	r := &request{b: b, done: make(chan struct{})}
	s.qmu.Lock()
	if s.closing {
		s.qmu.Unlock()
		return 0, ErrClosed
	}
	if p := s.poison.Load(); p != nil {
		s.qmu.Unlock()
		return 0, &poisonedError{*p}
	}
	s.queue = append(s.queue, r)
	s.qmu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	select {
	case <-r.done:
	case <-ctx.Done():
		if r.state.CompareAndSwap(reqQueued, reqCanceled) {
			return 0, ctx.Err()
		}
		<-r.done
	}
	return r.seq, r.err
}

// writer is the single goroutine that writes the log. Each round takes
// every queued request, checks preconditions in order against the state
// including the earlier batches of the round, writes all records with one
// write, fsyncs once, publishes the new state, and only then answers.
func (s *store) writer() {
	defer close(s.writerDone)
	for {
		s.qmu.Lock()
		for len(s.queue) == 0 && !s.closing {
			s.qmu.Unlock()
			<-s.wake
			s.qmu.Lock()
		}
		if s.closing {
			q := s.queue
			s.queue = nil
			s.qmu.Unlock()
			for _, r := range q {
				if r.state.CompareAndSwap(reqQueued, reqClaimed) {
					s.answer(r, 0, ErrClosed)
				}
			}
			return
		}
		n, size := 0, 0
		for n < len(s.queue) && (n == 0 || size+s.queue[n].b.size <= maxGroupBytes) {
			size += s.queue[n].b.size
			n++
		}
		reqs := slices.Clone(s.queue[:n])
		s.queue = append(s.queue[:0], s.queue[n:]...)
		s.qmu.Unlock()
		s.commitGroup(reqs)
	}
}

func (s *store) answer(r *request, seq Seq, err error) {
	r.seq, r.err = seq, err
	close(r.done)
}

func (s *store) commitGroup(reqs []*request) {
	claimed := reqs[:0]
	for _, r := range reqs {
		if r.state.CompareAndSwap(reqQueued, reqClaimed) {
			claimed = append(claimed, r)
		}
	}
	reqs = claimed
	if len(reqs) == 0 {
		return
	}
	if p := s.poison.Load(); p != nil {
		for _, r := range reqs {
			s.answer(r, 0, &poisonedError{*p})
		}
		return
	}
	if s.activeOffset.Load() >= s.segmentSize {
		if err := s.rotate(); err != nil {
			s.poisonWith(err)
			for _, r := range reqs {
				s.answer(r, 0, &poisonedError{err})
			}
			return
		}
	}

	x := s.state.Load().t.txn()
	group := s.nextSeq
	buf := s.groupBuf[:0]
	now := s.now()
	type outcome struct {
		r   *request
		seq Seq
		err error
	}
	outs := make([]outcome, 0, len(reqs))
	written := 0
	for _, r := range reqs {
		if err := checkRequires(x, r.b); err != nil {
			outs = append(outs, outcome{r: r, err: err})
			continue
		}
		start := len(buf)
		buf = appendRecord(buf, s.salt, s.nextSeq, group, now, r.b)
		if len(buf)-start-frameSize > s.maxBody {
			buf = buf[:start]
			outs = append(outs, outcome{r: r, err: ErrBatchTooLarge})
			continue
		}
		applyOps(x, r.b.ops, s.nextSeq)
		outs = append(outs, outcome{r: r, seq: s.nextSeq})
		s.nextSeq++
		written++
	}
	if cap(buf) <= maxGroupBytes {
		s.groupBuf = buf
	}
	if written > 0 {
		n, err := s.active.Write(buf)
		if err == nil && n < len(buf) {
			err = io.ErrShortWrite
		}
		if err == nil {
			err = s.active.Sync()
		}
		if err != nil {
			s.poisonWith(err)
			for _, o := range outs {
				if o.seq != 0 {
					s.answer(o.r, 0, &writeFailure{err})
				} else {
					s.answer(o.r, 0, &poisonedError{err})
				}
			}
			return
		}
		last := s.nextSeq - 1
		s.state.Store(&published{t: x.tree(), seq: last})
		off := s.activeOffset.Add(int64(len(buf)))
		s.mu.Lock()
		s.segs[len(s.segs)-1].size = off
		s.mu.Unlock()
		s.groups.Add(1)
		s.commits.Add(uint64(written))
		if s.snapshotBytes > 0 && s.sinceSnap.Add(int64(len(buf))) >= s.snapshotBytes {
			s.kickMaintenance()
		}
	}
	for _, o := range outs {
		if errors.Is(o.err, ErrConflict) {
			s.conflicts.Add(1)
		}
		s.answer(o.r, o.seq, o.err)
	}
}

func checkRequires(x *txn, b *Batch) error {
	for _, rq := range b.reqs {
		var have Seq
		if r, ok := x.get(rq.key); ok {
			have = r.Version
		}
		if have != rq.v {
			return fmt.Errorf("%w: key %q is at version %d, want %d", ErrConflict, rq.key, have, rq.v)
		}
	}
	return nil
}

// rotate starts a new active segment. It runs on the writer goroutine,
// between group commits, so the old segment is fully fsynced.
func (s *store) rotate() error {
	f, sg, salt, err := s.createSegment(s.nextSeq)
	if err != nil {
		return err
	}
	if err := s.active.Close(); err != nil {
		s.log.Warn("meta: closing log segment", "err", err)
	}
	s.active, s.salt = f, salt
	s.activeOffset.Store(sg.size)
	s.mu.Lock()
	s.segs = append(s.segs, sg)
	s.mu.Unlock()
	return nil
}

func (s *store) poisonWith(err error) {
	if s.poison.CompareAndSwap(nil, &err) {
		s.log.Error("meta: log write failed; rejecting writes until restart, reads continue", "err", err)
	}
}

func (s *store) kickMaintenance() {
	select {
	case s.maintWake <- struct{}{}:
	default:
	}
}

// maintain runs background snapshots and log retention.
func (s *store) maintain() {
	defer close(s.maintDone)
	for {
		select {
		case <-s.stop:
			return
		case <-s.maintWake:
		}
		if s.snapshotBytes > 0 && s.sinceSnap.Load() >= s.snapshotBytes {
			s.sinceSnap.Store(0)
			s.snapshot()
		} else {
			s.retain()
		}
	}
}

func (s *store) Snapshot() error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	s.sinceSnap.Store(0)
	return s.snapshot()
}

func (s *store) Close() error {
	s.qmu.Lock()
	if s.closing {
		s.qmu.Unlock()
		return nil
	}
	s.closing = true
	s.qmu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	<-s.writerDone
	close(s.stop)
	<-s.maintDone
	s.snapMu.Lock() // wait for a Snapshot call in progress
	s.consMu.Lock()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.consMu.Unlock()
	s.snapMu.Unlock()
	return s.active.Close()
}

func (s *store) Stats() Stats {
	p := s.state.Load()
	st := Stats{
		Seq:            p.seq,
		Keys:           p.t.count,
		Commits:        s.commits.Load(),
		Conflicts:      s.conflicts.Load(),
		GroupCommits:   s.groups.Load(),
		Snapshots:      s.snapshots.Load(),
		SnapshotErrors: s.snapErrors.Load(),
	}
	if e := s.poison.Load(); e != nil {
		st.Poisoned = *e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st.Segments = len(s.segs)
	for _, sg := range s.segs {
		st.LogBytes += sg.size
	}
	st.SnapshotSeq = s.snapSeq
	st.PinnedViews = len(s.pins)
	return st
}

type view struct {
	t        tree
	seq      Seq
	s        *store
	pinned   bool
	released atomic.Bool
}

func (s *store) View() View {
	p := s.state.Load()
	return &view{t: p.t, seq: p.seq, s: s}
}

func (s *store) PinView() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.state.Load()
	v := &view{t: p.t, seq: p.seq, s: s, pinned: true}
	s.pins = append(s.pins, v)
	return v
}

func (s *store) PinnedViews() []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]View, len(s.pins))
	for i, p := range s.pins {
		out[i] = &view{t: p.t, seq: p.seq, s: s}
	}
	return out
}

func (v *view) Seq() Seq { return v.seq }

func (v *view) Get(key []byte) (Record, bool) { return v.t.get(key) }

func (v *view) Scan(prefix, after []byte, fn func(key []byte, r Record) bool) {
	start := prefix
	if after != nil && bytes.Compare(after, prefix) >= 0 {
		start = after
	}
	v.t.scan(start, func(k []byte, r Record) bool {
		if !bytes.HasPrefix(k, prefix) {
			return false
		}
		if after != nil && bytes.Compare(k, after) <= 0 {
			return true
		}
		return fn(k, r)
	})
}

func (v *view) Release() {
	if !v.released.CompareAndSwap(false, true) || !v.pinned {
		return
	}
	v.s.mu.Lock()
	defer v.s.mu.Unlock()
	if i := slices.Index(v.s.pins, v); i >= 0 {
		v.s.pins = slices.Delete(v.s.pins, i, i+1)
	}
}
