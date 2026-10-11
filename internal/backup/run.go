package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/flock"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
)

// Options configures a Manager.
type Options struct {
	// Meta and Blobs are the data directory's stores. Required.
	Meta  meta.Store
	Blobs blob.Store
	// Dir is the backup directory: an absolute path on a filesystem the
	// server can write, such as a mounted volume. Required.
	Dir string
	// FS is Dir's filesystem; nil means fsys.OS.
	FS fsys.FS
	// Lock takes the exclusive lock on the backup directory's LOCK file
	// for the duration of a backup; nil means flock.Lock.
	Lock func(path string) (unlock func(), err error)
	// References report the blobs each format package's records
	// reference; a backup checks that it holds all of them.
	References []References
	// Version is the flint version recorded in each backup.
	Version string
	// Logger receives backup logs; nil means slog.Default().
	Logger *slog.Logger
	// Metrics receives backup metrics; nil means none.
	Metrics *metrics.Registry
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Errors from starting a backup.
var (
	// ErrRunning means a backup is already running.
	ErrRunning = errors.New("a backup is already running")
	// ErrClosed means the manager is closed.
	ErrClosed = errors.New("backups are shut down")
)

// Run states.
const (
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
)

// Run phases, in order.
const (
	PhaseMetadata   = "metadata"
	PhaseBlobs      = "blobs"
	PhaseReferences = "references"
	PhaseFinishing  = "finishing"
)

// Run is one backup attempt, running or finished.
type Run struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// Phase is what a running backup is doing.
	Phase string `json:"phase,omitempty"`
	// Actor is who started the backup.
	Actor string `json:"actor,omitempty"`
	// Sequence is the metadata sequence number the backup holds.
	Sequence uint64     `json:"sequence"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
	// DurationSeconds is how long the backup has run, or ran.
	DurationSeconds float64 `json:"durationSeconds"`
	// Records is the number of metadata records.
	Records int `json:"records"`
	// Blobs and Bytes count the blobs in the backup so far.
	Blobs int64 `json:"blobs"`
	Bytes int64 `json:"bytes"`
	// CopiedBlobs and CopiedBytes count those this backup copied; the
	// rest were present from earlier backups.
	CopiedBlobs int64 `json:"copiedBlobs"`
	CopiedBytes int64 `json:"copiedBytes"`
	// Error says why a failed backup failed.
	Error string `json:"error,omitempty"`
}

// Status reports the running backup and the last ones.
type Status struct {
	// Directory is the backup directory.
	Directory string `json:"directory"`
	// Running is the backup in progress, if any.
	Running *Run `json:"running,omitempty"`
	// Last is the last backup that finished, successfully or not, since
	// the server started.
	Last *Run `json:"last,omitempty"`
	// LastSuccess is the last complete backup, found in the backup
	// directory at startup or written since.
	LastSuccess *Run `json:"lastSuccess,omitempty"`
}

// Manager runs backups of a live server, at most one at a time.
type Manager struct {
	opts   Options
	fs     fsys.FS
	log    *slog.Logger
	now    func() time.Time
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	cur      *progress
	last     *Run
	lastOK   *Run
	closed   bool
	finished chan struct{} // closed and replaced whenever a backup finishes

	runs        *metrics.Counter
	copiedTotal *metrics.CounterSeries
}

// progress is the state of a running backup.
type progress struct {
	run         Run // the fields fixed when it starts
	phase       atomic.Pointer[string]
	records     atomic.Int64
	blobs       atomic.Int64
	bytes       atomic.Int64
	copiedBlobs atomic.Int64
	copiedBytes atomic.Int64
}

func (p *progress) setPhase(s string) { p.phase.Store(&s) }

// snapshot returns the run as of now.
func (p *progress) snapshot(now time.Time) Run {
	r := p.run
	r.Phase = *p.phase.Load()
	r.DurationSeconds = now.Sub(r.Started).Seconds()
	r.Records = int(p.records.Load())
	r.Blobs, r.Bytes = p.blobs.Load(), p.bytes.Load()
	r.CopiedBlobs, r.CopiedBytes = p.copiedBlobs.Load(), p.copiedBytes.Load()
	return r
}

// New returns a Manager. It reads the backup directory, if it exists, to
// report the last complete backup.
func New(opts Options) (*Manager, error) {
	if opts.Meta == nil || opts.Blobs == nil || opts.Dir == "" {
		return nil, errors.New("backup: Options.Meta, Options.Blobs, and Options.Dir are required")
	}
	m := &Manager{opts: opts, fs: opts.FS, log: opts.Logger, now: opts.Now, finished: make(chan struct{})}
	if m.fs == nil {
		m.fs = fsys.OS
	}
	if m.opts.Lock == nil {
		m.opts.Lock = flock.Lock
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	if m.now == nil {
		m.now = time.Now
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	if ents, err := List(m.fs, opts.Dir); err != nil {
		m.log.Warn("backup: reading the backup directory", "dir", opts.Dir, "err", err)
	} else {
		for _, e := range ents {
			if e.Complete() {
				m.lastOK = e.Record.run()
			}
		}
	}
	m.registerMetrics(opts.Metrics)
	return m, nil
}

// run converts a completion record to a Run.
func (rec *Record) run() *Run {
	fin := rec.Finished
	return &Run{
		ID: rec.ID, State: StateSucceeded, Sequence: rec.Sequence,
		Started: rec.Started, Finished: &fin, DurationSeconds: fin.Sub(rec.Started).Seconds(),
		Records: rec.Records, Blobs: rec.Blobs, Bytes: rec.Bytes,
		CopiedBlobs: rec.CopiedBlobs, CopiedBytes: rec.CopiedBytes,
	}
}

func (m *Manager) registerMetrics(reg *metrics.Registry) {
	if reg == nil {
		reg = metrics.NewRegistry()
	}
	m.runs = reg.Counter("flint_backup_runs_total", "Finished backups, by result (success, failure).", "result")
	m.copiedTotal = reg.Counter("flint_backup_copied_bytes_total",
		"Bytes of blobs copied to the backup directory, counted as they are copied.").With()
	reg.GaugeFunc("flint_backup_running", "1 while a backup is running, else 0.", func() float64 {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.cur != nil {
			return 1
		}
		return 0
	})
	lastOK := func(f func(*Run) float64) func() float64 {
		return func() float64 {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.lastOK == nil {
				return 0
			}
			return f(m.lastOK)
		}
	}
	for _, g := range []struct {
		name, help string
		f          func(*Run) float64
	}{
		{"flint_backup_last_success_timestamp_seconds", "When the last complete backup finished, in Unix seconds; 0 if none.",
			func(r *Run) float64 { return float64(r.Finished.UnixNano()) / 1e9 }},
		{"flint_backup_last_success_duration_seconds", "How long the last complete backup took.",
			func(r *Run) float64 { return r.DurationSeconds }},
		{"flint_backup_last_success_blobs", "Blobs in the last complete backup.",
			func(r *Run) float64 { return float64(r.Blobs) }},
		{"flint_backup_last_success_bytes", "Bytes of blobs in the last complete backup.",
			func(r *Run) float64 { return float64(r.Bytes) }},
		{"flint_backup_last_success_copied_blobs", "Blobs the last complete backup copied; the rest were already in the backup directory.",
			func(r *Run) float64 { return float64(r.CopiedBlobs) }},
		{"flint_backup_last_success_copied_bytes", "Bytes of blobs the last complete backup copied.",
			func(r *Run) float64 { return float64(r.CopiedBytes) }},
	} {
		reg.GaugeFunc(g.name, g.help, lastOK(g.f))
	}
}

// Dir returns the backup directory.
func (m *Manager) Dir() string { return m.opts.Dir }

// Status reports the running backup and the last ones.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Directory: m.opts.Dir, Last: m.last, LastSuccess: m.lastOK}
	if m.cur != nil {
		r := m.cur.snapshot(m.now())
		st.Running = &r
	}
	return st
}

// Start starts a backup in the background and returns it. The metadata
// view it backs up is pinned before Start returns. actor names who
// started it, for the logs.
func (m *Manager) Start(actor string) (Run, error) {
	p, v, err := m.begin(actor)
	if err != nil {
		return Run{}, err
	}
	m.wg.Go(func() { m.execute(m.ctx, p, v) })
	return p.snapshot(m.now()), nil
}

// Run runs a backup and returns when it finishes. Its error is also in
// the returned Run.
func (m *Manager) Run(ctx context.Context, actor string) (Run, error) {
	p, v, err := m.begin(actor)
	if err != nil {
		return Run{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	r := m.execute(ctx, p, v)
	if r.Error != "" {
		return r, errors.New(r.Error)
	}
	return r, nil
}

// Wait returns when no backup is running, or when ctx is done.
func (m *Manager) Wait(ctx context.Context) error {
	for {
		m.mu.Lock()
		running, ch := m.cur != nil, m.finished
		m.mu.Unlock()
		if !running {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Close cancels a running backup, which then fails and leaves an
// incomplete backup behind, and waits for it to stop.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.cancel()
	m.wg.Wait()
}

// begin claims the one backup slot and pins the view to back up, in one
// step under the lock, so the view is pinned before the backup is visible
// as running.
func (m *Manager) begin(actor string) (*progress, meta.View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.closed:
		return nil, nil, ErrClosed
	case m.cur != nil:
		return nil, nil, ErrRunning
	}
	v := m.opts.Meta.PinView()
	now := m.now()
	p := &progress{run: Run{
		ID: newID(now, v.Seq()), State: StateRunning, Actor: actor,
		Sequence: uint64(v.Seq()), Started: now,
	}}
	p.setPhase(PhaseMetadata)
	m.cur = p
	return p, v, nil
}

// execute performs the backup p of the pinned view v, releases v, and
// records the outcome.
func (m *Manager) execute(ctx context.Context, p *progress, v meta.View) Run {
	defer v.Release()
	log := m.log.With("backup_id", p.run.ID)
	log.Info("backup started", "dir", m.opts.Dir, "sequence", p.run.Sequence, "actor", p.run.Actor)
	err := m.backup(ctx, p, v)
	fin := m.now()
	r := p.snapshot(fin)
	r.Phase = ""
	r.Finished = &fin
	if err != nil {
		r.State, r.Error = StateFailed, err.Error()
		m.runs.With("failure").Inc()
		log.Error("backup failed", "err", err, "duration", fin.Sub(r.Started).String(),
			"copied_blobs", r.CopiedBlobs, "copied_bytes", r.CopiedBytes)
	} else {
		r.State = StateSucceeded
		m.runs.With("success").Inc()
		log.Info("backup finished", "duration", fin.Sub(r.Started).String(), "records", r.Records,
			"blobs", r.Blobs, "bytes", r.Bytes, "copied_blobs", r.CopiedBlobs, "copied_bytes", r.CopiedBytes)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cur = nil
	m.last = &r
	if err == nil {
		m.lastOK = &r
	}
	close(m.finished)
	m.finished = make(chan struct{})
	return r
}

// backup writes the backup of v. See the package documentation.
func (m *Manager) backup(ctx context.Context, p *progress, v meta.View) error {
	dir := m.opts.Dir
	if err := mkdirDurable(m.fs, dir); err != nil {
		return fmt.Errorf("creating the backup directory: %w", err)
	}
	unlock, err := m.opts.Lock(filepath.Join(dir, lockFile))
	if err != nil {
		return fmt.Errorf("locking the backup directory: %w", err)
	}
	defer unlock()

	dst, err := blob.NewFS(dir, blob.Options{FS: m.fs, Now: m.now})
	if err != nil {
		return err
	}
	// Remove the staged copies an interrupted backup left; the lock
	// keeps any other backup out of this directory.
	if n, err := dst.PurgeUploads(ctx, m.now()); err != nil {
		return err
	} else if n > 0 {
		m.log.Info("backup: removed the partial blob copies of an interrupted backup", "count", n)
	}
	backups := filepath.Join(dir, backupsDir)
	if err := mkdirDurable(m.fs, backups); err != nil {
		return err
	}
	bdir := filepath.Join(backups, p.run.ID)
	if err := m.fs.Mkdir(bdir, 0o755); err != nil {
		return fmt.Errorf("creating the backup: %w", err)
	}
	if err := m.fs.SyncDir(backups); err != nil {
		return err
	}

	rec := Record{
		Format: recordFormat, ID: p.run.ID, FlintVersion: m.opts.Version,
		Sequence: p.run.Sequence, Started: p.run.Started,
	}
	n := 0
	v.Scan(nil, nil, func([]byte, meta.Record) bool { n++; return true })
	rec.Records = n
	p.records.Store(int64(n))
	if rec.Snapshot, err = writeSummed(m.fs, filepath.Join(bdir, snapshotFile), func(w io.Writer) error {
		return meta.WriteSnapshot(ctxWriter{ctx, w}, v)
	}); err != nil {
		return fmt.Errorf("writing the metadata snapshot: %w", err)
	}

	p.setPhase(PhaseBlobs)
	c := &copier{m: m, p: p, dst: dst, have: map[blob.Digest]struct{}{}}
	if rec.BlobList, err = writeSummed(m.fs, filepath.Join(bdir, blobListFile), func(w io.Writer) error {
		c.list = w
		if err := m.opts.Blobs.Walk(ctx, c.copy(ctx)); err != nil {
			return err
		}
		p.setPhase(PhaseReferences)
		return c.checkReferences(ctx, v)
	}); err != nil {
		return err
	}

	p.setPhase(PhaseFinishing)
	// A blob present from an interrupted backup may have been renamed
	// into place without its directory being synced since.
	for i, ok := range c.syncFanout {
		if ok {
			if err := m.fs.SyncDir(filepath.Join(dir, "blobs", "sha256", fmt.Sprintf("%02x", i))); err != nil {
				return err
			}
		}
	}
	if err := m.fs.SyncDir(bdir); err != nil {
		return err
	}
	rec.Blobs, rec.Bytes = p.blobs.Load(), p.bytes.Load()
	rec.CopiedBlobs, rec.CopiedBytes = p.copiedBlobs.Load(), p.copiedBytes.Load()
	rec.Finished = m.now()
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeFileAtomic(m.fs, bdir, recordFile, append(b, '\n'))
}

// copier copies blobs into the backup and lists them.
type copier struct {
	m          *Manager
	p          *progress
	dst        blob.Store
	list       io.Writer
	have       map[blob.Digest]struct{}
	syncFanout [256]bool
}

// copy returns the blob walk callback: it copies a blob the backup
// directory lacks, and lists it.
func (c *copier) copy(ctx context.Context) func(blob.Info) error {
	return func(info blob.Info) error {
		size := info.Size
		if have, err := c.dst.Stat(ctx, info.Digest); err == nil && have.Size == info.Size {
			c.syncFanout[fanout(info.Digest)] = true
		} else {
			if err != nil && !errors.Is(err, blob.ErrNotFound) {
				return err
			}
			n, err := c.copyBlob(ctx, info.Digest)
			if errors.Is(err, blob.ErrNotFound) {
				return nil // deleted since the walk listed it, so not referenced
			}
			if err != nil {
				return err
			}
			size = n
			c.p.copiedBlobs.Add(1)
			c.p.copiedBytes.Add(n)
		}
		return c.add(info.Digest, size)
	}
}

func (c *copier) add(d blob.Digest, size int64) error {
	c.have[d] = struct{}{}
	c.p.blobs.Add(1)
	c.p.bytes.Add(size)
	_, err := fmt.Fprintf(c.list, "%s %d\n", d, size)
	return err
}

// copyBlob copies blob d from the data directory, verifying its digest,
// and returns its size.
func (c *copier) copyBlob(ctx context.Context, d blob.Digest) (int64, error) {
	r, err := c.m.opts.Blobs.Open(ctx, d)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	up, err := c.dst.NewUpload(ctx)
	if err != nil {
		return 0, err
	}
	if _, err := io.Copy(up, &countingReader{ctx: ctx, r: r, n: c.m.copiedTotal}); err != nil {
		up.Cancel()
		return 0, fmt.Errorf("copying blob %s: %w", d, err)
	}
	info, err := up.Commit(ctx, d)
	if errors.Is(err, blob.ErrDigestMismatch) {
		return 0, fmt.Errorf("blob %s in the data directory is corrupt: its content does not match its digest", d)
	}
	if err != nil {
		return 0, fmt.Errorf("copying blob %s: %w", d, err)
	}
	return info.Size, nil
}

// maxReported bounds how many missing digests an error names.
const maxReported = 10

// checkReferences checks that the backup holds every blob v references.
// A referenced blob the walk did not find, but which an earlier backup
// copied, is added to the backup.
func (c *copier) checkReferences(ctx context.Context, v meta.View) error {
	var missing []string
	nMissing := 0
	for _, refs := range c.m.opts.References {
		err := refs(v, func(d blob.Digest) error {
			if _, ok := c.have[d]; ok {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			info, err := c.dst.Stat(ctx, d)
			if errors.Is(err, blob.ErrNotFound) {
				c.have[d] = struct{}{} // report it once
				nMissing++
				if len(missing) < maxReported {
					missing = append(missing, d.String())
				}
				return nil
			}
			if err != nil {
				return err
			}
			c.m.log.Warn("backup: a referenced blob is missing from the data directory; keeping the copy an earlier backup made",
				"digest", d.String())
			c.syncFanout[fanout(d)] = true
			return c.add(d, info.Size)
		})
		if err != nil {
			return err
		}
	}
	if nMissing > 0 {
		return fmt.Errorf("the metadata references %d blobs that are missing from the data directory, such as %s",
			nMissing, strings.Join(missing, ", "))
	}
	return nil
}

// fanout returns the number of d's fan-out directory.
func fanout(d blob.Digest) int {
	n, _ := strconv.ParseUint(d.Hex()[:2], 16, 8)
	return int(n)
}

// countingReader reads r, stopping when ctx is done, and counts the bytes
// read in n.
type countingReader struct {
	ctx context.Context
	r   io.Reader
	n   *metrics.CounterSeries
}

func (c *countingReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.r.Read(p)
	c.n.Add(float64(n))
	return n, err
}

// ctxWriter writes to w until ctx is done.
type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (c ctxWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}

// writeSummed creates path, lets write fill it, syncs it, and returns its
// size and digest. The caller syncs the directory.
func writeSummed(fsy fsys.FS, path string, write func(io.Writer) error) (FileSum, error) {
	f, err := fsy.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return FileSum{}, err
	}
	h := &summer{h: sha256.New()}
	bw := bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20)
	err = write(bw)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return FileSum{}, err
	}
	return h.sum(), nil
}

// summer hashes and counts what is written to it.
type summer struct {
	h hash.Hash
	n int64
}

func (s *summer) Write(p []byte) (int, error) {
	s.n += int64(len(p))
	return s.h.Write(p)
}

func (s *summer) sum() FileSum {
	d, _ := blob.ParseDigest(fmt.Sprintf("sha256:%x", s.h.Sum(nil)))
	return FileSum{Size: s.n, Digest: d}
}

// mkdirDurable creates dir and any missing parents, syncing the parent of
// each directory it creates.
func mkdirDurable(fsy fsys.FS, dir string) error {
	dir = filepath.Clean(dir)
	if _, err := fsy.Stat(dir); err == nil {
		return nil
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := mkdirDurable(fsy, parent); err != nil {
			return err
		}
	}
	if err := fsy.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return fsy.SyncDir(parent)
}
