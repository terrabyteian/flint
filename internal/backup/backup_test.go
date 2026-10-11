package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
)

var quiet = slog.New(slog.DiscardHandler)

const (
	dataDir    = "/data"
	backupDir  = "/backup"
	restoreDir = "/restored"
	refPrefix  = "ref\x00"
)

// testRefs reports the digests named by "ref\0<digest>" keys.
func testRefs(v meta.View, fn func(blob.Digest) error) error {
	var err error
	v.Scan([]byte(refPrefix), nil, func(k []byte, _ meta.Record) bool {
		d, perr := blob.ParseDigest(string(k[len(refPrefix):]))
		if perr != nil {
			err = perr
			return false
		}
		err = fn(d)
		return err == nil
	})
	return err
}

var refs = []References{testRefs}

func noLock(string) (func(), error) { return func() {}, nil }

// env is a data directory on one in-memory filesystem and a backup
// directory on another.
type env struct {
	t     *testing.T
	src   *fsys.Mem
	dst   *fsys.Mem
	meta  meta.Store
	blobs blob.Store
	reg   *metrics.Registry

	mu    sync.Mutex
	clock time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, src: fsys.NewMem(), dst: fsys.NewMem(), reg: metrics.NewRegistry(),
		clock: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
	var err error
	if e.meta, err = meta.Open(dataDir+"/meta", meta.Options{FS: e.src, Logger: quiet}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.meta.Close() })
	if e.blobs, err = blob.NewFS(dataDir, blob.Options{FS: e.src}); err != nil {
		t.Fatal(err)
	}
	return e
}

// now is a clock that advances a second per call, so backup IDs differ.
func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clock = e.clock.Add(time.Second)
	return e.clock
}

func (e *env) manager(blobs blob.Store) *Manager {
	e.t.Helper()
	if blobs == nil {
		blobs = e.blobs
	}
	e.reg = metrics.NewRegistry() // the latest manager's metrics
	m, err := New(Options{Meta: e.meta, Blobs: blobs, Dir: backupDir, FS: e.dst, Lock: noLock,
		References: refs, Version: "test", Logger: quiet, Metrics: e.reg, Now: e.now})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(m.Close)
	return m
}

// storeBlob stores content without referencing it.
func storeBlob(t *testing.T, bs blob.Store, content string) blob.Digest {
	t.Helper()
	ctx := context.Background()
	up, err := bs.NewUpload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(up, content); err != nil {
		t.Fatal(err)
	}
	info, err := up.Commit(ctx, blob.Digest{})
	if err != nil {
		t.Fatal(err)
	}
	return info.Digest
}

// put stores content and references it from the metadata.
func (e *env) put(content string) blob.Digest {
	e.t.Helper()
	d := storeBlob(e.t, e.blobs, content)
	e.ref(d, "value of "+content)
	return d
}

func (e *env) ref(d blob.Digest, value string) {
	e.t.Helper()
	var b meta.Batch
	b.Put([]byte(refPrefix+d.String()), []byte(value))
	if _, err := e.meta.Commit(context.Background(), &b); err != nil {
		e.t.Fatal(err)
	}
}

func dump(v meta.View) string {
	var sb strings.Builder
	v.Scan(nil, nil, func(k []byte, r meta.Record) bool {
		fmt.Fprintf(&sb, "%q=%q@%d\n", k, r.Value, r.Version)
		return true
	})
	return sb.String()
}

// checkRestored restores backup id into a fresh directory on fsy and
// checks it holds want's records and every blob in contents.
func checkRestored(t *testing.T, fsy fsys.FS, id, want string, contents []string) {
	t.Helper()
	dir := restoreDir + "-" + id
	if _, err := Restore(context.Background(), backupDir, dir, VerifyOptions{FS: fsy, ID: id, References: refs}); err != nil {
		t.Fatalf("Restore %s: %v", id, err)
	}
	if _, err := fsy.Stat(filepath.Join(dir, RestoreMarker)); err == nil {
		t.Fatal("restore marker left behind")
	}
	ms, err := meta.Open(dir+"/meta", meta.Options{FS: fsy, Logger: quiet})
	if err != nil {
		t.Fatalf("opening the restored metadata: %v", err)
	}
	defer ms.Close()
	v := ms.View()
	defer v.Release()
	if got := dump(v); got != want {
		t.Fatalf("restored metadata:\n%s\nwant:\n%s", got, want)
	}
	bs, err := blob.NewFS(dir, blob.Options{FS: fsy})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range contents {
		r, err := bs.Open(context.Background(), blob.FromBytes([]byte(c)))
		if err != nil {
			t.Fatalf("restored blob %q: %v", c, err)
		}
		b, _ := io.ReadAll(r)
		r.Close()
		if string(b) != c {
			t.Fatalf("restored blob holds %q, want %q", b, c)
		}
	}
}

func verifyOK(t *testing.T, fsy fsys.FS, id string) *Report {
	t.Helper()
	rep, err := Verify(context.Background(), backupDir, VerifyOptions{FS: fsy, ID: id, References: refs})
	if err != nil {
		t.Fatalf("Verify %s: %v", id, err)
	}
	if err := rep.Err(); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestBackupIncrementalAndRestore(t *testing.T) {
	e := newEnv(t)
	m := e.manager(nil)
	ctx := context.Background()

	first := []string{"alpha", "beta", strings.Repeat("big", 100000)}
	for _, c := range first {
		e.put(c)
	}
	storeBlob(t, e.blobs, "unreferenced") // copied too: backup does not interpret records
	v1 := e.meta.View()
	want1 := dump(v1)
	v1.Release()

	r1, err := m.Run(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if r1.State != StateSucceeded || r1.Blobs != 4 || r1.CopiedBlobs != 4 || r1.Records != 3 || r1.Actor != "alice" {
		t.Fatalf("first backup: %+v", r1)
	}

	second := []string{"gamma", "delta"}
	for _, c := range second {
		e.put(c)
	}
	v2 := e.meta.View()
	want2 := dump(v2)
	v2.Release()
	r2, err := m.Run(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Blobs != 6 || r2.CopiedBlobs != 2 || r2.CopiedBytes != int64(len("gamma")+len("delta")) {
		t.Fatalf("second backup copied %d blobs of %d bytes, holds %d; want 2 new of 10 bytes, 6 in all",
			r2.CopiedBlobs, r2.CopiedBytes, r2.Blobs)
	}

	ents, err := List(e.dst, backupDir)
	if err != nil || len(ents) != 2 || !ents[0].Complete() || !ents[1].Complete() ||
		ents[0].ID != r1.ID || ents[1].ID != r2.ID {
		t.Fatalf("List = %+v, %v", ents, err)
	}
	if rec := ents[1].Record; rec.Sequence != r2.Sequence || rec.FlintVersion != "test" || rec.CopiedBlobs != 2 {
		t.Fatalf("record %+v", rec)
	}
	if rep := verifyOK(t, e.dst, ""); rep.Record.ID != r2.ID {
		t.Fatalf("Verify picked %s, want the latest, %s", rep.Record.ID, r2.ID)
	}
	verifyOK(t, e.dst, r1.ID)

	checkRestored(t, e.dst, r1.ID, want1, first)
	checkRestored(t, e.dst, r2.ID, want2, append(first, second...))

	st := m.Status()
	if st.Running != nil || st.Last == nil || st.Last.ID != r2.ID || st.LastSuccess.ID != r2.ID || st.Directory != backupDir {
		t.Fatalf("Status = %+v", st)
	}
	var buf bytes.Buffer
	e.reg.WriteTo(&buf)
	for _, want := range []string{
		`flint_backup_runs_total{result="success"} 2`,
		"flint_backup_running 0",
		"flint_backup_last_success_copied_blobs 2",
		"flint_backup_last_success_blobs 6",
		"flint_backup_last_success_timestamp_seconds " + strconv.FormatFloat(float64(r2.Finished.Unix()), 'g', -1, 64),
	} {
		if !strings.Contains(buf.String(), want+"\n") {
			t.Errorf("metrics lack %q:\n%s", want, buf.String())
		}
	}

	// A new manager, as after a restart, finds the last complete backup.
	if st := e.manager(nil).Status(); st.LastSuccess == nil || st.LastSuccess.ID != r2.ID || st.Last != nil {
		t.Fatalf("Status after restart = %+v", st)
	}
}

func TestBackupEmptyStore(t *testing.T) {
	e := newEnv(t)
	r, err := e.manager(nil).Run(context.Background(), "")
	if err != nil || r.Blobs != 0 || r.Records != 0 {
		t.Fatalf("Run = %+v, %v", r, err)
	}
	verifyOK(t, e.dst, "")
	checkRestored(t, e.dst, r.ID, "", nil)
}

// gcBlobs is a blob store whose Open reports some blobs gone, as if
// garbage collection deleted them after the walk listed them, and can
// block Open until released.
type gcBlobs struct {
	blob.Store
	gone    map[blob.Digest]bool
	opened  chan struct{}
	release chan struct{}
}

func (g *gcBlobs) Open(ctx context.Context, d blob.Digest) (blob.Reader, error) {
	if g.opened != nil {
		select {
		case g.opened <- struct{}{}:
		default:
		}
		<-g.release
	}
	if g.gone[d] {
		return nil, fmt.Errorf("%w: %s", blob.ErrNotFound, d)
	}
	return g.Store.Open(ctx, d)
}

func TestBackupSkipsBlobsDeletedDuringWalk(t *testing.T) {
	e := newEnv(t)
	keep := e.put("kept")
	gone := storeBlob(t, e.blobs, "collected")
	m := e.manager(&gcBlobs{Store: e.blobs, gone: map[blob.Digest]bool{gone: true}})
	r, err := m.Run(context.Background(), "")
	if err != nil || r.Blobs != 1 {
		t.Fatalf("Run = %+v, %v", r, err)
	}
	rep := verifyOK(t, e.dst, "")
	if rep.Record.Blobs != 1 {
		t.Fatalf("backup holds %d blobs, want only %s", rep.Record.Blobs, keep)
	}
}

func TestBackupFailsOnMissingReference(t *testing.T) {
	e := newEnv(t)
	e.put("present")
	lost := blob.FromBytes([]byte("lost"))
	e.ref(lost, "points at nothing")
	m := e.manager(nil)
	r, err := m.Run(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), lost.String()) || r.State != StateFailed || r.Error == "" {
		t.Fatalf("Run = %+v, %v; want a failure naming %s", r, err, lost)
	}
	ents, _ := List(e.dst, backupDir)
	if len(ents) != 1 || ents[0].Complete() {
		t.Fatalf("List = %+v, want one incomplete backup", ents)
	}
	if _, err := Verify(context.Background(), backupDir, VerifyOptions{FS: e.dst, ID: ents[0].ID}); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("Verify of an incomplete backup: %v", err)
	}
	if _, err := Verify(context.Background(), backupDir, VerifyOptions{FS: e.dst}); err == nil {
		t.Fatal("Verify found a complete backup")
	}
	if st := m.Status(); st.Last.State != StateFailed || st.LastSuccess != nil {
		t.Fatalf("Status = %+v", st)
	}

	// A copy an earlier backup made makes up for a blob the data
	// directory lost.
	e2 := newEnv(t)
	d := e2.put("lost later")
	if _, err := e2.manager(nil).Run(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := e2.blobs.Delete(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	r, err = e2.manager(nil).Run(context.Background(), "")
	if err != nil || r.Blobs != 1 || r.CopiedBlobs != 0 {
		t.Fatalf("Run = %+v, %v", r, err)
	}
	verifyOK(t, e2.dst, r.ID)
}

func TestBackupFailsOnCorruptSourceBlob(t *testing.T) {
	e := newEnv(t)
	d := e.put("original")
	path := filepath.Join(dataDir, "blobs", "sha256", d.Hex()[:2], d.Hex())
	rewrite(t, e.src, path, func(b []byte) { b[0] = 'O' })
	if _, err := e.manager(nil).Run(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("Run: %v, want a corruption error", err)
	}
}

func TestVerifyFindsDamage(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, fsy *fsys.Mem, rec *Record, d blob.Digest)
		want   string
	}{
		{"flipped blob byte", func(t *testing.T, fsy *fsys.Mem, rec *Record, d blob.Digest) {
			rewrite(t, fsy, blobPath(backupDir, d), func(b []byte) { b[0] ^= 1 })
		}, "corrupt"},
		{"missing blob", func(t *testing.T, fsy *fsys.Mem, rec *Record, d blob.Digest) {
			fsy.Remove(blobPath(backupDir, d))
		}, "missing"},
		{"truncated blob", func(t *testing.T, fsy *fsys.Mem, rec *Record, d blob.Digest) {
			f, _ := fsy.OpenFile(blobPath(backupDir, d), os.O_RDWR, 0)
			f.Truncate(3)
			f.Close()
		}, "bytes"},
		{"corrupt snapshot", func(t *testing.T, fsy *fsys.Mem, rec *Record, d blob.Digest) {
			rewrite(t, fsy, filepath.Join(backupDir, backupsDir, rec.ID, snapshotFile), func(b []byte) { b[len(b)/2] ^= 1 })
		}, "metadata.snap is corrupt"},
		{"edited blob list", func(t *testing.T, fsy *fsys.Mem, rec *Record, d blob.Digest) {
			rewrite(t, fsy, filepath.Join(backupDir, backupsDir, rec.ID, blobListFile), func(b []byte) { b[10] ^= 1 })
		}, "blobs is corrupt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			d := e.put(strings.Repeat("payload", 50))
			e.put("other")
			r, err := e.manager(nil).Run(ctx, "")
			if err != nil {
				t.Fatal(err)
			}
			rec, err := find(e.dst, backupDir, r.ID)
			if err != nil {
				t.Fatal(err)
			}
			tc.damage(t, e.dst, rec, d)
			rep, err := Verify(ctx, backupDir, VerifyOptions{FS: e.dst, References: refs})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Err() == nil || !strings.Contains(rep.Err().Error(), tc.want) {
				t.Fatalf("Verify: %v, want a problem mentioning %q", rep.Err(), tc.want)
			}
			if _, err := Restore(ctx, backupDir, restoreDir, VerifyOptions{FS: e.dst, References: refs}); err == nil {
				t.Fatal("Restore of a damaged backup succeeded")
			}
			// A restore that fails leaves the marker, so the data directory
			// is never served as if complete.
			if _, err := e.dst.Stat(restoreDir); err == nil {
				if _, err := e.dst.Stat(filepath.Join(restoreDir, RestoreMarker)); err != nil {
					t.Fatal("a failed restore left a data directory without the marker")
				}
			}
		})
	}
}

func rewrite(t *testing.T, fsy *fsys.Mem, path string, edit func([]byte)) {
	t.Helper()
	f, err := fsy.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	edit(b)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFindsUnlistedReference(t *testing.T) {
	e := newEnv(t)
	e.put("a")
	r, err := e.manager(nil).Run(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	// A reference function that knows more than the backup's did.
	extra := blob.FromBytes([]byte("never stored"))
	more := func(v meta.View, fn func(blob.Digest) error) error { return fn(extra) }
	rep, err := Verify(context.Background(), backupDir, VerifyOptions{FS: e.dst, ID: r.ID, References: []References{testRefs, more}})
	if err != nil || rep.Err() == nil || !strings.Contains(rep.Err().Error(), extra.String()) {
		t.Fatalf("Verify = %v, %v", rep.Err(), err)
	}
}

func TestRestoreRefusesNonEmptyDataDir(t *testing.T) {
	e := newEnv(t)
	e.put("a")
	if _, err := e.manager(nil).Run(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	e.dst.MkdirAll(restoreDir+"/meta", 0o755)
	_, err := Restore(context.Background(), backupDir, restoreDir, VerifyOptions{FS: e.dst})
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("Restore: %v", err)
	}
	// A LOCK file, which the caller holds, is allowed.
	e.dst.MkdirAll(restoreDir+"2", 0o755)
	f, err := e.dst.OpenFile(restoreDir+"2/LOCK", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Restore(context.Background(), backupDir, restoreDir+"2", VerifyOptions{FS: e.dst}); err != nil {
		t.Fatalf("Restore next to a LOCK file: %v", err)
	}
}

func TestOneBackupAtATime(t *testing.T) {
	e := newEnv(t)
	e.put("a")
	e.put("b")
	g := &gcBlobs{Store: e.blobs, opened: make(chan struct{}, 1), release: make(chan struct{})}
	m := e.manager(g)

	r, err := m.Start("alice")
	if err != nil || r.State != StateRunning || r.ID == "" {
		t.Fatalf("Start = %+v, %v", r, err)
	}
	<-g.opened
	// The view stays pinned while the backup copies, and later commits
	// are not part of it.
	if n := e.meta.Stats().PinnedViews; n != 1 {
		t.Fatalf("%d pinned views while running, want 1", n)
	}
	e.put("after the pin")
	if _, err := m.Start("bob"); !errors.Is(err, ErrRunning) {
		t.Fatalf("second Start: %v, want ErrRunning", err)
	}
	if _, err := m.Run(context.Background(), "bob"); !errors.Is(err, ErrRunning) {
		t.Fatalf("Run while running: %v, want ErrRunning", err)
	}
	st := m.Status()
	if st.Running == nil || st.Running.ID != r.ID || st.Running.Phase != PhaseBlobs || st.Running.Records != 2 {
		t.Fatalf("Status while running = %+v", st.Running)
	}
	var buf bytes.Buffer
	e.reg.WriteTo(&buf)
	if !strings.Contains(buf.String(), "flint_backup_running 1\n") {
		t.Fatal("flint_backup_running is not 1 while running")
	}
	close(g.release)
	if err := m.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	st = m.Status()
	if st.Running != nil || st.Last.ID != r.ID || st.Last.State != StateSucceeded || st.Last.Records != 2 {
		t.Fatalf("Status after = %+v", st.Last)
	}
	if n := e.meta.Stats().PinnedViews; n != 0 {
		t.Fatalf("%d pinned views after the backup, want 0", n)
	}
}

func TestCloseCancelsRunningBackup(t *testing.T) {
	e := newEnv(t)
	e.put("a")
	g := &gcBlobs{Store: e.blobs, opened: make(chan struct{}, 1), release: make(chan struct{})}
	m := e.manager(g)
	if _, err := m.Start(""); err != nil {
		t.Fatal(err)
	}
	<-g.opened
	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	time.Sleep(10 * time.Millisecond)
	close(g.release)
	<-done
	if st := m.Status(); st.Last == nil || st.Last.State != StateFailed {
		t.Fatalf("Status after Close = %+v", st.Last)
	}
	if _, err := m.Start(""); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close: %v", err)
	}
	if ents, _ := List(e.dst, backupDir); len(ents) != 1 || ents[0].Complete() {
		t.Fatalf("List = %+v, want one incomplete backup", ents)
	}
}

// TestCrash interrupts backups with a simulated power loss at every point
// and checks that a backup that looks complete afterwards is complete and
// restorable, and that the next backup succeeds.
func TestCrash(t *testing.T) {
	e := newEnv(t)
	var contents []string
	for i := range 6 {
		c := fmt.Sprintf("blob %d %s", i, strings.Repeat("x", i*3000))
		contents = append(contents, c)
		e.put(c)
	}
	v := e.meta.View()
	want := dump(v)
	v.Release()

	// Count the operations of a backup on a directory that already holds
	// an earlier backup of part of the data, so crashes hit both copies
	// and skips.
	base := fsys.NewMem()
	var prepID string
	prep := func(fsy *fsys.Mem) {
		e.dst = fsy
		m := e.manager(&gcBlobs{Store: e.blobs, gone: map[blob.Digest]bool{
			blob.FromBytes([]byte(contents[1])): true, blob.FromBytes([]byte(contents[4])): true,
		}})
		m.opts.References = nil
		r, err := m.Run(context.Background(), "")
		if err != nil {
			t.Fatal(err)
		}
		prepID = r.ID
	}
	prep(base)
	start := base.Ops()
	e.dst = base
	if _, err := e.manager(nil).Run(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	total := base.Ops() - start

	rng := rand.New(rand.NewPCG(1, 2))
	for n := range total {
		fsy := fsys.NewMem()
		prep(fsy)
		fsy.CrashAfter(n)
		e.dst = fsy
		if _, err := e.manager(nil).Run(context.Background(), ""); err == nil {
			t.Fatalf("crash after %d ops: backup succeeded", n)
		}
		after := fsy.Restart(rng)
		ents, err := List(after, backupDir)
		if err != nil {
			t.Fatalf("crash after %d ops: List: %v", n, err)
		}
		completes := 0
		for _, en := range ents {
			if en.Err != nil {
				t.Fatalf("crash after %d ops: backup %s: %v", n, en.ID, en.Err)
			}
			if !en.Complete() {
				continue
			}
			completes++
			if en.ID != prepID {
				verifyOK(t, after, en.ID)
				continue
			}
			// The earlier backup lacks some referenced blobs on purpose.
			rep, err := Verify(context.Background(), backupDir, VerifyOptions{FS: after, ID: en.ID})
			if err != nil || rep.Err() != nil {
				t.Fatalf("crash after %d ops: earlier backup: %v, %v", n, err, rep.Err())
			}
		}
		if completes < 1 {
			t.Fatalf("crash after %d ops: the earlier backup was lost", n)
		}
		// The next backup succeeds and restores everything.
		e.dst = after
		r, err := e.manager(nil).Run(context.Background(), "")
		if err != nil {
			t.Fatalf("crash after %d ops: next backup: %v", n, err)
		}
		verifyOK(t, after, r.ID)
		if n%7 == 0 {
			checkRestored(t, after, r.ID, want, contents)
		}
	}
}

// TestRestoreCrash interrupts a restore at every point and checks that
// the data directory keeps the marker until the restore is complete.
func TestRestoreCrash(t *testing.T) {
	e := newEnv(t)
	for i := range 4 {
		e.put(fmt.Sprintf("blob %d", i))
	}
	if _, err := e.manager(nil).Run(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	probe := e.dst.Restart(nil)
	if _, err := Restore(context.Background(), backupDir, restoreDir, VerifyOptions{FS: probe}); err != nil {
		t.Fatal(err)
	}
	total := probe.Ops()
	for n := range total {
		fsy := e.dst.Restart(nil)
		e.dst = fsy.Restart(nil) // keep a pristine copy for the next round
		fsy.CrashAfter(n)
		if _, err := Restore(context.Background(), backupDir, restoreDir, VerifyOptions{FS: fsy}); err == nil {
			t.Fatalf("crash after %d ops: restore succeeded", n)
		}
		after := fsy.Restart(nil)
		if _, err := after.Stat(restoreDir); err != nil {
			continue // nothing durable yet
		}
		if _, err := after.Stat(filepath.Join(restoreDir, RestoreMarker)); err == nil {
			continue // marked incomplete
		}
		// No marker: the restore must be complete, unless nothing but
		// the directory itself was made durable yet.
		ents, _ := after.ReadDir(restoreDir)
		if len(ents) == 0 {
			continue
		}
		ms, err := meta.Open(restoreDir+"/meta", meta.Options{FS: after, Logger: quiet})
		if err != nil {
			t.Fatalf("crash after %d ops: no marker, but the metadata does not open: %v", n, err)
		}
		ms.Close()
	}
}

// TestBackupSyncsBlobsAnEarlierBackupLeftUnsynced fails a backup after a
// blob copy was renamed into place but before its directory was synced,
// so the next backup finds the blob present; it must make the blob
// durable before it completes.
func TestBackupSyncsBlobsAnEarlierBackupLeftUnsynced(t *testing.T) {
	e := newEnv(t)
	e.put("a blob")
	failed := false
	e.dst.SetFault(func(op fsys.Op, name string) error {
		if op == fsys.OpSyncDir && strings.Contains(name, "/blobs/sha256/") && !failed && strings.HasPrefix(name, backupDir) {
			failed = true
			return errors.New("injected sync failure")
		}
		return nil
	})
	if _, err := e.manager(nil).Run(context.Background(), ""); err == nil {
		t.Fatal("backup with a failed sync succeeded")
	}
	e.dst.SetFault(nil)
	r, err := e.manager(nil).Run(context.Background(), "")
	if err != nil || r.CopiedBlobs != 0 {
		t.Fatalf("Run = %+v, %v; want the blob found present", r, err)
	}
	after := e.dst.Restart(nil)
	verifyOK(t, after, r.ID)
}
