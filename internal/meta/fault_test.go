package meta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

func readAll(t testing.TB, fs fsys.FS, path string) []byte {
	t.Helper()
	f, err := fs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// overwrite writes p at off in path and syncs it, as disk rot or a test would.
func overwrite(t testing.TB, fs fsys.FS, path string, off int64, p []byte) {
	t.Helper()
	f, err := fs.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(p); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

func flipByte(t testing.TB, fs fsys.FS, path string, off int64) {
	t.Helper()
	b := readAll(t, fs, path)
	overwrite(t, fs, path, off, []byte{b[off] ^ 0x5a})
}

func segmentPaths(t testing.TB, fs fsys.FS) []string {
	t.Helper()
	dir := filepath.Join(testDir, "wal")
	ents, err := fs.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

func lastSegment(t testing.TB, fs fsys.FS) string {
	p := segmentPaths(t, fs)
	return p[len(p)-1]
}

// recordOffsets returns the offset of each intact record in a segment.
func recordOffsets(t testing.TB, data []byte) []int64 {
	t.Helper()
	h, err := parseSegHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	var offs []int64
	for off := segHeaderSize; off < len(data); {
		rec, ok := recordAt(data, off, h.salt)
		if !ok {
			t.Fatalf("no intact record at %d", off)
		}
		offs = append(offs, int64(off))
		off += len(rec)
	}
	return offs
}

func wantCorruption(t testing.TB, err error, path string, off int64, reason string) {
	t.Helper()
	var ce *CorruptionError
	if !errors.As(err, &ce) || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want a CorruptionError", err)
	}
	if ce.Path != path || (off >= 0 && ce.Offset != off) || !strings.Contains(ce.Reason, reason) {
		t.Fatalf("CorruptionError = %s at %d (%q), want %s at %d containing %q", ce.Path, ce.Offset, ce.Reason, path, off, reason)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not name the file", err)
	}
}

func openErr(m fsys.FS, opts Options) error {
	opts.FS = m
	opts.Logger = quiet
	s, err := Open(testDir, opts)
	if err == nil {
		s.Close()
	}
	return err
}

func failLog(op fsys.Op) func(fsys.Op, string) error {
	return func(o fsys.Op, name string) error {
		if o == op && filepath.Ext(name) == ".log" {
			return errors.New("injected " + string(op) + " failure")
		}
		return nil
	}
}

// TestWriteFailurePoisons covers guarantee 4: after a failed log write or
// fsync, writes fail, reads keep serving fsynced state, and a restart recovers.
func TestWriteFailurePoisons(t *testing.T) {
	for _, op := range []fsys.Op{fsys.OpSync, fsys.OpWrite} {
		for _, crash := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/crash=%v", op, crash), func(t *testing.T) {
				m := fsys.NewMem()
				s := openStore(t, m, Options{})
				commit(t, s, "a", "1")
				m.SetFault(failLog(op))
				_, err := s.Commit(context.Background(), batchOf("b", "2"))
				if !errors.Is(err, ErrUnknownOutcome) || !errors.Is(err, ErrPoisoned) {
					t.Fatalf("failed write: err = %v, want ErrUnknownOutcome and ErrPoisoned", err)
				}
				m.SetFault(nil)
				_, err = s.Commit(context.Background(), batchOf("c", "3"))
				if !errors.Is(err, ErrPoisoned) || errors.Is(err, ErrUnknownOutcome) {
					t.Fatalf("later write: err = %v, want only ErrPoisoned", err)
				}
				if !strings.Contains(err.Error(), "injected") {
					t.Fatalf("poison error %q does not carry the cause", err)
				}
				// Reads keep serving fsynced state only.
				wantGet(t, s, "a", "1", 1)
				wantAbsent(t, s, "b")
				st := s.Stats()
				if st.Poisoned == nil || st.Seq != 1 {
					t.Fatalf("Stats = %+v, want poisoned at seq 1", st)
				}
				s.Close()

				fs := fsys.FS(m)
				if crash {
					fs = m.Restart(nil)
				}
				s = openStore(t, fs, Options{})
				wantGet(t, s, "a", "1", 1)
				if op == fsys.OpWrite || crash {
					// A short write or an unsynced write is a torn final write.
					wantAbsent(t, s, "b")
				}
				wantAbsent(t, s, "c")
				if s.Stats().Poisoned != nil {
					t.Fatal("reopened store is poisoned")
				}
				seq := commit(t, s, "d", "4")
				s = reopen(t, s, fs, Options{})
				wantGet(t, s, "d", "4", seq)
			})
		}
	}
}

func TestRotationFailurePoisons(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, Options{SegmentSize: 100})
	commit(t, s, "a", strings.Repeat("x", 100))
	m.SetFault(func(op fsys.Op, name string) error {
		if op == fsys.OpOpen && filepath.Ext(name) == ".log" {
			return errors.New("disk full")
		}
		return nil
	})
	_, err := s.Commit(context.Background(), batchOf("b", "2"))
	if !errors.Is(err, ErrPoisoned) || errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("err = %v, want ErrPoisoned (nothing was written)", err)
	}
	m.SetFault(nil)
	s = reopen(t, s, m, Options{SegmentSize: 100})
	wantAbsent(t, s, "b")
	commit(t, s, "b", "2")
}

// TestTornFinalWrite covers the discardable case of guarantee 2: a bad
// region confined to the final group-commit write is truncated.
func TestTornFinalWrite(t *testing.T) {
	half := func(t *testing.T, seg string, data []byte) []byte {
		h, _ := parseSegHeader(data)
		rec := appendRecord(nil, h.salt, 4, 4, time.Now(), batchOf("torn", "x"))
		return rec[:len(rec)/2]
	}
	for name, tail := range map[string]func(*testing.T, string, []byte) []byte{
		"half record": half,
		"garbage":     func(*testing.T, string, []byte) []byte { return []byte("\x01\x02garbage bytes of an unsynced page") },
		"zeros":       func(*testing.T, string, []byte) []byte { return make([]byte, 4096) },
		"short frame": func(*testing.T, string, []byte) []byte { return []byte{9, 0, 0} },
	} {
		t.Run(name, func(t *testing.T) {
			m := fsys.NewMem()
			s := openStore(t, m, Options{})
			for i := range 3 {
				commit(t, s, fmt.Sprint(i), "v")
			}
			s.Close()
			seg := lastSegment(t, m)
			data := readAll(t, m, seg)
			overwrite(t, m, seg, int64(len(data)), tail(t, seg, data))
			s = openStore(t, m, Options{})
			if st := s.Stats(); st.Seq != 3 || st.Keys != 3 {
				t.Fatalf("Stats = %+v", st)
			}
			if got := readAll(t, m, seg); len(got) != len(data) {
				t.Fatalf("segment is %d bytes after recovery, want %d", len(got), len(data))
			}
			seq := commit(t, s, "after", "x")
			s = reopen(t, s, m, Options{})
			wantGet(t, s, "after", "x", seq)
		})
	}
}

// writeGroup appends records for the batches as one group commit starting
// at first, as the writer would, and syncs them.
func writeGroup(t testing.TB, m fsys.FS, seg string, first Seq, batches ...*Batch) {
	t.Helper()
	data := readAll(t, m, seg)
	h, err := parseSegHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	var buf []byte
	for i, b := range batches {
		buf = appendRecord(buf, h.salt, first+Seq(i), first, time.Now(), b)
	}
	overwrite(t, m, seg, int64(len(data)), buf)
}

// TestRotInFinalGroup checks that a bad record followed only by intact
// records of the same group commit is discarded with the rest of the group.
func TestRotInFinalGroup(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, Options{})
	commit(t, s, "a", "1")
	s.Close()
	seg := lastSegment(t, m)
	writeGroup(t, m, seg, 2, batchOf("g2", "x"), batchOf("g3", "x"), batchOf("g4", "x"))
	offs := recordOffsets(t, readAll(t, m, seg))
	flipByte(t, m, seg, offs[2]+frameSize+12) // record 3, the middle of the group
	s = openStore(t, m, Options{})
	wantGet(t, s, "g2", "x", 2) // complete batches before the bad record stay
	wantAbsent(t, s, "g3")
	wantAbsent(t, s, "g4")
	if seq := commit(t, s, "next", "x"); seq != 3 {
		t.Fatalf("next seq = %d, want 3", seq)
	}
}

// TestCorruptAckedRecord covers the error case of guarantee 2: a bad
// record followed by an intact record of a later group commit fails startup
// with an error naming the segment and offset.
func TestCorruptAckedRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, m fsys.FS, seg string, off int64)
	}{
		{"flipped byte", func(t *testing.T, m fsys.FS, seg string, off int64) { flipByte(t, m, seg, off+frameSize+3) }},
		{"bad length", func(t *testing.T, m fsys.FS, seg string, off int64) {
			overwrite(t, m, seg, off, []byte{0xff, 0xff, 0xff, 0x7f})
		}},
		{"zeroed", func(t *testing.T, m fsys.FS, seg string, off int64) { overwrite(t, m, seg, off, make([]byte, 30)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fsys.NewMem()
			s := openStore(t, m, Options{})
			for i := range 5 {
				commit(t, s, fmt.Sprint(i), strings.Repeat("v", 20))
			}
			s.Close()
			seg := lastSegment(t, m)
			offs := recordOffsets(t, readAll(t, m, seg))
			tc.damage(t, m, seg, offs[1])
			wantCorruption(t, openErr(m, Options{}), seg, offs[1], "later group commit")
		})
	}
}

func TestCorruptRecordCoveredByDurableState(t *testing.T) {
	t.Run("snapshot", func(t *testing.T) {
		m := fsys.NewMem()
		s := openStore(t, m, Options{SnapshotBytes: -1})
		for i := range 5 {
			commit(t, s, fmt.Sprint(i), "v")
		}
		if err := s.Snapshot(); err != nil {
			t.Fatal(err)
		}
		s.Close()
		seg := lastSegment(t, m)
		offs := recordOffsets(t, readAll(t, m, seg))
		flipByte(t, m, seg, offs[4]+frameSize+3) // the final record, covered by the snapshot
		wantCorruption(t, openErr(m, Options{}), seg, offs[4], "acknowledged")
	})
	t.Run("checkpoint", func(t *testing.T) {
		m := fsys.NewMem()
		s := openStore(t, m, Options{SnapshotBytes: -1})
		if _, err := s.RegisterConsumer("audit"); err != nil {
			t.Fatal(err)
		}
		for i := range 5 {
			commit(t, s, fmt.Sprint(i), "v")
		}
		if err := s.Checkpoint("audit", 5); err != nil {
			t.Fatal(err)
		}
		s.Close()
		seg := lastSegment(t, m)
		offs := recordOffsets(t, readAll(t, m, seg))
		flipByte(t, m, seg, offs[4]+frameSize+3)
		wantCorruption(t, openErr(m, Options{}), seg, offs[4], "acknowledged")
	})
}

func TestCorruptEarlierSegment(t *testing.T) {
	m := fsys.NewMem()
	opts := Options{SegmentSize: 200, SnapshotBytes: -1}
	s := openStore(t, m, opts)
	for i := range 30 {
		commit(t, s, fmt.Sprint(i), strings.Repeat("v", 30))
	}
	s.Close()
	segs := segmentPaths(t, m)
	if len(segs) < 3 {
		t.Fatalf("%d segments", len(segs))
	}
	// Damage the tail of a non-final segment: later segments prove it was synced.
	data := readAll(t, m, segs[1])
	offs := recordOffsets(t, data)
	last := offs[len(offs)-1]
	flipByte(t, m, segs[1], last+frameSize+3)
	wantCorruption(t, openErr(m, opts), segs[1], last, "later segments follow")
}

func TestLogGap(t *testing.T) {
	m := fsys.NewMem()
	opts := Options{SegmentSize: 200, SnapshotBytes: -1}
	s := openStore(t, m, opts)
	for i := range 30 {
		commit(t, s, fmt.Sprint(i), strings.Repeat("v", 30))
	}
	s.Close()
	segs := segmentPaths(t, m)
	if err := m.Remove(segs[2]); err != nil {
		t.Fatal(err)
	}
	wantCorruption(t, openErr(m, opts), segs[3], -1, "gap")

	// A missing first segment is a gap too.
	m2 := fsys.NewMem()
	s = openStore(t, m2, opts)
	for i := range 30 {
		commit(t, s, fmt.Sprint(i), strings.Repeat("v", 30))
	}
	s.Close()
	segs = segmentPaths(t, m2)
	m2.Remove(segs[0])
	wantCorruption(t, openErr(m2, opts), segs[1], -1, "still needed")
}

func TestSegmentHeader(t *testing.T) {
	t.Run("torn creation", func(t *testing.T) {
		m := fsys.NewMem()
		s := openStore(t, m, Options{})
		commit(t, s, "a", "1")
		s.Close()
		// A rotation that crashed while writing the new segment's header.
		torn := filepath.Join(testDir, "wal", segName(2))
		overwriteNew(t, m, torn, []byte("flintwal\x01\x00"))
		s = openStore(t, m, Options{})
		if _, err := m.Stat(torn); err == nil {
			// It was removed and then recreated cleanly for appends, or removed.
			if data := readAll(t, m, torn); len(data) > 0 {
				if _, err := parseSegHeader(data); err != nil {
					t.Fatalf("torn segment left in place: %v", err)
				}
			}
		}
		if seq := commit(t, s, "b", "2"); seq != 2 {
			t.Fatalf("seq = %d", seq)
		}
		s = reopen(t, s, m, Options{})
		wantGet(t, s, "a", "1", 1)
		wantGet(t, s, "b", "2", 2)
	})
	t.Run("rotted header with records", func(t *testing.T) {
		m := fsys.NewMem()
		s := openStore(t, m, Options{})
		commit(t, s, "a", "1")
		s.Close()
		seg := lastSegment(t, m)
		flipByte(t, m, seg, 3)
		wantCorruption(t, openErr(m, Options{}), seg, 0, "magic")
	})
}

func overwriteNew(t testing.TB, fs fsys.FS, path string, p []byte) {
	t.Helper()
	f, err := fs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(p)
	f.Sync()
	f.Close()
	if err := fs.SyncDir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
}

// TestEmbeddedRecordInValue checks that a value containing a well-formed
// log record cannot make a torn tail look like corruption: records are
// checksummed with a per-segment secret salt.
func TestEmbeddedRecordInValue(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, Options{})
	commit(t, s, "a", "1")
	s.Close()
	seg := lastSegment(t, m)
	data := readAll(t, m, seg)
	h, _ := parseSegHeader(data)
	// An attacker who knew the salt could forge a later-group record; one
	// who does not produces a record with some other salt.
	forged := appendRecord(nil, h.salt+1, 100, 100, time.Now(), batchOf("x", "y"))
	evil := appendRecord(nil, h.salt, 2, 2, time.Now(), batchOf("evil", string(forged)))
	overwrite(t, m, seg, int64(len(data)), evil[:len(evil)-3]) // torn
	s = openStore(t, m, Options{})
	wantAbsent(t, s, "evil")
}

func TestCorruptSnapshot(t *testing.T) {
	setup := func(t *testing.T, consumer bool) (*fsys.Mem, Options) {
		m := fsys.NewMem()
		opts := Options{SegmentSize: 200, SnapshotBytes: -1}
		s := openStore(t, m, opts)
		if consumer {
			if _, err := s.RegisterConsumer("audit"); err != nil { // holds every segment
				t.Fatal(err)
			}
		}
		for i := range 20 {
			commit(t, s, fmt.Sprint(i), strings.Repeat("v", 30))
		}
		if err := s.Snapshot(); err != nil {
			t.Fatal(err)
		}
		commit(t, s, "tail", "x")
		s.Close()
		return m, opts
	}
	snap := filepath.Join(testDir, "snapshots", snapName(20))
	t.Run("fallback to the log", func(t *testing.T) {
		m, opts := setup(t, true)
		flipByte(t, m, snap, 40)
		s := openStore(t, m, opts)
		wantGet(t, s, "19", strings.Repeat("v", 30), 20)
		wantGet(t, s, "tail", "x", 21)
	})
	t.Run("log already deleted", func(t *testing.T) {
		m, opts := setup(t, false)
		flipByte(t, m, snap, 40)
		err := openErr(m, opts)
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), snap) {
			t.Fatalf("err = %v, want corruption naming %s", err, snap)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		m, opts := setup(t, false)
		data := readAll(t, m, snap)
		overwriteNew(t, m, snap, data[:len(data)-5])
		if err := openErr(m, opts); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("leftover temp file", func(t *testing.T) {
		m, opts := setup(t, false)
		overwriteNew(t, m, filepath.Join(testDir, "snapshots", snapName(99)+".tmp"), []byte("partial"))
		s := openStore(t, m, opts)
		wantGet(t, s, "tail", "x", 21)
		if _, err := m.Stat(filepath.Join(testDir, "snapshots", snapName(99)+".tmp")); err == nil {
			t.Fatal("temp file not removed")
		}
	})
}

func TestCorruptCheckpoint(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, Options{})
	if _, err := s.RegisterConsumer("audit"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	path := filepath.Join(testDir, "consumers", "audit")
	flipByte(t, m, path, 9)
	wantCorruption(t, openErr(m, Options{}), path, 0, "checkpoint")
}

func TestReadLogDetectsCorruption(t *testing.T) {
	m := fsys.NewMem()
	opts := Options{SegmentSize: 200, SnapshotBytes: -1}
	s := openStore(t, m, opts)
	for i := range 30 {
		commit(t, s, fmt.Sprint(i), strings.Repeat("v", 30))
	}
	seg := segmentPaths(t, m)[0]
	offs := recordOffsets(t, readAll(t, m, seg))
	flipByte(t, m, seg, offs[1]+frameSize+3)
	err := s.ReadLog(context.Background(), 0, func(Entry) error { return nil })
	wantCorruption(t, err, seg, offs[1], "checksum")
}

// TestRandomTailDamage damages the final group commit at random and checks
// that recovery always succeeds and keeps every earlier group.
func TestRandomTailDamage(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 7))
	for i := range 200 {
		m := fsys.NewMem()
		s := openStore(t, m, Options{})
		for j := range 3 {
			commit(t, s, fmt.Sprint(j), strings.Repeat("v", r.IntN(100)))
		}
		s.Close()
		seg := lastSegment(t, m)
		size := int64(len(readAll(t, m, seg)))
		var batches []*Batch
		for j := range r.IntN(4) + 1 {
			batches = append(batches, batchOf(fmt.Sprintf("g%d", j), strings.Repeat("w", r.IntN(200))))
		}
		writeGroup(t, m, seg, 4, batches...)
		data := readAll(t, m, seg)
		tail := data[size:]
		for range r.IntN(5) + 1 {
			tail[r.IntN(len(tail))] ^= byte(r.IntN(255) + 1)
		}
		overwrite(t, m, seg, size, tail[:r.IntN(len(tail))+1])
		s2, err := Open(testDir, Options{FS: m, Logger: quiet})
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if st := s2.Stats(); st.Seq < 3 {
			t.Fatalf("iteration %d: lost acknowledged batches: seq %d", i, st.Seq)
		}
		s2.Close()
	}
}
