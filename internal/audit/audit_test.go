package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

const (
	metaDir  = "/data/meta"
	auditDir = "/data/audit"
)

var quiet = slog.New(slog.DiscardHandler)

func openStore(t *testing.T, fs fsys.FS, now func() time.Time) meta.Store {
	t.Helper()
	s, err := meta.Open(metaDir, meta.Options{FS: fs, Logger: quiet, SnapshotBytes: -1, SegmentSize: 4096, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func openLog(t *testing.T, opts Options) *Log {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = auditDir
	}
	opts.Logger = quiet
	l, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// commit commits a batch with the origin and a put of each key, with a
// value of value.
func commit(t *testing.T, s meta.Store, o meta.Origin, value []byte, keys ...string) meta.Seq {
	t.Helper()
	var b meta.Batch
	for _, k := range keys {
		if strings.HasPrefix(k, "-") {
			b.Delete([]byte(k[1:]))
		} else {
			b.Put([]byte(k), value)
		}
	}
	b.SetOrigin(o)
	seq, err := s.Commit(context.Background(), &b)
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

// records returns every record of the stream that f selects.
func records(t *testing.T, l *Log, f Filter) []Record {
	t.Helper()
	var out []Record
	err := l.Scan(context.Background(), f, func(r *Record) bool {
		c := *r
		c.Keys = nil
		for _, k := range r.Keys {
			c.Keys = append(c.Keys, Key{Delete: k.Delete, Key: bytes.Clone(k.Key)})
		}
		out = append(out, c)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// checkMatchesLog checks that the stream holds exactly the batches of the
// metadata log after after, in order, each with its origin and keys.
func checkMatchesLog(t *testing.T, l *Log, s meta.Store, after meta.Seq) {
	t.Helper()
	got := records(t, l, Filter{After: after})
	i := 0
	err := s.ReadLog(context.Background(), after, func(e meta.Entry) error {
		if i >= len(got) {
			return fmt.Errorf("the stream lacks batch %d", e.Seq)
		}
		r := got[i]
		i++
		o := e.Origin
		if r.Seq != e.Seq || !r.Time.Equal(e.Time) || r.Actor != o.Actor || r.Action != o.Action ||
			r.Target != o.Target || len(r.Keys) != len(e.Ops) {
			return fmt.Errorf("record %+v does not match batch %d %+v", r, e.Seq, e)
		}
		for j, op := range e.Ops {
			if r.Keys[j].Delete != op.Delete || !bytes.Equal(r.Keys[j].Key, op.Key) {
				return fmt.Errorf("batch %d key %d = %+v, want %q delete %v", e.Seq, j, r.Keys[j], op.Key, op.Delete)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if i != len(got) {
		t.Fatalf("the stream has %d records, the log %d batches", len(got), i)
	}
}

// streamBytes returns the contents of every file in the audit directory.
func streamBytes(t *testing.T, fs fsys.FS) []byte {
	t.Helper()
	ents, err := fs.ReadDir(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	var all []byte
	for _, e := range ents {
		f, err := fs.Open(filepath.Join(auditDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	return all
}

func TestRecordsMatchLog(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, nil)
	defer s.Close()
	// Batches before the audit log first starts are not audited.
	commit(t, s, meta.Origin{Actor: "early"}, []byte("v"), "before")
	l := openLog(t, Options{Store: s, FS: m, SegmentSize: 600})
	for i := range 50 {
		o := meta.Origin{Actor: "alice", Action: "test.put", Target: fmt.Sprint(i)}
		if i%7 == 0 {
			o.Actor = "alice (token abc)"
		}
		commit(t, s, o, []byte("value"), fmt.Sprintf("k\x00%d", i), fmt.Sprintf("-k\x00%d", i-1))
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkMatchesLog(t, l, s, 1)
	if st := l.Stats(); st.Seq != 51 || st.Segments < 3 || st.Fault != nil {
		t.Fatalf("stats = %+v, want seq 51 and several segments", st)
	}

	// Reopening continues the stream without duplicates.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Sync(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Sync after Close = %v", err)
	}
	commit(t, s, meta.Origin{Actor: "bob", Action: "test.put"}, nil, "after-close")
	l = openLog(t, Options{Store: s, FS: m, SegmentSize: 600})
	defer l.Close()
	commit(t, s, meta.Origin{Actor: "bob", Action: "test.put"}, nil, "after-reopen")
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkMatchesLog(t, l, s, 1)
}

// TestNeverValues checks that no value byte sequence reaches the stream.
func TestNeverValues(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, nil)
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m})
	defer l.Close()
	var values [][]byte
	for i := range 20 {
		v := []byte("SECRET-" + rand.Text())
		values = append(values, v)
		commit(t, s, meta.Origin{Actor: "a", Action: "test.put"}, v, fmt.Sprint("key", i))
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := streamBytes(t, m)
	if !bytes.Contains(all, []byte("key19")) {
		t.Fatal("the stream lacks the keys")
	}
	for _, v := range values {
		if bytes.Contains(all, v) || bytes.Contains(all, v[len("SECRET-"):]) {
			t.Fatalf("the stream contains the value %q", v)
		}
	}
	if bytes.Contains(all, []byte("SECRET")) {
		t.Fatal("the stream contains part of a value")
	}
}

func TestFilters(t *testing.T) {
	m := fsys.NewMem()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	s := openStore(t, m, now)
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m, SegmentSize: 100})
	defer l.Close()
	type batch struct{ actor, action, target string }
	for i, b := range []batch{
		{"alice", "oci.manifest.push", "docker-local/app:v1"},
		{"alice (token t1)", "oci.blob.push", "docker-local/app@sha256:aa"},
		{"alicex", "oci.manifest.push", "other/app:v1"},
		{meta.ActorSystem, "oci.upload.expire", "x"},
		{"bob", "oci.manifest.delete", "docker-local/app@sha256:bb"},
		{"admin", "auth.token.create", "token t2 of user bob"},
		{"alice", "oci.manifestx.push", "docker-local/lib:v2"},
	} {
		clock = clock.Add(time.Hour)
		commit(t, s, meta.Origin{Actor: b.actor, Action: b.action, Target: b.target}, nil, fmt.Sprint("k", i))
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	seqs := func(f Filter) []meta.Seq {
		var out []meta.Seq
		for _, r := range records(t, l, f) {
			out = append(out, r.Seq)
		}
		return out
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		f    Filter
		want []meta.Seq
	}{
		{"all", Filter{}, []meta.Seq{1, 2, 3, 4, 5, 6, 7}},
		{"after", Filter{After: 5}, []meta.Seq{6, 7}},
		{"after the end", Filter{After: 7}, nil},
		{"actor user", Filter{Actor: "alice"}, []meta.Seq{1, 2, 7}},
		{"actor token", Filter{Actor: "alice (token t1)"}, []meta.Seq{2}},
		{"actor system", Filter{Actor: meta.ActorSystem}, []meta.Seq{4}},
		{"action exact", Filter{Action: "oci.manifest.push"}, []meta.Seq{1, 3}},
		{"action prefix", Filter{Action: "oci.manifest"}, []meta.Seq{1, 3, 5}},
		{"action family", Filter{Action: "auth"}, []meta.Seq{6}},
		{"target prefix", Filter{Target: "docker-local/app"}, []meta.Seq{1, 2, 5}},
		{"since", Filter{Since: start.Add(5 * time.Hour)}, []meta.Seq{5, 6, 7}},
		{"until", Filter{Until: start.Add(3 * time.Hour)}, []meta.Seq{1, 2}},
		{"range", Filter{Since: start.Add(2 * time.Hour), Until: start.Add(4 * time.Hour)}, []meta.Seq{2, 3}},
		{"combined", Filter{Actor: "alice", Action: "oci", After: 1}, []meta.Seq{2, 7}},
	} {
		if got := seqs(tc.f); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if l.Stats().Segments < 3 {
		t.Fatalf("want several segments, have %d", l.Stats().Segments)
	}
}

// TestRotationByAge checks that a segment stops taking records after a
// day of commit times.
func TestRotationByAge(t *testing.T) {
	m := fsys.NewMem()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := openStore(t, m, func() time.Time { return clock })
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m})
	defer l.Close()
	for range 3 {
		commit(t, s, meta.Origin{Actor: "a"}, nil, "k")
		clock = clock.Add(13 * time.Hour)
		if err := l.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := l.Stats().Segments; n != 2 {
		t.Fatalf("segments = %d, want 2: a new one once records span a day", n)
	}
	checkMatchesLog(t, l, s, 0)
}

func TestRetention(t *testing.T) {
	m := fsys.NewMem()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	m.SetClock(now)
	s := openStore(t, m, now)
	defer s.Close()

	// By default nothing is deleted.
	l := openLog(t, Options{Store: s, FS: m, SegmentSize: 200, Now: now})
	fill := func(n int) {
		for range n {
			clock = clock.Add(time.Hour)
			commit(t, s, meta.Origin{Actor: "a", Action: "test.put", Target: strings.Repeat("t", 50)}, nil, "k")
			if err := l.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
	fill(40)
	if got := records(t, l, Filter{}); len(got) != 40 || got[0].Seq != 1 {
		t.Fatalf("without retention: %d records from %d", len(got), got[0].Seq)
	}
	segs := l.Stats().Segments
	l.Close()

	// By size: the oldest sealed segments go until the stream fits.
	l = openLog(t, Options{Store: s, FS: m, SegmentSize: 200, Now: now, MaxSize: 1000})
	fill(1) // rotates, which runs retention
	st := l.Stats()
	if st.Bytes > 1000 || st.Segments >= segs {
		t.Fatalf("with maxSize 1000: %+v, %d segments before", st, segs)
	}
	got := records(t, l, Filter{})
	if got[len(got)-1].Seq != 41 || got[0].Seq == 1 {
		t.Fatalf("with maxSize: records %d to %d", got[0].Seq, got[len(got)-1].Seq)
	}
	for i := range got[1:] {
		if got[i+1].Seq != got[i].Seq+1 {
			t.Fatalf("a gap after retention at %d", got[i].Seq)
		}
	}
	l.Close()

	// By age: segments whose newest record is older than maxAge go.
	l = openLog(t, Options{Store: s, FS: m, SegmentSize: 200, Now: now, MaxAge: 3 * time.Hour})
	fill(6) // rotations and retention apply as the clock advances
	got = records(t, l, Filter{})
	if age := clock.Sub(got[0].Time); age > 4*time.Hour {
		t.Fatalf("with maxAge 3h: the oldest record is %v old", age)
	}
	// Without new records, the active segment is sealed and goes too.
	clock = clock.Add(100 * time.Hour)
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := l.Stats(); st.Segments != 1 || st.Bytes != segHeaderSize {
		t.Fatalf("after 100h: %+v, want only an empty active segment", st)
	}
	if got := records(t, l, Filter{}); len(got) != 0 {
		t.Fatalf("after 100h: %d records remain", len(got))
	}
	fill(1)
	if got := records(t, l, Filter{}); len(got) != 1 || got[0].Seq != 48 {
		t.Fatalf("after sealing: records %+v", got)
	}
	l.Close()
}

// TestRetentionDerivesSegments checks that retention limits smaller than
// the default segment limits are honored closely: segments are sized and
// aged from them, and a quiet active segment is sealed so that its
// records are deleted soon after they pass maxAge.
func TestRetentionDerivesSegments(t *testing.T) {
	m := fsys.NewMem()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	m.SetClock(now)
	s := openStore(t, m, now)
	defer s.Close()

	const maxSize = 256 << 10
	l := openLog(t, Options{Store: s, FS: m, Now: now, MaxSize: maxSize})
	key := strings.Repeat("k", 1000)
	var seen int64
	for i := range 300 {
		clock = clock.Add(time.Second)
		commit(t, s, meta.Origin{Actor: "a", Action: "test.put"}, nil, key+fmt.Sprint(i), "-"+key)
		if err := l.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		st := l.Stats()
		if st.Bytes > maxSize+maxSize/4+4096 {
			t.Fatalf("with maxSize %d: the stream holds %d bytes after %d batches", maxSize, st.Bytes, i+1)
		}
		seen = max(seen, st.Bytes)
	}
	if seen < maxSize*3/4 {
		t.Fatalf("retention deleted too much: the stream held at most %d bytes", seen)
	}
	l.Close()

	const maxAge = time.Hour
	l = openLog(t, Options{Store: s, FS: m, Now: now, MaxAge: maxAge})
	defer l.Close()
	for range 30 {
		clock = clock.Add(10 * time.Minute)
		commit(t, s, meta.Origin{Actor: "a", Action: "test.put"}, nil, "k")
		if err := l.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		got := records(t, l, Filter{})
		if age := clock.Sub(got[0].Time); age > maxAge+maxAge/2 {
			t.Fatalf("with maxAge %v: the oldest record is %v old", maxAge, age)
		}
	}
	last := commit(t, s, meta.Origin{Actor: "a", Action: "test.put"}, nil, "k")
	for range 12 {
		clock = clock.Add(10 * time.Minute)
		if err := l.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	got := records(t, l, Filter{})
	if len(got) != 0 {
		t.Fatalf("two quiet hours after batch %d, records %d to %d remain", last, got[0].Seq, got[len(got)-1].Seq)
	}
}

// TestCheckpointHoldsLog checks that the metadata store keeps the log
// segments the audit log has not checkpointed, and deletes them once it
// has.
func TestCheckpointHoldsLog(t *testing.T) {
	m := fsys.NewMem()
	s, err := meta.Open(metaDir, meta.Options{FS: m, Logger: quiet, SnapshotBytes: -1, SegmentSize: 300})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m})
	defer l.Close()
	for i := range 40 {
		commit(t, s, meta.Origin{Actor: "a"}, []byte("vvvvvvvvvvvvvvvvvvvv"), fmt.Sprint("k", i))
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	held := s.Stats().Segments
	if held < 5 {
		t.Fatalf("only %d log segments", held)
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if n := s.Stats().Segments; n >= held {
		t.Fatalf("log segments: %d after the audit checkpoint, %d before", n, held)
	}
}

func TestTornTailAfterCheckpoint(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, nil)
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m})
	for i := range 5 {
		commit(t, s, meta.Origin{Actor: "a"}, nil, fmt.Sprint("k", i))
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.Close()
	// Records past the checkpoint whose write was torn: append a record
	// for a batch after the checkpoint, then cut it short.
	commit(t, s, meta.Origin{Actor: "a"}, nil, "k5")
	path := filepath.Join(auditDir, segName(1))
	f, err := m.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := appendRecord(nil, &meta.Entry{Seq: 6, Origin: meta.Origin{Actor: "a"}, Ops: []meta.Op{{Key: []byte("k5")}}})
	f.Write(rec[:len(rec)-3])
	f.Sync()
	f.Close()

	l = openLog(t, Options{Store: s, FS: m})
	defer l.Close()
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkMatchesLog(t, l, s, 0)
}

func TestCorruptCheckpointedRecord(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, nil)
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m})
	for i := range 5 {
		commit(t, s, meta.Origin{Actor: "a"}, nil, fmt.Sprint("k", i))
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.Close()
	path := filepath.Join(auditDir, segName(1))
	f, err := m.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(segHeaderSize+frameSize+2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0xff})
	f.Sync()
	f.Close()
	_, err = Open(Options{Store: s, Dir: auditDir, FS: m, Logger: quiet})
	var ce *CorruptionError
	if !errors.As(err, &ce) || ce.Path != path || ce.Offset != segHeaderSize {
		t.Fatalf("Open = %v, want a CorruptionError at %s offset %d", err, path, segHeaderSize)
	}
}

func TestTornSegmentCreation(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, nil)
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m})
	commit(t, s, meta.Origin{Actor: "a"}, nil, "k")
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.Close()
	// A crash while creating the next segment left a partial header.
	f, err := m.OpenFile(filepath.Join(auditDir, segName(2)), os.O_WRONLY|os.O_CREATE, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(appendSegHeader(nil, 2)[:10])
	f.Sync()
	f.Close()
	m.SyncDir(auditDir)

	commit(t, s, meta.Origin{Actor: "a"}, nil, "k2")
	l = openLog(t, Options{Store: s, FS: m})
	defer l.Close()
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkMatchesLog(t, l, s, 0)
	if _, err := m.Stat(filepath.Join(auditDir, segName(2))); err == nil {
		t.Fatal("the torn segment was kept")
	}
}

func TestStreamAheadOfStore(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, nil)
	l := openLog(t, Options{Store: s, FS: m})
	for i := range 3 {
		commit(t, s, meta.Origin{Actor: "a"}, nil, fmt.Sprint("k", i))
	}
	l.Close()
	s.Close()
	// The metadata store is replaced by an older one, as by a restore.
	m2 := fsys.NewMem()
	s2, err := meta.Open(metaDir, meta.Options{FS: m2, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	m2.MkdirAll(auditDir, 0o750)
	for _, name := range []string{segName(1)} {
		f, _ := m.Open(filepath.Join(auditDir, name))
		b, _ := io.ReadAll(f)
		f.Close()
		g, _ := m2.OpenFile(filepath.Join(auditDir, name), os.O_WRONLY|os.O_CREATE, 0o640)
		g.Write(b)
		g.Close()
	}
	if _, err := Open(Options{Store: s2, Dir: auditDir, FS: m2, Logger: quiet}); err == nil || !strings.Contains(err.Error(), "past the metadata store's latest batch") {
		t.Fatalf("Open = %v, want an error about the stream being ahead", err)
	}
}

// TestWriteFailureKeepsSegmentAge checks that a failed write does not
// reset the active segment's age when it already holds durable records,
// so the segment is still sealed a segment age after its oldest record.
func TestWriteFailureKeepsSegmentAge(t *testing.T) {
	m := fsys.NewMem()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := start
	now := func() time.Time { return clock }
	m.SetClock(now)
	s := openStore(t, m, now)
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m, Now: now, MaxAge: 4 * time.Hour}) // segment age 1h
	defer l.Close()
	commit(t, s, meta.Origin{Actor: "a"}, nil, "k0")
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	clock = start.Add(40 * time.Minute)
	failing := true
	m.SetFault(func(o fsys.Op, name string) error {
		if failing && strings.HasPrefix(name, auditDir) && o == fsys.OpWrite {
			return errors.New("injected failure")
		}
		return nil
	})
	commit(t, s, meta.Origin{Actor: "a"}, nil, "k1")
	if err := l.Sync(context.Background()); err == nil {
		t.Fatal("Sync succeeded with failing writes")
	}
	failing = false
	clock = start.Add(50 * time.Minute)
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	clock = start.Add(65 * time.Minute)
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := l.Stats().Segments; n != 2 {
		t.Fatalf("segments = %d, want 2: the segment's oldest record is over an hour old", n)
	}
	checkMatchesLog(t, l, s, 0)
}

// TestWriteFailureRecovers checks that after failed writes or fsyncs the
// stream is rewritten from the metadata log without losing or repeating a
// record.
func TestWriteFailureRecovers(t *testing.T) {
	for _, op := range []fsys.Op{fsys.OpWrite, fsys.OpSync, fsys.OpTruncate} {
		t.Run(string(op), func(t *testing.T) {
			m := fsys.NewMem()
			s := openStore(t, m, nil)
			defer s.Close()
			l := openLog(t, Options{Store: s, FS: m, SegmentSize: 300})
			defer l.Close()
			for i := range 5 {
				commit(t, s, meta.Origin{Actor: "a"}, nil, fmt.Sprint("k", i))
			}
			if err := l.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			failing := true
			m.SetFault(func(o fsys.Op, name string) error {
				if failing && strings.HasPrefix(name, auditDir) && (o == op || o == fsys.OpWrite) {
					return errors.New("injected failure")
				}
				return nil
			})
			for i := range 10 {
				commit(t, s, meta.Origin{Actor: "b"}, nil, fmt.Sprint("x", i))
			}
			if err := l.Sync(context.Background()); err == nil {
				t.Fatal("Sync succeeded with failing writes")
			}
			if err := l.Sync(context.Background()); err == nil {
				t.Fatal("Sync succeeded with failing writes")
			}
			if st := l.Stats(); st.Fault == nil || st.Seq != 5 {
				t.Fatalf("stats while failing = %+v", st)
			}
			failing = false
			if err := l.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			if st := l.Stats(); st.Fault != nil || st.Seq != 15 {
				t.Fatalf("stats after recovering = %+v", st)
			}
			checkMatchesLog(t, l, s, 0)

			// And after a restart, the durable state is the same.
			l.Close()
			s.Close()
			m2 := m.Restart(nil)
			s = openStore(t, m2, nil)
			l = openLog(t, Options{Store: s, FS: m2, SegmentSize: 300})
			if err := l.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			checkMatchesLog(t, l, s, 0)
			l.Close()
			s.Close()
		})
	}
}
