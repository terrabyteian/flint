package meta

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

const testDir = "meta"

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func openStore(t testing.TB, fs fsys.FS, opts Options) Store {
	t.Helper()
	opts.FS = fs
	if opts.Logger == nil {
		opts.Logger = quiet
	}
	s, err := Open(testDir, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func reopen(t testing.TB, s Store, fs fsys.FS, opts Options) Store {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return openStore(t, fs, opts)
}

func commit(t testing.TB, s Store, kv ...string) Seq {
	t.Helper()
	var b Batch
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "<del>" {
			b.Delete([]byte(kv[i]))
		} else {
			b.Put([]byte(kv[i]), []byte(kv[i+1]))
		}
	}
	seq, err := s.Commit(context.Background(), &b)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return seq
}

func get(s Store, key string) (string, Seq, bool) {
	v := s.View()
	defer v.Release()
	r, ok := v.Get([]byte(key))
	return string(r.Value), r.Version, ok
}

func wantGet(t testing.TB, s Store, key, want string, wantVer Seq) {
	t.Helper()
	got, ver, ok := get(s, key)
	if !ok || got != want || (wantVer != 0 && ver != wantVer) {
		t.Fatalf("%s = %q@%d (present %v), want %q@%d", key, got, ver, ok, want, wantVer)
	}
}

func wantAbsent(t testing.TB, s Store, key string) {
	t.Helper()
	if got, _, ok := get(s, key); ok {
		t.Fatalf("%s = %q, want absent", key, got)
	}
}

func TestCommitGetDelete(t *testing.T) {
	s := openStore(t, fsys.NewMem(), Options{})
	if v := s.View(); v.Seq() != 0 {
		t.Fatalf("empty store at seq %d", v.Seq())
	}
	if seq := commit(t, s, "a", "1", "b", "2"); seq != 1 {
		t.Fatalf("first seq = %d", seq)
	}
	if seq := commit(t, s, "a", "3", "b", "<del>", "b", "4", "c", "<del>"); seq != 2 {
		t.Fatalf("second seq = %d", seq)
	}
	wantGet(t, s, "a", "3", 2)
	wantGet(t, s, "b", "4", 2) // the last op on a key wins
	wantAbsent(t, s, "c")
	commit(t, s, "a", "<del>")
	wantAbsent(t, s, "a")
	if st := s.Stats(); st.Seq != 3 || st.Keys != 1 || st.Commits != 3 {
		t.Fatalf("Stats = %+v", st)
	}
	// An empty value is present, not absent.
	commit(t, s, "empty", "")
	wantGet(t, s, "empty", "", 4)
}

func TestRequire(t *testing.T) {
	s := openStore(t, fsys.NewMem(), Options{})
	ctx := context.Background()
	var b Batch
	b.Require([]byte("tag"), 0)
	b.Put([]byte("tag"), []byte("v1"))
	v1, err := s.Commit(ctx, &b)
	if err != nil {
		t.Fatal(err)
	}

	// The same create-if-absent batch now conflicts, and none of its ops apply.
	b.Put([]byte("other"), []byte("x"))
	if _, err := s.Commit(ctx, &b); !errors.Is(err, ErrConflict) {
		t.Fatalf("second create: err = %v, want ErrConflict", err)
	}
	wantAbsent(t, s, "other")

	var u Batch
	u.Require([]byte("tag"), v1)
	u.Require([]byte("missing"), 0)
	u.Put([]byte("tag"), []byte("v2"))
	v2, err := s.Commit(ctx, &u)
	if err != nil {
		t.Fatal(err)
	}
	wantGet(t, s, "tag", "v2", v2)
	// A stale version conflicts.
	if _, err := s.Commit(ctx, &u); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: err = %v, want ErrConflict", err)
	}
	if st := s.Stats(); st.Conflicts != 2 {
		t.Fatalf("Conflicts = %d", st.Conflicts)
	}
}

// TestRequireConcurrent runs compare-and-swap increments from many
// goroutines; preconditions must make every acknowledged increment count.
func TestRequireConcurrent(t *testing.T) {
	s := openStore(t, fsys.NewMem(), Options{})
	const workers, incs = 8, 50
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for done := 0; done < incs; {
				val, ver, _ := get(s, "ctr")
				var n int
				fmt.Sscan(val, &n)
				var b Batch
				b.Require([]byte("ctr"), ver)
				b.Put([]byte("ctr"), fmt.Append(nil, n+1))
				_, err := s.Commit(context.Background(), &b)
				switch {
				case err == nil:
					done++
				case !errors.Is(err, ErrConflict):
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	wantGet(t, s, "ctr", fmt.Sprint(workers*incs), 0)
}

func TestViewIsolationAndScan(t *testing.T) {
	s := openStore(t, fsys.NewMem(), Options{})
	commit(t, s, "oci\x00tag\x00r\x00a", "1", "oci\x00tag\x00r\x00b", "2", "oci\x00tag\x00r\x00c", "3", "oci\x00tag\x00r2\x00a", "4", "oci\x00tah", "5")
	v := s.View()
	defer v.Release()
	commit(t, s, "oci\x00tag\x00r\x00b", "<del>", "oci\x00tag\x00r\x00d", "6")
	if v.Seq() != 1 {
		t.Fatalf("view seq = %d", v.Seq())
	}

	scan := func(v View, prefix, after string) []string {
		var out []string
		var a []byte
		if after != "" {
			a = []byte(after)
		}
		v.Scan([]byte(prefix), a, func(k []byte, r Record) bool {
			out = append(out, string(k[len(prefix):])+"="+string(r.Value))
			return true
		})
		return out
	}
	p := "oci\x00tag\x00r\x00"
	for _, tc := range []struct {
		after string
		want  []string
	}{
		{"", []string{"a=1", "b=2", "c=3"}},
		{p + "a", []string{"b=2", "c=3"}},
		{p + "b0", []string{"c=3"}},
		{p + "c", nil},
		{"a", []string{"a=1", "b=2", "c=3"}},                   // after sorts before the prefix
		{"oci\x00tah", nil},                                    // after sorts past the prefix
		{"oci\x00tag\x00r\x00", []string{"a=1", "b=2", "c=3"}}, // after is the prefix itself
	} {
		if got := scan(v, p, tc.after); !slices.Equal(got, tc.want) {
			t.Errorf("old view: Scan after %q = %q, want %q", tc.after, got, tc.want)
		}
	}
	cur := s.View()
	defer cur.Release()
	if got := scan(cur, p, ""); !slices.Equal(got, []string{"a=1", "c=3", "d=6"}) {
		t.Errorf("new view: Scan = %q", got)
	}
	// Stopping early.
	var n int
	cur.Scan(nil, nil, func([]byte, Record) bool { n++; return n < 2 })
	if n != 2 {
		t.Errorf("Scan did not stop when fn returned false: %d calls", n)
	}
}

func TestPinnedViews(t *testing.T) {
	s := openStore(t, fsys.NewMem(), Options{})
	commit(t, s, "k", "1")
	p1 := s.PinView()
	commit(t, s, "k", "2")
	p2 := s.PinView()
	plain := s.View()
	plain.Release()
	pins := s.PinnedViews()
	if len(pins) != 2 || pins[0].Seq() != 1 || pins[1].Seq() != 2 {
		t.Fatalf("PinnedViews seqs = %v", pins)
	}
	if r, _ := pins[0].Get([]byte("k")); string(r.Value) != "1" {
		t.Fatalf("pinned view sees %q", r.Value)
	}
	for _, v := range pins {
		v.Release() // releasing a returned view does not unpin
	}
	if st := s.Stats(); st.PinnedViews != 2 {
		t.Fatalf("PinnedViews = %d after releasing copies", st.PinnedViews)
	}
	p1.Release()
	p1.Release() // idempotent
	if pins := s.PinnedViews(); len(pins) != 1 || pins[0].Seq() != 2 {
		t.Fatalf("after releasing the first pin: %d pins", len(pins))
	}
	p2.Release()
	if pins := s.PinnedViews(); len(pins) != 0 {
		t.Fatalf("%d pins left", len(pins))
	}
}

func TestReopen(t *testing.T) {
	m := fsys.NewMem()
	opts := Options{SegmentSize: 1 << 10, SnapshotBytes: -1}
	s := openStore(t, m, opts)
	want := map[string]string{}
	for i := range 200 {
		k, v := fmt.Sprintf("k%03d", i%50), fmt.Sprintf("v%d-%s", i, bytes.Repeat([]byte("x"), i%40))
		commit(t, s, k, v)
		want[k] = v
	}
	if st := s.Stats(); st.Segments < 5 {
		t.Fatalf("only %d segments; rotation did not happen", st.Segments)
	}
	check := func(s Store) {
		t.Helper()
		for k, v := range want {
			wantGet(t, s, k, v, 0)
		}
		if st := s.Stats(); st.Seq != 200 || st.Keys != 50 {
			t.Fatalf("Stats after reopen = %+v", st)
		}
	}
	s = reopen(t, s, m, opts)
	check(s)
	// Reopen again: the reopened active segment takes appends.
	commit(t, s, "after", "reopen")
	want["after"] = "reopen"
	s = reopen(t, s, m, opts)
	wantGet(t, s, "after", "reopen", 201)
	if seq := commit(t, s, "next", "x"); seq != 202 {
		t.Fatalf("seq after reopen = %d", seq)
	}
}

func TestSnapshotAndRetention(t *testing.T) {
	m := fsys.NewMem()
	opts := Options{SegmentSize: 512, SnapshotBytes: -1}
	s := openStore(t, m, opts)
	for i := range 100 {
		commit(t, s, fmt.Sprintf("k%02d", i%30), fmt.Sprint(i))
	}
	before := s.Stats()
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	after := s.Stats()
	if after.SnapshotSeq != 100 || after.Snapshots != 1 {
		t.Fatalf("after snapshot: %+v", after)
	}
	if after.Segments != 1 || after.Segments >= before.Segments {
		t.Fatalf("segments %d -> %d; want only the active one left", before.Segments, after.Segments)
	}
	segs, _ := m.ReadDir(filepath.Join(testDir, "wal"))
	if len(segs) != 1 {
		t.Fatalf("%d segment files on disk", len(segs))
	}
	for i := 100; i < 130; i++ {
		commit(t, s, fmt.Sprintf("k%02d", i%30), fmt.Sprint(i))
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	snaps, _ := m.ReadDir(filepath.Join(testDir, "snapshots"))
	if len(snaps) != 1 || snaps[0].Name() != snapName(130) {
		t.Fatalf("snapshot files = %v", snaps)
	}
	commit(t, s, "tail", "x")
	s = reopen(t, s, m, opts)
	for i := 100; i < 130; i++ {
		wantGet(t, s, fmt.Sprintf("k%02d", i%30), fmt.Sprint(i), Seq(i+1))
	}
	wantGet(t, s, "tail", "x", 131)
	if st := s.Stats(); st.SnapshotSeq != 130 || st.Keys != 31 {
		t.Fatalf("Stats after reopen = %+v", st)
	}
}

func TestSnapshotLargeEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 65 MiB value")
	}
	m := fsys.NewMem()
	opts := Options{MaxBatchBytes: 128 << 20, SnapshotBytes: -1}
	s := openStore(t, m, opts)
	big := strings.Repeat("v", 65<<20)
	commit(t, s, "big", big)
	commit(t, s, "small", "x")
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	s = reopen(t, s, m, opts)
	if st := s.Stats(); st.SnapshotSeq != 2 {
		t.Fatalf("SnapshotSeq after reopen = %d; want 2", st.SnapshotSeq)
	}
	if v, ver, ok := get(s, "big"); !ok || ver != 1 || v != big {
		t.Fatalf("big value after reopen: ok %v, version %d, %d bytes", ok, ver, len(v))
	}
	wantGet(t, s, "small", "x", 2)
}

func TestBackgroundSnapshot(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, Options{SegmentSize: 1 << 10, SnapshotBytes: 4 << 10})
	for i := range 300 {
		commit(t, s, fmt.Sprintf("k%03d", i), string(bytes.Repeat([]byte("v"), 50)))
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Stats().Snapshots == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no background snapshot")
		}
		time.Sleep(time.Millisecond)
	}
	s = reopen(t, s, m, Options{})
	if st := s.Stats(); st.Seq != 300 || st.Keys != 300 || st.SnapshotSeq == 0 {
		t.Fatalf("Stats after reopen = %+v", st)
	}
}

func TestCommitContext(t *testing.T) {
	s := openStore(t, fsys.NewMem(), Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var b Batch
	b.Put([]byte("k"), []byte("v"))
	if _, err := s.Commit(ctx, &b); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Commit: err = %v", err)
	}
	wantAbsent(t, s, "k")
}

func TestBatchTooLarge(t *testing.T) {
	s := openStore(t, fsys.NewMem(), Options{MaxBatchBytes: 1 << 10})
	var b Batch
	b.Put([]byte("k"), make([]byte, 2<<10))
	if _, err := s.Commit(context.Background(), &b); !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("err = %v, want ErrBatchTooLarge", err)
	}
	commit(t, s, "small", "ok")
}

// blockingSync returns a fault hook that blocks every log fsync until
// release is closed, signalling on entered first.
func blockingSync(entered chan<- struct{}, release <-chan struct{}) func(fsys.Op, string) error {
	var once sync.Once
	return func(op fsys.Op, name string) error {
		if op == fsys.OpSync && filepath.Ext(name) == ".log" {
			once.Do(func() { close(entered) })
			<-release
		}
		return nil
	}
}

func TestGroupCommit(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, Options{})
	entered, release := make(chan struct{}), make(chan struct{})
	m.SetFault(blockingSync(entered, release))
	var wg sync.WaitGroup
	wg.Go(func() { commit(t, s, "first", "x") })
	<-entered
	// While the first fsync is stuck, queue more commits; they must share
	// the next group commit.
	const n = 20
	for i := range n {
		wg.Go(func() { commit(t, s, fmt.Sprint(i), "x") })
	}
	for {
		s.(*store).qmu.Lock()
		q := len(s.(*store).queue)
		s.(*store).qmu.Unlock()
		if q == n {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	m.SetFault(nil)
	if st := s.Stats(); st.Commits != n+1 || st.GroupCommits != 2 {
		t.Fatalf("Commits = %d, GroupCommits = %d; want %d commits in 2 groups", st.Commits, st.GroupCommits, n+1)
	}
}

func TestClose(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, Options{})
	entered, release := make(chan struct{}), make(chan struct{})
	m.SetFault(blockingSync(entered, release))
	errA, errB := make(chan error, 1), make(chan error, 1)
	go func() { _, err := s.Commit(context.Background(), batchOf("a", "1")); errA <- err }()
	<-entered
	go func() { _, err := s.Commit(context.Background(), batchOf("b", "2")); errB <- err }()
	for {
		s.(*store).qmu.Lock()
		q := len(s.(*store).queue)
		s.(*store).qmu.Unlock()
		if q == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan error)
	go func() { closed <- s.Close() }()
	for {
		s.(*store).qmu.Lock()
		c := s.(*store).closing
		s.(*store).qmu.Unlock()
		if c {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The commit being written completes; the queued one fails with ErrClosed.
	e1, e2 := <-errA, <-errB
	if e1 != nil || !errors.Is(e2, ErrClosed) {
		t.Fatalf("commit errors = %v, %v; want nil, ErrClosed", e1, e2)
	}
	if _, err := s.Commit(context.Background(), batchOf("c", "3")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Commit after Close: %v", err)
	}
	if _, err := s.RegisterConsumer("x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("RegisterConsumer after Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	wantGet(t, s, "a", "1", 1) // views still work
	m.SetFault(nil)
	s = openStore(t, m, Options{})
	wantGet(t, s, "a", "1", 1)
	wantAbsent(t, s, "b")
}

func batchOf(kv ...string) *Batch {
	var b Batch
	for i := 0; i < len(kv); i += 2 {
		b.Put([]byte(kv[i]), []byte(kv[i+1]))
	}
	return &b
}

func TestReadLog(t *testing.T) {
	m := fsys.NewMem()
	opts := Options{SegmentSize: 300, SnapshotBytes: -1, Now: func() time.Time { return time.Unix(1700000000, 42) }}
	s := openStore(t, m, opts)
	for i := 1; i <= 40; i++ {
		b := batchOf(fmt.Sprintf("k%d", i), fmt.Sprintf("v%d", i))
		if i%3 == 0 {
			b.Delete([]byte(fmt.Sprintf("k%d", i-1)))
		}
		b.SetOrigin(Origin{Actor: "alice", Action: "test.put", Target: fmt.Sprint(i)})
		if _, err := s.Commit(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}
	read := func(after Seq) []Entry {
		t.Helper()
		var out []Entry
		if err := s.ReadLog(context.Background(), after, func(e Entry) error { out = append(out, e); return nil }); err != nil {
			t.Fatalf("ReadLog(%d): %v", after, err)
		}
		return out
	}
	all := read(0)
	if len(all) != 40 {
		t.Fatalf("read %d entries", len(all))
	}
	for i, e := range all {
		n := i + 1
		if e.Seq != Seq(n) || e.Origin != (Origin{"alice", "test.put", fmt.Sprint(n)}) || !e.Time.Equal(time.Unix(1700000000, 42)) {
			t.Fatalf("entry %d = %+v", n, e)
		}
		if string(e.Ops[0].Key) != fmt.Sprintf("k%d", n) || string(e.Ops[0].Value) != fmt.Sprintf("v%d", n) || e.Ops[0].Delete {
			t.Fatalf("entry %d op = %+v", n, e.Ops[0])
		}
		if n%3 == 0 && (len(e.Ops) != 2 || !e.Ops[1].Delete || e.Ops[1].Value != nil) {
			t.Fatalf("entry %d delete op = %+v", n, e.Ops)
		}
	}
	if got := read(25); len(got) != 15 || got[0].Seq != 26 {
		t.Fatalf("ReadLog(25) returned %d entries starting at %d", len(got), got[0].Seq)
	}
	if got := read(40); len(got) != 0 {
		t.Fatalf("ReadLog(40) returned %d entries", len(got))
	}
	stop := errors.New("stop")
	if err := s.ReadLog(context.Background(), 0, func(Entry) error { return stop }); err != stop {
		t.Fatalf("fn error not returned: %v", err)
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if err := s.ReadLog(context.Background(), 0, func(Entry) error { return nil }); !errors.Is(err, ErrCompacted) {
		t.Fatalf("ReadLog of deleted segments: err = %v, want ErrCompacted", err)
	}
}

func TestConsumers(t *testing.T) {
	m := fsys.NewMem()
	opts := Options{SegmentSize: 300, SnapshotBytes: -1}
	s := openStore(t, m, opts)
	commit(t, s, "a", "1")
	for _, name := range []string{"Bad/Name", "audit.tmp"} {
		if _, err := s.RegisterConsumer(name); err == nil {
			t.Fatalf("invalid consumer name %q accepted", name)
		}
	}
	cp, err := s.RegisterConsumer("audit")
	if err != nil || cp != 1 {
		t.Fatalf("RegisterConsumer = %d, %v; want the latest seq 1", cp, err)
	}
	if err := s.Checkpoint("nobody", 1); !errors.Is(err, ErrUnknownConsumer) {
		t.Fatalf("Checkpoint unknown: %v", err)
	}
	if err := s.UnregisterConsumer("nobody"); !errors.Is(err, ErrUnknownConsumer) {
		t.Fatalf("Unregister unknown: %v", err)
	}
	for i := range 50 {
		commit(t, s, fmt.Sprintf("k%d", i), "some value to fill segments")
	}
	if err := s.Checkpoint("audit", 999); err == nil {
		t.Fatal("checkpoint past the log accepted")
	}
	// The consumer holds every segment after its checkpoint, even past a snapshot.
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.ReadLog(context.Background(), cp, func(e Entry) error { n++; return nil }); err != nil || n != 50 {
		t.Fatalf("consumer read %d entries, err %v", n, err)
	}
	segsBefore := s.Stats().Segments
	if err := s.Checkpoint("audit", 30); err != nil {
		t.Fatal(err)
	}
	if err := s.Checkpoint("audit", 20); err == nil {
		t.Fatal("checkpoint moving backwards accepted")
	}
	s = reopen(t, s, m, opts)
	if cp, err := s.RegisterConsumer("audit"); err != nil || cp != 30 {
		t.Fatalf("reopened consumer checkpoint = %d, %v; want 30", cp, err)
	}
	if err := s.Snapshot(); err != nil { // retention runs; segments up to 30 may go
		t.Fatal(err)
	}
	if after := s.Stats().Segments; after >= segsBefore {
		t.Fatalf("segments %d -> %d after checkpoint and snapshot", segsBefore, after)
	}
	n = 0
	if err := s.ReadLog(context.Background(), 30, func(e Entry) error { n++; return nil }); err != nil || n != 21 {
		t.Fatalf("consumer read %d entries after reopen, err %v", n, err)
	}
	if err := s.UnregisterConsumer("audit"); err != nil {
		t.Fatal(err)
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.Segments != 1 {
		t.Fatalf("%d segments after unregistering the consumer", st.Segments)
	}
	s = reopen(t, s, m, opts)
	if err := s.Checkpoint("audit", 51); !errors.Is(err, ErrUnknownConsumer) {
		t.Fatalf("unregistered consumer survived reopen: %v", err)
	}
}

func TestStoreOnOS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "meta")
	s, err := Open(dir, Options{Logger: quiet, SegmentSize: 4 << 10})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		commit(t, s, fmt.Sprintf("k%d", i), fmt.Sprintf("v%d", i))
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	commit(t, s, "last", "x")
	s.Close()
	s, err = Open(dir, Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	wantGet(t, s, "k99", "v99", 100)
	wantGet(t, s, "last", "x", 101)
}
