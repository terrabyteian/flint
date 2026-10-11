package gc

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

var crashIters = flag.Int("gc.crash-iters", 150, "iterations of TestCrashDuringSweep")

// TestCrashDuringSweep loses power at random points while a sweep runs
// under concurrent links and unlinks, restarts, and checks that every
// blob the recovered metadata references exists, that every acknowledged
// link survived, that the doomed set was cleared, and that garbage
// collection and links work again.
func TestCrashDuringSweep(t *testing.T) {
	iters := *crashIters
	if testing.Short() {
		iters = 30
	}
	// Count where the crashes hit, so the test cannot quietly stop
	// crashing in the middle of sweeps.
	var midSweep, afterDeleting int
	for i := range iters {
		seed := uint64(i)
		r, ok := crashOnce(t, seed)
		if !ok {
			t.Fatalf("seed %d failed", seed)
		}
		if r != nil && r.State == StateFailed && r.Phase == "" && r.Stored.Blobs > 0 {
			midSweep++
			if r.Deleted.Blobs > 0 {
				afterDeleting++
			}
		}
	}
	t.Logf("%d of %d crashes hit a run after its scan, %d after it deleted blobs", midSweep, iters, afterDeleting)
	if midSweep < iters/10 || afterDeleting == 0 {
		t.Errorf("too few crashes hit a sweep: %d of %d, %d after deleting", midSweep, iters, afterDeleting)
	}
}

// crashWorkers link and unlink blobs while the sweep runs; each owns
// its own contents, so the last acknowledged operation on each is known.
const (
	crashWorkers  = 3
	crashContents = 4
	crashOps      = 12
)

// crashOnce runs one crash iteration and returns the report of the run
// that crashed, and whether the checks passed.
func crashOnce(t *testing.T, seed uint64) (*Report, bool) {
	rng := rand.New(rand.NewPCG(seed, 7))
	quiet := slog.New(slog.DiscardHandler)
	clk := &clock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	fs := fsys.NewMem()
	// Most iterations start the workers, and arm the crash, when the run
	// has scanned the blob store, so the crash hits its sweep; the others
	// start them with the run, so links race with marking too.
	early := seed%4 == 0
	crashAt := int64(rng.IntN(150))
	if !early {
		crashAt = int64(rng.IntN(60))
	}
	start := make(chan struct{})
	var startOnce sync.Once
	begin := func() {
		startOnce.Do(func() {
			fs.CrashAfter(crashAt)
			close(start)
		})
	}
	hook := func(s Step) {
		if s == StepScanned {
			begin()
		}
	}
	open := func(fs *fsys.Mem) (meta.Store, blob.Store, *Collector) {
		ms, err := meta.Open("/data/meta", meta.Options{FS: fs, Logger: quiet})
		if err != nil {
			t.Fatalf("seed %d: opening the metadata store: %v", seed, err)
		}
		bs, err := blob.NewFS("/data", blob.Options{FS: fs, Now: clk.now})
		if err != nil {
			t.Fatalf("seed %d: opening the blob store: %v", seed, err)
		}
		c, err := New(Options{Meta: ms, Blobs: bs, Markers: []Marker{testMarker}, Logger: quiet, Now: clk.now, RoundSize: 3, Hook: hook})
		if err != nil {
			t.Fatalf("seed %d: New: %v", seed, err)
		}
		return ms, bs, c
	}
	ms, bs, c := open(fs)

	// Old garbage, some of it the content workers link again, and old
	// linked content that workers unlink.
	content := func(w, j int) string { return fmt.Sprintf("worker %d content %d", w, j) }
	for w := range crashWorkers {
		for j := range crashContents {
			if _, err := putBlob(bs, content(w, j)); err != nil {
				t.Fatal(err)
			}
			if j%2 == 0 {
				if err := link(ms, bs, content(w, j), nil); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for j := range 6 {
		putBlob(bs, fmt.Sprintf("plain garbage %d", j))
	}
	clk.advance(DefaultGracePeriod + time.Second)

	if early {
		begin()
	}
	// state[w][j]: the last acknowledged state of content (w, j); unknown
	// while an operation on it was in flight at the crash.
	type state struct{ linked, unknown bool }
	states := make([][]state, crashWorkers)
	var wg sync.WaitGroup
	for w := range crashWorkers {
		states[w] = make([]state, crashContents)
		for j := range crashContents {
			states[w][j].linked = j%2 == 0
		}
		wrng := rand.New(rand.NewPCG(seed, uint64(w)))
		wg.Go(func() {
			<-start
			for range crashOps {
				j := wrng.IntN(crashContents)
				s := &states[w][j]
				d := blob.FromBytes([]byte(content(w, j)))
				var err error
				if wrng.IntN(3) > 0 {
					err = link(ms, bs, content(w, j), nil)
					if err == nil {
						s.linked = true
					}
				} else {
					var b meta.Batch
					b.Delete(linkKey(d))
					if _, err = ms.Commit(context.Background(), &b); err == nil {
						s.linked = false
					}
				}
				switch {
				case err == nil, errors.Is(err, ErrDoomed):
				case errors.Is(err, meta.ErrUnknownOutcome) || errors.Is(err, fsys.ErrCrashed) && !errors.Is(err, meta.ErrPoisoned):
					s.unknown = true
					return
				default:
					// Refused before writing anything: the state is unchanged.
					return
				}
			}
		})
	}
	var crashed *Report
	wg.Go(func() {
		crashed, _ = c.Run(context.Background(), RunOptions{})
		begin() // if the run failed before its scan
	})
	wg.Wait()
	c.Close()
	ms.Close()

	fs = fs.Restart(rng)
	ms, bs, c = open(fs)
	defer func() {
		c.Close()
		ms.Close()
	}()
	ok := true
	fail := func(format string, args ...any) {
		t.Errorf("seed %d: "+format, append([]any{seed}, args...)...)
		ok = false
	}
	if d := doomed(ms); len(d) != 0 {
		fail("doomed set after recovery: %v", d)
	}
	checkReferencedExist(t, ms, bs)
	v := ms.View()
	for w := range crashWorkers {
		for j, s := range states[w] {
			if s.unknown {
				continue
			}
			d := blob.FromBytes([]byte(content(w, j)))
			if _, linked := v.Get(linkKey(d)); linked != s.linked {
				fail("content %d/%d: linked = %v after recovery, want %v", w, j, linked, s.linked)
			}
		}
	}
	v.Release()

	// Garbage collection and links work again.
	r, err := c.Run(context.Background(), RunOptions{})
	if err != nil || r.State != StateSucceeded {
		fail("run after recovery = %+v, %v", r, err)
	}
	checkReferencedExist(t, ms, bs)
	for w := range crashWorkers {
		if err := link(ms, bs, content(w, 0), nil); err != nil {
			fail("link after recovery: %v", err)
		}
	}
	checkReferencedExist(t, ms, bs)
	return crashed, ok && !t.Failed()
}

// TestRestartMidSweep loses power at each step of a sweep, restarts, and
// checks that New clears the doomed set, that the referenced blobs exist,
// and that the next run completes the work.
func TestRestartMidSweep(t *testing.T) {
	for _, step := range []Step{StepDoomed, StepVerified, StepDeleted} {
		for _, round := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s in round %d", step, round), func(t *testing.T) {
				e := newTestEnv(t, func(o *Options) { o.RoundSize = 2 })
				keep := e.link("kept")
				var garbage []blob.Digest
				for i := range 4 {
					garbage = append(garbage, e.put(fmt.Sprintf("garbage %d", i)))
				}
				e.clock.advance(DefaultGracePeriod + time.Second)
				rounds := 0
				e.setHook(func(s Step) {
					if s == StepDoomed {
						rounds++
					}
					if s == step && rounds == round {
						e.fs.Crash()
					}
				})
				if r, err := e.c.Run(context.Background(), RunOptions{}); err != nil || r.State != StateFailed {
					t.Fatalf("run that crashed = %+v, %v", r, err)
				}
				e.setHook(nil)
				e.c.Close()
				e.meta.Close()
				e.fs = e.fs.Restart(nil)
				e.open(nil)
				if d := doomed(e.meta); len(d) != 0 {
					t.Fatalf("doomed set after restart: %v", d)
				}
				checkReferencedExist(t, e.meta, e.blobs)
				if !e.exists(keep) {
					t.Fatal("a referenced blob is gone")
				}
				if r := e.run(false); r.State != StateSucceeded {
					t.Fatalf("run after restart = %+v", r)
				}
				for _, d := range garbage {
					if e.exists(d) {
						t.Errorf("garbage %s survived the next run", d)
					}
				}
				if !e.exists(keep) {
					t.Error("a referenced blob is gone")
				}
			})
		}
	}
}

// TestPoisonedDuringSweep fails a run whose metadata store stops
// accepting writes mid-sweep, deletes nothing more, and leaves the
// doomed set for the restart to clear.
func TestPoisonedDuringSweep(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.RoundSize = 1 })
	a := e.put("garbage a")
	b := e.put("garbage b")
	e.clock.advance(DefaultGracePeriod + time.Second)
	rounds := 0
	e.setHook(func(s Step) {
		if s == StepDoomed {
			rounds++
		}
		if s == StepDeleted && rounds == 1 {
			e.fs.SetFault(func(op fsys.Op, name string) error {
				if op == fsys.OpSync {
					return errors.New("injected fsync failure")
				}
				return nil
			})
		}
	})
	r := e.run(false)
	e.setHook(nil)
	if r.State != StateFailed || r.Deleted.Blobs != 1 || !strings.Contains(r.Error, "clearing the doomed set") {
		t.Fatalf("report = %+v", r)
	}
	if e.exists(a) == e.exists(b) {
		t.Fatalf("want exactly one of the two blobs deleted, before the fault")
	}
	if !strings.Contains(e.logs.String(), "links of its blobs fail until a run or a restart clears it") {
		t.Errorf("no log of the doomed set left behind:\n%s", e.logs)
	}
	e.fs.SetFault(nil)
	e.c.Close()
	e.meta.Close()
	e.fs = e.fs.Restart(nil)
	e.open(nil)
	if d := doomed(e.meta); len(d) != 0 {
		t.Fatalf("doomed set after restart: %v", d)
	}
	if r := e.run(false); r.State != StateSucceeded || e.exists(a) || e.exists(b) {
		t.Errorf("run after restart = %+v", r)
	}
}
