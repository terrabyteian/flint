package meta

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

var crashIters = flag.Int("meta.crash-iters", 0, "iterations of the crash tests (default 20, or 4 with -short)")

func iterations(normal, short int) int {
	switch {
	case *crashIters > 0:
		return *crashIters
	case testing.Short():
		return short
	}
	return normal
}

// consumerLoad reads the log as a durable consumer and checkpoints as it goes.
type consumerLoad struct {
	mu         sync.Mutex
	registered bool // registration acknowledged
	acked      Seq  // highest checkpoint acknowledged
}

func (c *consumerLoad) run(s Store, stop <-chan struct{}) error {
	cp, err := s.RegisterConsumer("audit")
	if err != nil {
		return nil // the store failed under us
	}
	c.mu.Lock()
	c.registered = true
	c.mu.Unlock()
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		next := cp
		err := s.ReadLog(context.Background(), cp, func(e Entry) error {
			if e.Seq != next+1 {
				return fmt.Errorf("ReadLog returned %d after %d", e.Seq, next)
			}
			next = e.Seq
			return nil
		})
		if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrCompacted) {
			return err
		}
		if err != nil || s.Checkpoint("audit", next) != nil {
			return nil
		}
		cp = next
		c.mu.Lock()
		c.acked = max(c.acked, cp)
		c.mu.Unlock()
		time.Sleep(200 * time.Microsecond)
	}
}

// check verifies that the consumer's acknowledged checkpoint survived and
// that the log after it is still readable.
func (c *consumerLoad) check(s Store) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Read the recovered checkpoint without RegisterConsumer, which would
	// quietly create a consumer whose registration was lost.
	st := s.(*store)
	st.mu.Lock()
	cp, ok := st.consumers["audit"]
	st.mu.Unlock()
	switch {
	case c.registered && !ok:
		return errors.New("acknowledged consumer registration was lost")
	case cp < c.acked:
		return fmt.Errorf("consumer checkpoint %d, but %d was acknowledged", cp, c.acked)
	}
	cp, err := s.RegisterConsumer("audit")
	if err != nil {
		return err
	}
	next := cp
	err = s.ReadLog(context.Background(), cp, func(e Entry) error {
		if e.Seq != next+1 {
			return fmt.Errorf("ReadLog returned %d after %d", e.Seq, next)
		}
		next = e.Seq
		return nil
	})
	if err != nil {
		return fmt.Errorf("reading the log after checkpoint %d: %w", cp, err)
	}
	if next != s.View().Seq() {
		return fmt.Errorf("ReadLog stopped at %d, store at %d", next, s.View().Seq())
	}
	return nil
}

// TestCrashRecovery runs the store on the strict in-memory filesystem
// under concurrent load, crashes it at random filesystem operations
// (including during recovery itself), and checks after every restart that
// every acknowledged write is present, no partial batch is visible, and
// consumer checkpoints and their log survive. Small segments and snapshot
// thresholds put rotations, snapshots, and segment deletion in the crash
// window.
func TestCrashRecovery(t *testing.T) {
	iters := iterations(20, 4)
	base := uint64(time.Now().UnixNano())
	for it := range iters {
		seed := base + uint64(it)
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 1))
			m := fsys.NewMem()
			w := newWorkload(6, 2)
			var cons consumerLoad
			opts := Options{FS: m, SegmentSize: 4 << 10, SnapshotBytes: 24 << 10, Logger: quiet}
			// est estimates the filesystem operations of one generation, so
			// that crash points fall inside the workload. It is refined from
			// every generation that finishes without crashing.
			est := int64(500)
			for gen := range 4 {
				opts.FS = m
				if r.IntN(5) == 0 {
					m.CrashAfter(1 + r.Int64N(40)) // crash during recovery
				}
				s, err := Open(testDir, opts)
				if errors.Is(err, fsys.ErrCrashed) {
					m = m.Restart(crashRand(r))
					continue
				}
				if err != nil {
					t.Fatalf("generation %d: Open: %v", gen, err)
				}
				m.CrashAfter(-1)
				if m.Crashed() {
					// The crash hit best-effort cleanup at the end of Open.
					s.Close()
					m = m.Restart(crashRand(r))
					continue
				}
				if err := w.check(s, gen > 0); err != nil {
					t.Fatalf("generation %d: %v", gen, err)
				}
				if err := cons.check(s); err != nil {
					t.Fatalf("generation %d: %v", gen, err)
				}
				start := m.Ops()
				crashAt := 1 + r.Int64N(est*9/10)
				m.CrashAfter(crashAt)
				stop := make(chan struct{})
				consErr := make(chan error, 1)
				go func() { consErr <- cons.run(s, stop) }()
				w.run(s, 40)
				close(stop)
				if err := <-consErr; err != nil {
					t.Fatalf("generation %d: consumer: %v", gen, err)
				}
				if !m.Crashed() {
					est = max(m.Ops()-start, 20)
				}
				s.Close()
				m = m.Restart(crashRand(r))
			}
			opts.FS = m
			s, err := Open(testDir, opts)
			if err != nil {
				t.Fatalf("final Open: %v", err)
			}
			defer s.Close()
			if err := w.check(s, true); err != nil {
				t.Fatal(err)
			}
			if err := cons.check(s); err != nil {
				t.Fatal(err)
			}
			// The recovered store takes writes.
			w.run(s, 3)
			if err := w.check(s, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// crashRand returns nil for a strict crash (every unsynced change lost) or
// a source for a torn crash (unsynced pages kept or lost at random).
func crashRand(r *rand.Rand) *rand.Rand {
	if r.IntN(2) == 0 {
		return nil
	}
	return rand.New(rand.NewPCG(r.Uint64(), r.Uint64()))
}

// TestMissingFsyncIsCaught checks that the crash harness has teeth: a store
// whose log fsync is skipped loses acknowledged writes in a strict crash.
func TestMissingFsyncIsCaught(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, Options{})
	commit(t, s, "a", "1")
	// Make the log's fsync a no-op that still reports success.
	m.SetFault(func(op fsys.Op, name string) error { return nil })
	st := s.(*store)
	st.active = noSync{st.active}
	commit(t, s, "b", "2")
	s.Close()
	s = openStore(t, m.Restart(nil), Options{})
	if _, _, ok := get(s, "b"); ok {
		t.Fatal("an unsynced write survived a strict crash")
	}
	w := newWorkload(1, 0)
	w.acked[0], w.maxSeq = 0, 2
	if err := w.check(s, false); err == nil {
		t.Fatal("check did not notice the lost acknowledged write")
	}
}

type noSync struct{ fsys.File }

func (noSync) Sync() error { return nil }
