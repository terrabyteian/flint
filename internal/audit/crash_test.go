package audit

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

var crashIters = flag.Int("audit.crash-iters", 0, "iterations of the crash test (default 40, or 10 with -short)")

// TestCrashResume crashes the filesystem under the metadata store and the
// audit log at random points, with concurrent writers, a catching-up
// audit log, and snapshots that let the metadata store delete what the
// audit checkpoint covers, sometimes during recovery too. After every
// restart, the stream must hold each batch exactly once, in order, from
// the first audited batch to the latest, with every acknowledged batch
// under its own origin.
func TestCrashResume(t *testing.T) {
	iters := *crashIters
	switch {
	case iters > 0:
	case testing.Short():
		iters = 10
	default:
		iters = 40
	}
	seed := rand.Uint64()
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 1))
	m := fsys.NewMem()
	// The data directory exists, as flint serve makes sure.
	if err := m.MkdirAll("/data", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.SyncDir("/"); err != nil {
		t.Fatal(err)
	}
	acked := map[meta.Seq]string{} // sequence number to target
	var mu sync.Mutex
	for it := range iters {
		if rng.IntN(4) == 0 {
			m.CrashAfter(rng.Int64N(60)) // crash during recovery
		}
		s, err := meta.Open(metaDir, meta.Options{FS: m, Logger: quiet, SnapshotBytes: -1, SegmentSize: 2048})
		if err != nil {
			if !m.Crashed() {
				t.Fatalf("iteration %d: opening the store: %v", it, err)
			}
			m = m.Restart(rng)
			continue
		}
		l, err := Open(Options{Store: s, Dir: auditDir, FS: m, Logger: quiet, SegmentSize: 1024})
		if err != nil {
			s.Close()
			if !m.Crashed() {
				t.Fatalf("iteration %d: opening the audit log: %v", it, err)
			}
			m = m.Restart(rng)
			continue
		}
		if !m.Crashed() {
			m.CrashAfter(rng.Int64N(300))
		}

		var wg sync.WaitGroup
		done := make(chan struct{})
		for w := range 4 {
			wg.Go(func() {
				for i := range 30 {
					target := fmt.Sprintf("i%d-w%d-%d", it, w, i)
					var b meta.Batch
					b.Put([]byte(target), []byte("value"))
					b.SetOrigin(meta.Origin{Actor: "writer", Action: "test.put", Target: target})
					seq, err := s.Commit(context.Background(), &b)
					if err != nil {
						return
					}
					mu.Lock()
					acked[seq] = target
					mu.Unlock()
				}
			})
		}
		var syncer sync.WaitGroup
		syncer.Go(func() {
			for {
				if l.Sync(context.Background()) == nil && rng.IntN(8) == 0 {
					s.Snapshot()
				}
				select {
				case <-done:
					return
				default:
				}
			}
		})
		wg.Wait()
		close(done)
		syncer.Wait()
		l.Close()
		s.Close()
		m = m.Restart(rng)
	}

	s, err := meta.Open(metaDir, meta.Options{FS: m, Logger: quiet, SnapshotBytes: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	l, err := Open(Options{Store: s, Dir: auditDir, FS: m, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	recs := records(t, l, Filter{})
	if len(recs) == 0 {
		t.Fatalf("no records; %d acknowledged, latest %d", len(acked), l.latest())
	}
	// The audit log first started on an empty store, so it holds every batch.
	if recs[0].Seq != 1 || recs[len(recs)-1].Seq != l.latest() {
		t.Fatalf("the stream holds batches %d to %d, the store %d to %d", recs[0].Seq, recs[len(recs)-1].Seq, 1, l.latest())
	}
	for i, r := range recs {
		if r.Seq != meta.Seq(i+1) {
			t.Fatalf("record %d has batch %d: a gap or a duplicate", i, r.Seq)
		}
		if len(r.Keys) != 1 || string(r.Keys[0].Key) != r.Target || r.Actor != "writer" {
			t.Fatalf("record %+v does not describe its batch", r)
		}
		if want, ok := acked[r.Seq]; ok && r.Target != want {
			t.Fatalf("record %d is %q, but the acknowledged batch was %q", r.Seq, r.Target, want)
		}
	}
	for seq := range acked {
		if seq > recs[len(recs)-1].Seq {
			t.Fatalf("acknowledged batch %d is missing", seq)
		}
	}
	t.Logf("%d records after %d crashes", len(recs), iters)
}
