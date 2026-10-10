package blob

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

// ledger records what a crash-test workload attempted and what the store
// acknowledged, so the post-crash state can be checked against it.
type ledger struct {
	mu        sync.Mutex
	attempted map[Digest][]byte // every content a Commit was called for with its true digest
	committed map[Digest]bool   // acknowledged commits
	deleting  map[Digest]bool   // deletes started; contents never re-uploaded
	deleted   map[Digest]bool   // acknowledged deletes
	never     map[Digest]bool   // contents only ever committed under a wrong digest
	chunked   map[string]*chunkedUpload
}

// chunkedUpload tracks one suspended-and-resumed upload.
type chunkedUpload struct {
	content   []byte
	sizes     []int64 // sizes at which a Suspend was started
	acked     int64   // size at the last acknowledged Suspend
	suspended bool    // some Suspend was acknowledged
	finishing bool    // a Commit was started after the last acknowledged Suspend
	done      bool    // a Commit was acknowledged
}

func newLedger() *ledger {
	return &ledger{
		attempted: map[Digest][]byte{},
		committed: map[Digest]bool{},
		deleting:  map[Digest]bool{},
		deleted:   map[Digest]bool{},
		never:     map[Digest]bool{},
		chunked:   map[string]*chunkedUpload{},
	}
}

func (l *ledger) do(f func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f()
}

// shared are contents every worker uploads, so commits of identical
// content race each other.
var shared = [][]byte{
	bytes.Repeat([]byte("shared-a "), 500),
	bytes.Repeat([]byte("shared-b "), 1500),
	{},
}

// worker runs one goroutine of the crash workload until it has done n
// operations or the filesystem fails. It returns the first error that is
// not an expected outcome.
func worker(s Store, l *ledger, w, n int, rng *rand.Rand) error {
	var mine []Digest // unique committed blobs this worker may delete
	for i := range n {
		unique := fmt.Appendf(nil, "worker %d op %d ", w, i)
		unique = append(unique, randBytes(rng, rng.IntN(3*4096+100))...)
		var err error
		switch k := rng.IntN(10); {
		case k < 3:
			var d Digest
			if d, err = commitWhole(s, l, unique); err == nil {
				mine = append(mine, d)
			}
		case k < 5:
			_, err = commitWhole(s, l, shared[rng.IntN(len(shared))])
		case k < 7:
			err = commitChunked(s, l, unique, rng)
		case k < 8:
			err = commitMismatched(s, l, unique)
		case k < 9:
			if len(mine) == 0 {
				continue
			}
			d := mine[0]
			mine = mine[1:]
			l.do(func() { l.deleting[d] = true })
			if err = s.Delete(ctx, d); err == nil {
				l.do(func() { l.deleted[d] = true })
			}
		default:
			var u Upload
			if u, err = s.NewUpload(ctx); err == nil {
				if _, err = u.Write(unique); err == nil {
					err = u.Cancel()
				}
			}
		}
		if err != nil {
			if errors.Is(err, fsys.ErrCrashed) {
				return nil
			}
			return fmt.Errorf("worker %d op %d: %w", w, i, err)
		}
	}
	return nil
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

func commitWhole(s Store, l *ledger, data []byte) (Digest, error) {
	d := FromBytes(data)
	u, err := s.NewUpload(ctx)
	if err != nil {
		return d, err
	}
	if _, err := u.Write(data); err != nil {
		u.Cancel()
		return d, err
	}
	l.do(func() { l.attempted[d] = data })
	if _, err := u.Commit(ctx, d); err != nil {
		return d, err
	}
	l.do(func() { l.committed[d] = true })
	return d, nil
}

func commitChunked(s Store, l *ledger, data []byte, rng *rand.Rand) error {
	d := FromBytes(data)
	cuts := []int{0, len(data)}
	for range 1 + rng.IntN(3) {
		cuts = append(cuts, rng.IntN(len(data)+1))
	}
	slices.Sort(cuts)
	u, err := s.NewUpload(ctx)
	if err != nil {
		return err
	}
	c := &chunkedUpload{content: data}
	id := u.ID()
	l.do(func() { l.chunked[id] = c })
	for i := 1; i < len(cuts); i++ {
		if i > 1 {
			if u, err = s.ResumeUpload(ctx, id); err != nil {
				return err
			}
		}
		if _, err := u.Write(data[cuts[i-1]:cuts[i]]); err != nil {
			u.Cancel()
			return err
		}
		if i == len(cuts)-1 {
			break
		}
		l.do(func() { c.sizes = append(c.sizes, u.Size()) })
		if err := u.Suspend(); err != nil {
			return err
		}
		l.do(func() { c.acked, c.suspended = u.Size(), true })
	}
	l.do(func() { c.finishing = true; l.attempted[d] = data })
	if _, err := u.Commit(ctx, d); err != nil {
		return err
	}
	l.do(func() { c.done = true; l.committed[d] = true })
	return nil
}

func commitMismatched(s Store, l *ledger, data []byte) error {
	u, err := s.NewUpload(ctx)
	if err != nil {
		return err
	}
	if _, err := u.Write(data); err != nil {
		u.Cancel()
		return err
	}
	l.do(func() { l.never[FromBytes(data)] = true })
	_, err = u.Commit(ctx, FromBytes(append(data, '!')))
	if errors.Is(err, ErrDigestMismatch) {
		return nil
	}
	if err == nil {
		return errors.New("Commit with a wrong digest succeeded")
	}
	return err
}

// runWorkload runs the concurrent crash workload against s.
func runWorkload(t *testing.T, s Store, l *ledger, seed uint64) {
	t.Helper()
	const workers, opsPerWorker = 4, 12
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := range workers {
		wg.Go(func() {
			errs[w] = worker(s, l, w, opsPerWorker, rand.New(rand.NewPCG(seed, uint64(w))))
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

// checkRecovered verifies a store reopened after a crash against the ledger:
// every acknowledged commit and delete is durable, every visible blob is
// complete and matches its digest, and every acknowledged Suspend can be
// resumed and finished.
func checkRecovered(t *testing.T, s Store, l *ledger) {
	t.Helper()
	for d := range l.committed {
		// A delete that was not acknowledged may still have become
		// durable, through another commit's sync of the same directory.
		if l.deleting[d] {
			continue
		}
		r, err := s.Open(ctx, d)
		if err != nil {
			t.Errorf("acknowledged blob %s lost: %v", d, err)
			continue
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil || !bytes.Equal(got, l.attempted[d]) {
			t.Errorf("acknowledged blob %s reads back %d wrong bytes: %v", d, len(got), err)
		}
	}
	for d := range l.deleted {
		if _, err := s.Stat(ctx, d); !errors.Is(err, ErrNotFound) {
			t.Errorf("acknowledged delete of %s undone: %v", d, err)
		}
	}
	err := s.Walk(ctx, func(info Info) error {
		if _, ok := l.attempted[info.Digest]; !ok {
			t.Errorf("visible blob %s was never committed under its digest (mismatched: %v)", info.Digest, l.never[info.Digest])
		}
		r, err := s.Open(ctx, info.Digest)
		if err != nil {
			return err
		}
		defer r.Close()
		got, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if FromBytes(got) != info.Digest || int64(len(got)) != info.Size {
			t.Errorf("visible blob %s is partial or corrupt: %d bytes, Info.Size %d", info.Digest, len(got), info.Size)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk after crash: %v", err)
	}
	for id, c := range l.chunked {
		if c.done {
			continue
		}
		u, err := s.ResumeUpload(ctx, id)
		if err != nil {
			// Unacknowledged uploads may be gone; so may one whose
			// commit had started, which may have renamed its data.
			if c.suspended && !c.finishing {
				t.Errorf("acknowledged suspend of %s (size %d) lost: %v", id, c.acked, err)
			} else if !errors.Is(err, ErrUploadUnknown) {
				t.Errorf("ResumeUpload(%s) = %v, want success or ErrUploadUnknown", id, err)
			}
			continue
		}
		if !slices.Contains(c.sizes, u.Size()) || u.Size() < c.acked {
			t.Errorf("resumed %s at size %d; suspends started at %v, last acknowledged at %d", id, u.Size(), c.sizes, c.acked)
			u.Cancel()
			continue
		}
		if _, err := u.Write(c.content[u.Size():]); err != nil {
			t.Fatal(err)
		}
		// The hash state must describe exactly the staged bytes.
		if _, err := u.Commit(ctx, FromBytes(c.content)); err != nil {
			t.Errorf("finishing resumed upload %s: %v", id, err)
		}
	}
	if _, err := s.PurgeUploads(ctx, farFuture); err != nil {
		t.Fatal(err)
	}
}

// checkUploadsEmpty fails if any upload files are left.
func checkUploadsEmpty(t *testing.T, fs fsys.FS, dir string) {
	t.Helper()
	entries, err := fs.ReadDir(filepath.Join(dir, "uploads"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("upload file left after purge: %s", e.Name())
	}
}

// TestCrash runs a concurrent workload against the strict in-memory
// filesystem, crashes it at a random operation, and checks the state that
// survives. Half the crashes drop all unsynced data; the other half keep a
// random subset of unsynced pages, as a real disk may.
func TestCrash(t *testing.T) {
	iterations := 300
	if testing.Short() {
		iterations = 40
	}
	// Calibrate how many mutating operations a whole workload performs.
	mem := fsys.NewMem()
	s, err := NewFS("/data", Options{FS: mem})
	if err != nil {
		t.Fatal(err)
	}
	base := mem.Ops()
	runWorkload(t, s, newLedger(), 0)
	total := mem.Ops() - base

	for i := range iterations {
		seed := uint64(i) + 1
		rng := rand.New(rand.NewPCG(seed, 99))
		crashAt := rng.Int64N(total + total/10)
		t.Run(fmt.Sprintf("seed=%d/crash=%d", seed, crashAt), func(t *testing.T) {
			mem := fsys.NewMem()
			s, err := NewFS("/data", Options{FS: mem})
			if err != nil {
				t.Fatal(err)
			}
			l := newLedger()
			mem.CrashAfter(crashAt)
			runWorkload(t, s, l, seed)
			var torn *rand.Rand
			if i%2 == 1 {
				torn = rng
			}
			after := mem.Restart(torn)
			s, err = NewFS("/data", Options{FS: after})
			if err != nil {
				t.Fatalf("reopening after crash: %v", err)
			}
			checkRecovered(t, s, l)
			checkUploadsEmpty(t, after, "/data")
			if info := put(t, s, []byte("after the crash")); info.Size == 0 {
				t.Fatal("store unusable after crash")
			}
		})
		if t.Failed() {
			break
		}
	}
}

// TestCrashDuringSuspendKeepsPreviousState crashes at each operation of a
// second Suspend and checks the upload resumes at one of the two suspended
// sizes, never in between and never with mismatched data.
func TestCrashDuringSuspendKeepsPreviousState(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), 2000)
	for crashAt := int64(0); ; crashAt++ {
		mem := fsys.NewMem()
		s, err := NewFS("/data", Options{FS: mem})
		if err != nil {
			t.Fatal(err)
		}
		u, _ := s.NewUpload(ctx)
		u.Write(data[:5000])
		if err := u.Suspend(); err != nil {
			t.Fatal(err)
		}
		u, _ = s.ResumeUpload(ctx, u.ID())
		mem.CrashAfter(crashAt)
		u.Write(data[5000:12000])
		suspendErr := u.Suspend()
		after := mem.Restart(nil)
		s, _ = NewFS("/data", Options{FS: after})
		r, err := s.ResumeUpload(ctx, u.ID())
		if err != nil {
			t.Fatalf("crash at %d: acknowledged first suspend lost: %v", crashAt, err)
		}
		if size := r.Size(); size != 5000 && size != 12000 || suspendErr == nil && size != 12000 {
			t.Fatalf("crash at %d: resumed at %d (second suspend error %v)", crashAt, size, suspendErr)
		}
		r.Write(data[r.Size():])
		if _, err := r.Commit(ctx, FromBytes(data)); err != nil {
			t.Fatalf("crash at %d: %v", crashAt, err)
		}
		if suspendErr == nil {
			break // crashAt ran past the end of the second Suspend
		}
	}
}

// farFuture is a purge cutoff that removes every suspended upload.
var farFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// TestCrashHelpersOnOS sanity-checks the crash-test helpers against the OS
// filesystem with no crash at all.
func TestCrashHelpersOnOS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := NewFS(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	l := newLedger()
	runWorkload(t, s, l, 7)
	s, err = NewFS(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	checkRecovered(t, s, l)
	checkUploadsEmpty(t, fsys.OS, dir)
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
}
