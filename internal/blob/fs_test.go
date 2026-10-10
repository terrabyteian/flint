package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

// env is a store under test plus the filesystem and directory behind it.
type env struct {
	store Store
	fs    fsys.FS
	dir   string
}

// backends returns a fresh store on the real filesystem and one on the
// strict in-memory filesystem.
func backends(t *testing.T) map[string]env {
	t.Helper()
	osDir := filepath.Join(t.TempDir(), "data")
	return map[string]env{
		"os":  newEnv(t, fsys.OS, osDir, nil),
		"mem": newEnv(t, fsys.NewMem(), "/data", nil),
	}
}

func newEnv(t *testing.T, fs fsys.FS, dir string, now func() time.Time) env {
	t.Helper()
	s, err := NewFS(dir, Options{FS: fs, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return env{s, fs, dir}
}

// forEach runs f against each backend.
func forEach(t *testing.T, f func(t *testing.T, e env)) {
	for name, e := range backends(t) {
		t.Run(name, func(t *testing.T) { f(t, e) })
	}
}

var ctx = context.Background()

// put uploads data in one piece and commits it under its digest.
func put(t *testing.T, s Store, data []byte) Info {
	t.Helper()
	u, err := s.NewUpload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Write(data); err != nil {
		t.Fatal(err)
	}
	info, err := u.Commit(ctx, FromBytes(data))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// get reads a committed blob.
func get(t *testing.T, s Store, d Digest) []byte {
	t.Helper()
	r, err := s.Open(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// uploadFiles lists the uploads directory.
func uploadFiles(t *testing.T, e env) []string {
	t.Helper()
	entries, err := e.fs.ReadDir(filepath.Join(e.dir, "uploads"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ent := range entries {
		names = append(names, ent.Name())
	}
	return names
}

func walkAll(t *testing.T, s Store) []Info {
	t.Helper()
	var out []Info
	if err := s.Walk(ctx, func(i Info) error { out = append(out, i); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUploadCommitOpen(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		data := []byte("hello, flint")
		info := put(t, e.store, data)
		want := FromBytes(data)
		if info.Digest != want || info.Size != int64(len(data)) || info.ModTime.IsZero() {
			t.Fatalf("Commit = %+v, want digest %s size %d", info, want, len(data))
		}
		if got := get(t, e.store, want); !bytes.Equal(got, data) {
			t.Fatalf("Open read %q, want %q", got, data)
		}
		st, err := e.store.Stat(ctx, want)
		if err != nil || st.Digest != want || st.Size != info.Size || !st.ModTime.Equal(info.ModTime) {
			t.Fatalf("Stat = %+v, %v; want %+v", st, err, info)
		}
		path := filepath.Join(e.dir, "blobs", "sha256", want.Hex()[:2], want.Hex())
		if _, err := e.fs.Stat(path); err != nil {
			t.Fatalf("blob not at its fan-out path %s: %v", path, err)
		}
		if names := uploadFiles(t, e); len(names) != 0 {
			t.Fatalf("uploads left after commit: %v", names)
		}
	})
}

func TestOpenReturnsOSFile(t *testing.T) {
	s, err := NewFS(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	info := put(t, s, []byte("sendfile me"))
	r, err := s.Open(ctx, info.Digest)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, ok := r.(*os.File); !ok {
		t.Fatalf("Open returned %T, want *os.File so net/http can use sendfile", r)
	}
}

func TestReaderSeeks(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		info := put(t, e.store, []byte("0123456789"))
		r, err := e.store.Open(ctx, info.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := r.Seek(4, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 3)
		if _, err := io.ReadFull(r, b); err != nil || string(b) != "456" {
			t.Fatalf("read after seek = %q, %v", b, err)
		}
	})
}

func TestEmptyBlob(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		u, err := e.store.NewUpload(ctx)
		if err != nil {
			t.Fatal(err)
		}
		info, err := u.Commit(ctx, FromBytes(nil))
		if err != nil || info.Size != 0 {
			t.Fatalf("Commit of empty upload = %+v, %v", info, err)
		}
		if got := get(t, e.store, info.Digest); len(got) != 0 {
			t.Fatalf("empty blob read %d bytes", len(got))
		}
	})
}

func TestCommitZeroDigestAcceptsAny(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		u, _ := e.store.NewUpload(ctx)
		io.WriteString(u, "anything")
		info, err := u.Commit(ctx, Digest{})
		if err != nil || info.Digest != FromBytes([]byte("anything")) {
			t.Fatalf("Commit(zero) = %+v, %v", info, err)
		}
	})
}

func TestDigestMismatch(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		u, _ := e.store.NewUpload(ctx)
		io.WriteString(u, "actual content")
		claimed := FromBytes([]byte("claimed content"))
		if _, err := u.Commit(ctx, claimed); !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("Commit with wrong digest = %v, want ErrDigestMismatch", err)
		}
		for _, d := range []Digest{claimed, FromBytes([]byte("actual content"))} {
			if _, err := e.store.Stat(ctx, d); !errors.Is(err, ErrNotFound) {
				t.Errorf("Stat(%s) after mismatch = %v, want ErrNotFound", d, err)
			}
		}
		if names := uploadFiles(t, e); len(names) != 0 {
			t.Fatalf("mismatched upload not discarded: %v", names)
		}
		if _, err := u.Write([]byte("x")); !errors.Is(err, ErrUploadClosed) {
			t.Fatalf("Write after failed Commit = %v, want ErrUploadClosed", err)
		}
		if _, err := e.store.ResumeUpload(ctx, u.ID()); !errors.Is(err, ErrUploadUnknown) {
			t.Fatalf("ResumeUpload after mismatch = %v, want ErrUploadUnknown", err)
		}
	})
}

func TestDuplicateUpload(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		data := []byte("same bytes twice")
		first := put(t, e.store, data)
		second := put(t, e.store, data)
		if second != first {
			t.Fatalf("second commit = %+v, want the existing blob %+v", second, first)
		}
		if blobs := walkAll(t, e.store); len(blobs) != 1 {
			t.Fatalf("Walk found %d blobs, want 1", len(blobs))
		}
		if names := uploadFiles(t, e); len(names) != 0 {
			t.Fatalf("duplicate upload's staged data not dropped: %v", names)
		}
	})
}

func TestDamagedExistingBlobReplaced(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		data := []byte("the real content")
		d := FromBytes(data)
		// Plant a truncated copy where the blob belongs.
		path := filepath.Join(e.dir, "blobs", "sha256", d.Hex()[:2], d.Hex())
		f, err := e.fs.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.Write(data[:4])
		f.Close()
		if info := put(t, e.store, data); info.Size != int64(len(data)) {
			t.Fatalf("Commit over a damaged copy = %+v", info)
		}
		if got := get(t, e.store, d); !bytes.Equal(got, data) {
			t.Fatalf("blob reads %q after replacing the damaged copy", got)
		}
	})
}

func TestConcurrentSameContent(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		data := bytes.Repeat([]byte("concurrent "), 10000)
		want := FromBytes(data)
		const n = 16
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for range n {
			wg.Go(func() {
				u, err := e.store.NewUpload(ctx)
				if err != nil {
					errs <- err
					return
				}
				for off := 0; off < len(data); off += 4096 {
					if _, err := u.Write(data[off:min(off+4096, len(data))]); err != nil {
						errs <- err
						return
					}
				}
				info, err := u.Commit(ctx, want)
				if err == nil && (info.Digest != want || info.Size != int64(len(data))) {
					err = fmt.Errorf("Commit = %+v", info)
				}
				if err != nil {
					errs <- err
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if got := get(t, e.store, want); !bytes.Equal(got, data) {
			t.Fatal("blob content wrong after concurrent commits")
		}
		if blobs := walkAll(t, e.store); len(blobs) != 1 {
			t.Fatalf("Walk found %d blobs, want 1", len(blobs))
		}
		if names := uploadFiles(t, e); len(names) != 0 {
			t.Fatalf("uploads left: %v", names)
		}
	})
}

func TestChunkedUpload(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		data := bytes.Repeat([]byte("0123456789abcdef"), 5000)
		chunks := [][]byte{data[:1], data[1:30000], nil, data[30000:70001], data[70001:]}
		u, err := e.store.NewUpload(ctx)
		if err != nil {
			t.Fatal(err)
		}
		id := u.ID()
		var size int64
		for i, c := range chunks {
			if i > 0 {
				if u, err = e.store.ResumeUpload(ctx, id); err != nil {
					t.Fatalf("ResumeUpload before chunk %d: %v", i, err)
				}
				if u.ID() != id || u.Size() != size {
					t.Fatalf("resumed upload %s has size %d, want %s size %d", u.ID(), u.Size(), id, size)
				}
			}
			if _, err := u.Write(c); err != nil {
				t.Fatal(err)
			}
			size += int64(len(c))
			if u.Size() != size {
				t.Fatalf("Size = %d, want %d", u.Size(), size)
			}
			if i < len(chunks)-1 {
				if err := u.Suspend(); err != nil {
					t.Fatal(err)
				}
				if _, err := u.Write(c); !errors.Is(err, ErrUploadClosed) {
					t.Fatalf("Write after Suspend = %v, want ErrUploadClosed", err)
				}
			}
		}
		info, err := u.Commit(ctx, FromBytes(data))
		if err != nil {
			t.Fatal(err)
		}
		if got := get(t, e.store, info.Digest); !bytes.Equal(got, data) {
			t.Fatal("chunked upload committed the wrong bytes")
		}
		if names := uploadFiles(t, e); len(names) != 0 {
			t.Fatalf("uploads left after commit: %v", names)
		}
		if _, err := e.store.ResumeUpload(ctx, id); !errors.Is(err, ErrUploadUnknown) {
			t.Fatalf("ResumeUpload after commit = %v, want ErrUploadUnknown", err)
		}
	})
}

func TestResumeAcrossReopen(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		u, _ := e.store.NewUpload(ctx)
		io.WriteString(u, "first half, ")
		if err := u.Suspend(); err != nil {
			t.Fatal(err)
		}
		reopened := newEnv(t, e.fs, e.dir, nil)
		u, err := reopened.store.ResumeUpload(ctx, u.ID())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(u, "second half")
		want := FromBytes([]byte("first half, second half"))
		if _, err := u.Commit(ctx, want); err != nil {
			t.Fatal(err)
		}
	})
}

func TestResumeDropsUnacknowledgedBytes(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		u, _ := e.store.NewUpload(ctx)
		io.WriteString(u, "kept")
		u.Suspend()
		// Bytes written to the staged file after Suspend, as by a request
		// that died before suspending again, are not part of the upload.
		f, err := e.fs.OpenFile(filepath.Join(e.dir, "uploads", u.ID()), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(" and lost"))
		f.Close()
		r, err := e.store.ResumeUpload(ctx, u.ID())
		if err != nil {
			t.Fatal(err)
		}
		if r.Size() != 4 {
			t.Fatalf("resumed Size = %d, want 4", r.Size())
		}
		io.WriteString(r, "!")
		info, err := r.Commit(ctx, FromBytes([]byte("kept!")))
		if err != nil {
			t.Fatal(err)
		}
		if got := get(t, e.store, info.Digest); string(got) != "kept!" || info.Size != 5 {
			t.Fatalf("committed %q (size %d), want \"kept!\"", got, info.Size)
		}
	})
}

func TestResumeErrors(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		for _, id := range []string{"", "nope", strings.Repeat("0", 32), "../../blobs/sha256/00/xx", strings.Repeat("A", 32)} {
			if _, err := e.store.ResumeUpload(ctx, id); !errors.Is(err, ErrUploadUnknown) {
				t.Errorf("ResumeUpload(%q) = %v, want ErrUploadUnknown", id, err)
			}
		}

		// A never-suspended upload cannot be resumed: it is open.
		u, _ := e.store.NewUpload(ctx)
		if _, err := e.store.ResumeUpload(ctx, u.ID()); !errors.Is(err, ErrUploadBusy) {
			t.Fatalf("ResumeUpload of an open upload = %v, want ErrUploadBusy", err)
		}
		u.Suspend()
		r, err := e.store.ResumeUpload(ctx, u.ID())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.store.ResumeUpload(ctx, u.ID()); !errors.Is(err, ErrUploadBusy) {
			t.Fatalf("second concurrent ResumeUpload = %v, want ErrUploadBusy", err)
		}
		r.Cancel()

		canceled, err := e.store.ResumeUpload(ctx, u.ID())
		if !errors.Is(err, ErrUploadUnknown) {
			t.Fatalf("ResumeUpload after Cancel = %v, %v; want ErrUploadUnknown", canceled, err)
		}
	})
}

func TestResumeDamagedState(t *testing.T) {
	cases := map[string]func(state []byte) []byte{
		"flipped bit": func(b []byte) []byte { b[len(b)/2] ^= 1; return b },
		"truncated":   func(b []byte) []byte { return b[:len(b)-3] },
		"empty":       func(b []byte) []byte { return nil },
		"bad version": func(b []byte) []byte { b[4] = 99; return b },
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, fsys.NewMem(), "/data", nil)
			u, _ := e.store.NewUpload(ctx)
			io.WriteString(u, "staged")
			u.Suspend()
			path := filepath.Join(e.dir, "uploads", u.ID()+".state")
			f, _ := e.fs.Open(path)
			state, _ := io.ReadAll(f)
			f.Close()
			f, _ = e.fs.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
			f.Write(damage(state))
			f.Close()
			if _, err := e.store.ResumeUpload(ctx, u.ID()); !errors.Is(err, ErrUploadUnknown) {
				t.Fatalf("ResumeUpload with damaged state = %v, want ErrUploadUnknown", err)
			}
			if names := uploadFiles(t, e); len(names) != 0 {
				t.Fatalf("damaged upload not removed: %v", names)
			}
		})
	}
}

func TestResumeMissingData(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		u, _ := e.store.NewUpload(ctx)
		io.WriteString(u, "staged")
		u.Suspend()
		data := filepath.Join(e.dir, "uploads", u.ID())
		// Shorter than the state says: the staged bytes were lost.
		f, _ := e.fs.OpenFile(data, os.O_WRONLY, 0)
		f.Truncate(2)
		f.Close()
		if _, err := e.store.ResumeUpload(ctx, u.ID()); !errors.Is(err, ErrUploadUnknown) {
			t.Fatalf("ResumeUpload with short data = %v, want ErrUploadUnknown", err)
		}

		u, _ = e.store.NewUpload(ctx)
		u.Suspend()
		e.fs.Remove(filepath.Join(e.dir, "uploads", u.ID()))
		if _, err := e.store.ResumeUpload(ctx, u.ID()); !errors.Is(err, ErrUploadUnknown) {
			t.Fatalf("ResumeUpload with missing data = %v, want ErrUploadUnknown", err)
		}
		if names := uploadFiles(t, e); len(names) != 0 {
			t.Fatalf("broken uploads not removed: %v", names)
		}
	})
}

func TestCancel(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		u, _ := e.store.NewUpload(ctx)
		io.WriteString(u, "never mind")
		if err := u.Cancel(); err != nil {
			t.Fatal(err)
		}
		if names := uploadFiles(t, e); len(names) != 0 {
			t.Fatalf("cancelled upload left files: %v", names)
		}
		if err := u.Cancel(); !errors.Is(err, ErrUploadClosed) {
			t.Fatalf("second Cancel = %v, want ErrUploadClosed", err)
		}
		if _, err := u.Commit(ctx, Digest{}); !errors.Is(err, ErrUploadClosed) {
			t.Fatalf("Commit after Cancel = %v, want ErrUploadClosed", err)
		}
		if err := u.Suspend(); !errors.Is(err, ErrUploadClosed) {
			t.Fatalf("Suspend after Cancel = %v, want ErrUploadClosed", err)
		}
		if blobs := walkAll(t, e.store); len(blobs) != 0 {
			t.Fatalf("cancelled upload produced blobs: %v", blobs)
		}
	})
}

func TestNotFoundAndDelete(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		missing := FromBytes([]byte("missing"))
		for _, d := range []Digest{missing, {}} {
			if _, err := e.store.Open(ctx, d); !errors.Is(err, ErrNotFound) {
				t.Errorf("Open(%q) = %v, want ErrNotFound", d, err)
			}
			if _, err := e.store.Stat(ctx, d); !errors.Is(err, ErrNotFound) {
				t.Errorf("Stat(%q) = %v, want ErrNotFound", d, err)
			}
			if err := e.store.Delete(ctx, d); !errors.Is(err, ErrNotFound) {
				t.Errorf("Delete(%q) = %v, want ErrNotFound", d, err)
			}
		}
		info := put(t, e.store, []byte("doomed"))
		if err := e.store.Delete(ctx, info.Digest); err != nil {
			t.Fatal(err)
		}
		if _, err := e.store.Open(ctx, info.Digest); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Open after Delete = %v, want ErrNotFound", err)
		}
		// The same content can be uploaded again.
		put(t, e.store, []byte("doomed"))
	})
}

func TestWalk(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		want := map[Digest]int64{}
		for i := range 50 {
			data := fmt.Appendf(nil, "blob %d", i)
			want[put(t, e.store, data).Digest] = int64(len(data))
		}
		// Strays in the blob tree are not blobs and are never reported.
		for _, name := range []string{"00/not-a-digest", "ab/" + strings.Repeat("cd", 32), "stray"} {
			f, err := e.fs.OpenFile(filepath.Join(e.dir, "blobs", "sha256", name), os.O_WRONLY|os.O_CREATE, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
		}
		var prev string
		for _, info := range walkAll(t, e.store) {
			size, ok := want[info.Digest]
			if !ok || size != info.Size || info.ModTime.IsZero() {
				t.Errorf("Walk reported %+v", info)
			}
			if info.Digest.Hex() <= prev {
				t.Errorf("Walk out of order: %s after %s", info.Digest.Hex(), prev)
			}
			prev = info.Digest.Hex()
			delete(want, info.Digest)
		}
		if len(want) != 0 {
			t.Fatalf("Walk missed %d blobs", len(want))
		}

		stop := errors.New("stop")
		calls := 0
		err := e.store.Walk(ctx, func(Info) error { calls++; return stop })
		if !errors.Is(err, stop) || calls != 1 {
			t.Fatalf("Walk with failing fn = %v after %d calls, want stop after 1", err, calls)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := e.store.Walk(cancelled, func(Info) error { return nil }); !errors.Is(err, context.Canceled) {
			t.Fatalf("Walk with cancelled context = %v", err)
		}
	})
}

func TestModTimeIsCommitTime(t *testing.T) {
	mem := fsys.NewMem()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	mem.SetClock(now)
	e := newEnv(t, mem, "/data", now)
	u, _ := e.store.NewUpload(ctx)
	io.WriteString(u, "slow chunked upload")
	u.Suspend()
	clock = clock.Add(48 * time.Hour)
	u, _ = e.store.ResumeUpload(ctx, u.ID())
	info, err := u.Commit(ctx, Digest{})
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime.Equal(clock) {
		t.Fatalf("ModTime = %v, want the commit time %v", info.ModTime, clock)
	}
	if st, _ := e.store.Stat(ctx, info.Digest); !st.ModTime.Equal(clock) {
		t.Fatalf("Stat ModTime = %v, want %v", st.ModTime, clock)
	}
}

func TestPurgeUploads(t *testing.T) {
	mem := fsys.NewMem()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	mem.SetClock(now)
	e := newEnv(t, mem, "/data", now)

	old, _ := e.store.NewUpload(ctx)
	io.WriteString(old, "abandoned long ago")
	old.Suspend()
	clock = clock.Add(time.Hour)
	recent, _ := e.store.NewUpload(ctx)
	io.WriteString(recent, "still wanted")
	recent.Suspend()
	open, _ := e.store.NewUpload(ctx)
	io.WriteString(open, "in progress")

	// A crash while writing a state file leaves a temporary copy behind.
	f, _ := mem.OpenFile(filepath.Join(e.dir, "uploads", recent.ID()+".state.tmp"), os.O_WRONLY|os.O_CREATE, 0o644)
	f.Close()
	// Files that are not uploads are not touched.
	f, _ = mem.OpenFile(filepath.Join(e.dir, "uploads", "README"), os.O_WRONLY|os.O_CREATE, 0o644)
	f.Close()

	n, err := e.store.PurgeUploads(ctx, clock.Add(-30*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("PurgeUploads = %d, %v; want 1", n, err)
	}
	if _, err := e.store.ResumeUpload(ctx, old.ID()); !errors.Is(err, ErrUploadUnknown) {
		t.Fatalf("old upload survived purge: %v", err)
	}
	r, err := e.store.ResumeUpload(ctx, recent.ID())
	if err != nil {
		t.Fatalf("recent upload purged: %v", err)
	}
	r.Suspend()
	if _, err := io.WriteString(open, " and done"); err != nil {
		t.Fatalf("open upload broken by purge: %v", err)
	}
	if _, err := open.Commit(ctx, FromBytes([]byte("in progress and done"))); err != nil {
		t.Fatal(err)
	}
	if got := uploadFiles(t, e); len(got) != 3 {
		t.Fatalf("uploads after purge = %v, want the recent upload's data and state and README", got)
	}

	// An upload a previous process never suspended is useless, whatever its age.
	orphan, _ := e.store.NewUpload(ctx)
	io.WriteString(orphan, "the process died")
	restarted := newEnv(t, mem, e.dir, now)
	if n, err := restarted.store.PurgeUploads(ctx, clock.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("PurgeUploads after restart = %d, %v; want the orphan removed", n, err)
	}
	if n, err := restarted.store.PurgeUploads(ctx, clock.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("PurgeUploads(later) = %d, %v; want the recent upload removed", n, err)
	}
	if got := uploadFiles(t, e); len(got) != 1 || got[0] != "README" {
		t.Fatalf("uploads after full purge = %v, want only README", got)
	}
}

func TestReadFromUsesUpload(t *testing.T) {
	forEach(t, func(t *testing.T, e env) {
		data := bytes.Repeat([]byte{7}, 3*copyBufSize+5)
		u, _ := e.store.NewUpload(ctx)
		n, err := io.Copy(u, bytes.NewReader(data))
		if err != nil || n != int64(len(data)) || u.Size() != n {
			t.Fatalf("io.Copy = %d, %v; Size %d", n, err, u.Size())
		}
		if _, err := u.Commit(ctx, FromBytes(data)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestReadFromSourceError(t *testing.T) {
	// A truncated HTTP body reports io.ErrUnexpectedEOF, which must not
	// pass for the end of the stream.
	for _, boom := range []error{errors.New("client went away"), io.ErrUnexpectedEOF} {
		t.Run(boom.Error(), func(t *testing.T) {
			e := newEnv(t, fsys.NewMem(), "/data", nil)
			u, _ := e.store.NewUpload(ctx)
			_, err := io.Copy(u, io.MultiReader(strings.NewReader("partial"), errReader{boom}))
			if !errors.Is(err, boom) {
				t.Fatalf("io.Copy = %v, want the source's error", err)
			}
			if u.Size() != int64(len("partial")) {
				t.Fatalf("Size = %d after a failed copy, want the bytes that arrived", u.Size())
			}
		})
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestNewFSIdempotentAndDurable(t *testing.T) {
	mem := fsys.NewMem()
	mem.MkdirAll("/srv", 0o755)
	mem.SyncDir("/")
	e := newEnv(t, mem, "/srv/data", nil)
	put(t, e.store, []byte("survivor"))
	if _, err := NewFS("/srv/data", Options{FS: mem}); err != nil {
		t.Fatalf("reopening: %v", err)
	}
	// A power loss right after NewFS must not lose the layout itself.
	after := mem.Restart(nil)
	for _, dir := range []string{"/srv/data/uploads", "/srv/data/blobs/sha256/00", "/srv/data/blobs/sha256/ff"} {
		if fi, err := after.Stat(dir); err != nil || !fi.IsDir() {
			t.Errorf("%s after crash: %v", dir, err)
		}
	}
	s, err := NewFS("/srv/data", Options{FS: after})
	if err != nil {
		t.Fatal(err)
	}
	if got := get(t, s, FromBytes([]byte("survivor"))); string(got) != "survivor" {
		t.Fatalf("committed blob after crash = %q", got)
	}
}

func TestNewFSMakesExistingLayoutDurable(t *testing.T) {
	data := []byte("survivor")
	cases := map[string]struct {
		dir     string
		prepare func(mem *fsys.Mem)
	}{
		"missing ancestors": {"/a/b/data", func(*fsys.Mem) {}},
		// A process killed during NewFS left the layout created but unsynced.
		"unsynced layout": {"/srv/data", func(mem *fsys.Mem) {
			mem.MkdirAll("/srv", 0o755)
			mem.SyncDir("/")
			mem.MkdirAll("/srv/data/blobs/sha256/"+FromBytes(data).Hex()[:2], 0o755)
			mem.MkdirAll("/srv/data/uploads", 0o755)
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			mem := fsys.NewMem()
			c.prepare(mem)
			e := newEnv(t, mem, c.dir, nil)
			put(t, e.store, data)
			after := mem.Restart(nil)
			s, err := NewFS(c.dir, Options{FS: after})
			if err != nil {
				t.Fatal(err)
			}
			if got := get(t, s, FromBytes(data)); !bytes.Equal(got, data) {
				t.Fatalf("committed blob after crash = %q", got)
			}
		})
	}
}

func TestNewFSErrors(t *testing.T) {
	mem := fsys.NewMem()
	f, _ := mem.OpenFile("/file", os.O_WRONLY|os.O_CREATE, 0o644)
	f.Close()
	if _, err := NewFS("/file", Options{FS: mem}); err == nil {
		t.Fatal("NewFS on a file succeeded")
	}
	mem.MkdirAll("/d/blobs", 0o755)
	f, _ = mem.OpenFile("/d/blobs/sha256", os.O_WRONLY|os.O_CREATE, 0o644)
	f.Close()
	if _, err := NewFS("/d", Options{FS: mem}); err == nil {
		t.Fatal("NewFS with a file in place of blobs/sha256 succeeded")
	}
}

func TestCancelledContext(t *testing.T) {
	e := newEnv(t, fsys.NewMem(), "/data", nil)
	info := put(t, e.store, []byte("x"))
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := e.store.NewUpload(cancelled); !errors.Is(err, context.Canceled) {
		t.Errorf("NewUpload = %v", err)
	}
	if _, err := e.store.ResumeUpload(cancelled, strings.Repeat("0", 32)); !errors.Is(err, context.Canceled) {
		t.Errorf("ResumeUpload = %v", err)
	}
	if _, err := e.store.Open(cancelled, info.Digest); !errors.Is(err, context.Canceled) {
		t.Errorf("Open = %v", err)
	}
	if _, err := e.store.Stat(cancelled, info.Digest); !errors.Is(err, context.Canceled) {
		t.Errorf("Stat = %v", err)
	}
	if err := e.store.Delete(cancelled, info.Digest); !errors.Is(err, context.Canceled) {
		t.Errorf("Delete = %v", err)
	}
	if _, err := e.store.PurgeUploads(cancelled, time.Now()); err != nil {
		t.Errorf("PurgeUploads with nothing to purge = %v", err)
	}
	u, _ := e.store.NewUpload(ctx)
	if _, err := u.Commit(cancelled, Digest{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Commit = %v", err)
	}
	if _, err := e.store.Stat(ctx, FromBytes(nil)); !errors.Is(err, ErrNotFound) {
		t.Errorf("Commit under a cancelled context made a blob visible: %v", err)
	}
}

// TestFaults checks that a failing filesystem operation anywhere in a write
// fails the operation, discards the upload, and never makes a blob visible.
func TestFaults(t *testing.T) {
	data := bytes.Repeat([]byte("fault "), 1000)
	d := FromBytes(data)
	boom := errors.New("injected fault")
	ops := []fsys.Op{fsys.OpWrite, fsys.OpSync, fsys.OpChtimes, fsys.OpStat, fsys.OpClose, fsys.OpRename, fsys.OpSyncDir, fsys.OpOpen}
	for _, op := range ops {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/chunked=%v", op, chunked), func(t *testing.T) {
				mem := fsys.NewMem()
				e := newEnv(t, mem, "/data", nil)
				var armed bool
				mem.SetFault(func(o fsys.Op, name string) error {
					if armed && o == op && !strings.HasSuffix(name, "/uploads") {
						return boom
					}
					return nil
				})
				var err error
				func() {
					armed = !chunked
					u, nerr := e.store.NewUpload(ctx)
					if err = nerr; err != nil {
						return
					}
					if _, err = u.Write(data[:100]); err != nil {
						u.Cancel()
						return
					}
					if chunked {
						armed = true
						if err = u.Suspend(); err != nil {
							return
						}
						if u, err = e.store.ResumeUpload(ctx, u.ID()); err != nil {
							return
						}
					}
					if _, err = u.Write(data[100:]); err != nil {
						u.Cancel()
						return
					}
					_, err = u.Commit(ctx, d)
				}()
				if !errors.Is(err, boom) {
					t.Fatalf("upload with failing %s = %v, want the injected fault", op, err)
				}
				mem.SetFault(nil)
				// Only a failed sync of the fan-out directory, after the
				// rename, can leave the blob visible; it is complete
				// either way (see TestSyncDirFaultAfterRename).
				for _, info := range walkAll(t, e.store) {
					if op != fsys.OpSyncDir {
						t.Fatalf("a failed upload left a visible blob: %v", info)
					}
					if got := get(t, e.store, info.Digest); FromBytes(got) != info.Digest {
						t.Fatalf("visible blob %s does not match its digest", info.Digest)
					}
				}
				// The store keeps working once the fault clears.
				if info := put(t, e.store, data); info.Digest != d {
					t.Fatalf("upload after fault = %+v", info)
				}
			})
		}
	}
}

func TestSyncDirFaultAfterRename(t *testing.T) {
	// If the fan-out directory sync fails after the rename, the blob is
	// visible but Commit reports failure. The visible blob is still
	// complete, and a retried commit syncs it and succeeds.
	mem := fsys.NewMem()
	e := newEnv(t, mem, "/data", nil)
	data := []byte("visible but not yet durable")
	d := FromBytes(data)
	mem.SetFault(func(o fsys.Op, name string) error {
		if o == fsys.OpSyncDir && strings.HasSuffix(name, d.Hex()[:2]) {
			return fs.ErrPermission
		}
		return nil
	})
	u, _ := e.store.NewUpload(ctx)
	u.Write(data)
	if _, err := u.Commit(ctx, d); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Commit = %v, want the sync error", err)
	}
	if got := get(t, e.store, d); !bytes.Equal(got, data) {
		t.Fatalf("visible blob is %q", got)
	}
	mem.SetFault(nil)
	put(t, e.store, data)
	after := mem.Restart(nil)
	s, _ := NewFS("/data", Options{FS: after})
	if got := get(t, s, d); !bytes.Equal(got, data) {
		t.Fatalf("blob after crash = %q", got)
	}
}
