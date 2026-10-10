package fsys

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// implementations returns each FS under test with a directory to work in.
func implementations(t *testing.T) map[string]struct {
	fs  FS
	dir string
} {
	return map[string]struct {
		fs  FS
		dir string
	}{
		"os":  {OS, t.TempDir()},
		"mem": {NewMem(), "/data"},
	}
}

// TestSemantics checks that OS and Mem behave alike for the operations the
// storage code relies on.
func TestSemantics(t *testing.T) {
	for name, impl := range implementations(t) {
		t.Run(name, func(t *testing.T) {
			fsys, dir := impl.fs, impl.dir
			join := func(p ...string) string { return filepath.Join(append([]string{dir}, p...)...) }
			if err := fsys.MkdirAll(join("a", "b"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := fsys.MkdirAll(join("a", "b"), 0o755); err != nil {
				t.Fatalf("MkdirAll on existing dir: %v", err)
			}
			if err := fsys.Mkdir(join("a"), 0o755); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("Mkdir existing = %v, want ErrExist", err)
			}

			f, err := fsys.OpenFile(join("a", "f"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fsys.OpenFile(join("a", "f"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("O_EXCL on existing file = %v, want ErrExist", err)
			}
			if _, err := f.Write([]byte("hello world")); err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(5); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("!")); err != nil {
				t.Fatal(err)
			}
			if err := f.Sync(); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 10)
			n, err := f.ReadAt(buf, 0)
			if n != 6 || err != io.EOF || string(buf[:n]) != "hello!" {
				t.Fatalf("ReadAt = %d, %v, %q; want 6, EOF, hello!", n, err, buf[:n])
			}
			if fi, err := f.Stat(); err != nil || fi.Size() != 6 || fi.Name() != "f" {
				t.Fatalf("Stat = %v, %v", fi, err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			r, err := fsys.Open(join("a", "f"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil || string(got) != "hello!" {
				t.Fatalf("ReadAll = %q, %v", got, err)
			}
			if _, err := r.Write([]byte("x")); err == nil {
				t.Fatal("Write on read-only file succeeded")
			}
			r.Close()

			a, err := fsys.OpenFile(join("a", "g"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			a.Write([]byte("12"))
			a.Seek(0, io.SeekStart)
			a.Write([]byte("34"))
			a.Close()
			if fi, err := fsys.Stat(join("a", "g")); err != nil || fi.Size() != 4 {
				t.Fatalf("O_APPEND file size = %v, %v; want 4", fi, err)
			}

			if err := fsys.Rename(join("a", "g"), join("a", "f")); err != nil {
				t.Fatal(err)
			}
			if _, err := fsys.Stat(join("a", "g")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Stat renamed-away file = %v, want ErrNotExist", err)
			}
			if err := fsys.Rename(join("a", "nope"), join("a", "x")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Rename missing = %v, want ErrNotExist", err)
			}
			ents, err := fsys.ReadDir(join("a"))
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, e := range ents {
				names = append(names, e.Name())
			}
			if len(names) != 2 || names[0] != "b" || names[1] != "f" || !ents[0].IsDir() || ents[1].IsDir() {
				t.Fatalf("ReadDir = %v", names)
			}
			if err := fsys.Remove(join("a")); err == nil {
				t.Fatal("Remove of non-empty dir succeeded")
			}
			if err := fsys.SyncDir(join("a")); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Remove(join("a", "f")); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Remove(join("a", "f")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Remove missing = %v, want ErrNotExist", err)
			}
			if _, err := fsys.Open(join("a", "f")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Open missing = %v, want ErrNotExist", err)
			}
		})
	}
}

func TestOSOpenReturnsOSFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OS.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, ok := f.(*os.File); !ok {
		t.Fatalf("OS.Open returned %T, want *os.File", f)
	}
	if f, err := OS.Open(name + ".missing"); f != nil || err == nil {
		t.Fatalf("OS.Open missing = %v, %v; want nil interface and an error", f, err)
	}
}

func writeFile(t *testing.T, m *Mem, name, data string, sync bool) {
	t.Helper()
	f, err := m.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if sync {
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func readFile(m *Mem, name string) (string, error) {
	f, err := m.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	return string(b), err
}

func mustSyncDir(t *testing.T, m *Mem, name string) {
	t.Helper()
	if err := m.SyncDir(name); err != nil {
		t.Fatal(err)
	}
}

func TestMemCrashDiscardsUnsynced(t *testing.T) {
	m := NewMem()
	if err := m.MkdirAll("/d/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	mustSyncDir(t, m, "/")
	mustSyncDir(t, m, "/d")

	writeFile(t, m, "/d/synced", "durable", true)
	writeFile(t, m, "/d/unsynced", "lost", false)
	writeFile(t, m, "/d/sub/nodirsync", "named nowhere", true)
	mustSyncDir(t, m, "/d")

	// Overwrite a durable file without syncing: the old contents survive.
	writeFile(t, m, "/d/synced", "newer", false)
	// Create a file after the last directory sync: it vanishes.
	writeFile(t, m, "/d/late", "late", true)
	// Make a directory without syncing its parent: it vanishes.
	if err := m.Mkdir("/d/newdir", 0o755); err != nil {
		t.Fatal(err)
	}

	after := m.Restart(nil)
	if _, err := m.Stat("/d"); !errors.Is(err, ErrCrashed) {
		t.Fatalf("old filesystem after crash: %v, want ErrCrashed", err)
	}
	for name, want := range map[string]string{
		"/d/synced":   "durable",
		"/d/unsynced": "",
	} {
		if got, err := readFile(after, name); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"/d/sub/nodirsync", "/d/late", "/d/newdir"} {
		if _, err := after.Stat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s survived without a directory sync: %v", name, err)
		}
	}
}

func TestMemCrashRenameAndRemove(t *testing.T) {
	m := NewMem()
	m.MkdirAll("/a", 0o755)
	m.MkdirAll("/b", 0o755)
	mustSyncDir(t, m, "/")
	writeFile(t, m, "/a/x", "x", true)
	writeFile(t, m, "/a/y", "y", true)
	mustSyncDir(t, m, "/a")

	// A rename within a directory that is not synced is undone.
	if err := m.Rename("/a/x", "/a/x2"); err != nil {
		t.Fatal(err)
	}
	// A rename to a synced directory from an unsynced one leaves both names.
	if err := m.Rename("/a/y", "/b/y"); err != nil {
		t.Fatal(err)
	}
	mustSyncDir(t, m, "/b")
	after := m.Restart(nil)
	for name, want := range map[string]string{"/a/x": "x", "/a/y": "y", "/b/y": "y"} {
		if got, err := readFile(after, name); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := after.Stat("/a/x2"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("unsynced rename target survived: %v", err)
	}

	// A remove followed by a directory sync is durable; one without is undone.
	m = after
	if err := m.Remove("/a/x"); err != nil {
		t.Fatal(err)
	}
	mustSyncDir(t, m, "/a")
	if err := m.Remove("/b/y"); err != nil {
		t.Fatal(err)
	}
	after = m.Restart(nil)
	if _, err := after.Stat("/a/x"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("synced remove was undone: %v", err)
	}
	if _, err := after.Stat("/b/y"); err != nil {
		t.Errorf("unsynced remove survived: %v", err)
	}
}

func TestMemCrashTorn(t *testing.T) {
	old := bytes.Repeat([]byte{'o'}, 4*pageSize)
	latest := bytes.Repeat([]byte{'n'}, 6*pageSize)
	seenSizes := map[int]bool{}
	seenMixed := false
	for seed := range uint64(64) {
		m := NewMem()
		writeFile(t, m, "/f", string(old), true)
		mustSyncDir(t, m, "/")
		f, _ := m.OpenFile("/f", os.O_WRONLY, 0)
		f.Write(latest)
		after := m.Restart(rand.New(rand.NewPCG(seed, 0)))
		got, err := readFile(after, "/f")
		if err != nil {
			t.Fatal(err)
		}
		seenSizes[len(got)] = true
		var o, n int
		for off := 0; off < len(got); off += pageSize {
			page := got[off : off+pageSize]
			switch page {
			case string(old[:pageSize]):
				o++
			case string(latest[:pageSize]):
				n++
			case string(make([]byte, pageSize)):
			default:
				t.Fatalf("seed %d: page at %d is neither version", seed, off)
			}
		}
		if o > 0 && n > 0 {
			seenMixed = true
		}
	}
	if !seenSizes[len(old)] || !seenSizes[len(latest)] || !seenMixed {
		t.Fatalf("torn crashes did not cover both sizes and mixed pages: sizes %v, mixed %v", seenSizes, seenMixed)
	}
}

func TestMemCrashAfter(t *testing.T) {
	m := NewMem()
	m.CrashAfter(2)
	if err := m.Mkdir("/a", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.SyncDir("/"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stat("/a"); err != nil {
		t.Fatalf("read before crash point: %v", err)
	}
	if err := m.Mkdir("/b", 0o755); !errors.Is(err, ErrCrashed) {
		t.Fatalf("third mutating op = %v, want ErrCrashed", err)
	}
	if !m.Crashed() || m.Ops() != 2 {
		t.Fatalf("Crashed = %v, Ops = %d; want true, 2", m.Crashed(), m.Ops())
	}
	after := m.Restart(nil)
	if _, err := after.Stat("/a"); err != nil {
		t.Fatalf("synced mkdir lost: %v", err)
	}
	if _, err := after.Stat("/b"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("op after crash point survived: %v", err)
	}
}

func TestMemFault(t *testing.T) {
	m := NewMem()
	boom := errors.New("boom")
	f, err := m.OpenFile("/f", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	m.SetFault(func(op Op, name string) error {
		if op == OpWrite || op == OpSync {
			return boom
		}
		return nil
	})
	n, err := f.Write([]byte("abcdef"))
	if n != 3 || !errors.Is(err, boom) {
		t.Fatalf("faulted Write = %d, %v; want a short write of 3 and boom", n, err)
	}
	if err := f.Sync(); !errors.Is(err, boom) {
		t.Fatalf("faulted Sync = %v, want boom", err)
	}
	m.SetFault(nil)
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}
