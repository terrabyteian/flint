package blob

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

// killDirEnv names the data directory of the child process in TestKill.
const killDirEnv = "FLINT_BLOB_KILL_DIR"

// killContent returns the deterministic content of upload i of worker w in
// round r, so the parent can finish uploads the child left suspended.
func killContent(r, w, i int) []byte {
	rng := rand.New(rand.NewPCG(uint64(r), uint64(w)<<32|uint64(i)))
	data := fmt.Appendf(nil, "round %d worker %d upload %d ", r, w, i)
	return append(data, randBytes(rng, rng.IntN(1<<20))...)
}

// TestKill runs the store in a child process under concurrent load, kills
// it with SIGKILL at a random moment, reopens the store, and checks it
// against what the child reported as acknowledged. The page cache survives
// SIGKILL, so this covers process crashes and recovery, not missing fsyncs;
// TestCrash covers those.
func TestKill(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns child processes")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	dir := filepath.Join(t.TempDir(), "data")
	rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0))
	for round := range 3 {
		cmd := exec.Command(exe, "-test.run=^TestKillChild$")
		cmd.Env = append(os.Environ(), killDirEnv+"="+dir, "FLINT_BLOB_KILL_ROUND="+strconv.Itoa(round))
		cmd.Stderr = os.Stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var lines []string
		read := make(chan struct{})
		go func() {
			defer close(read)
			br := bufio.NewReader(stdout)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return // a partial last line was never fully reported
				}
				lines = append(lines, strings.TrimSuffix(line, "\n"))
			}
		}()
		// Let the child get going, then kill it at a random moment.
		time.Sleep(time.Duration(200+rng.IntN(400)) * time.Millisecond)
		if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		<-read
		cmd.Wait()
		if len(lines) == 0 {
			t.Fatalf("round %d: child reported nothing before it was killed", round)
		}
		t.Logf("round %d: %d acknowledged operations before SIGKILL", round, len(lines))
		checkKilled(t, dir, round, lines)
	}
}

// checkKilled verifies the store in dir against the child's reports.
func checkKilled(t *testing.T, dir string, round int, lines []string) {
	t.Helper()
	type chunked struct {
		w, i      int
		sizes     []int64
		acked     int64
		finishing bool
		done      bool
	}
	// deleting holds blobs whose Delete started; deleted, those acknowledged.
	committed, deleting, deleted := map[Digest]bool{}, map[Digest]bool{}, map[Digest]bool{}
	uploads := map[string]*chunked{}
	for _, line := range lines {
		f := strings.Fields(line)
		switch f[0] {
		// C digest [id]: a Commit was acknowledged (of upload id, if chunked).
		// X digest: a Delete is starting. D digest: it was acknowledged.
		case "C", "X", "D":
			d, err := ParseDigest(f[1])
			if err != nil {
				t.Fatalf("bad report %q: %v", line, err)
			}
			switch f[0] {
			case "C":
				committed[d] = true
			case "X":
				deleting[d] = true
			case "D":
				deleted[d] = true
			}
			if len(f) == 3 {
				uploads[f[2]].done = true
			}
		case "B": // B id worker upload size: a Suspend is starting
			c := uploads[f[1]]
			if c == nil {
				c = &chunked{}
				c.w, _ = strconv.Atoi(f[2])
				c.i, _ = strconv.Atoi(f[3])
				uploads[f[1]] = c
			}
			size, _ := strconv.ParseInt(f[4], 10, 64)
			c.sizes = append(c.sizes, size)
		case "S": // S id size: the Suspend was acknowledged
			uploads[f[1]].acked, _ = strconv.ParseInt(f[2], 10, 64)
		case "F": // F id: a Commit is starting
			uploads[f[1]].finishing = true
		default:
			t.Fatalf("bad report %q", line)
		}
	}

	s, err := NewFS(dir, Options{})
	if err != nil {
		t.Fatalf("reopening after SIGKILL: %v", err)
	}
	checked := 0
	for d := range committed {
		if deleting[d] {
			continue
		}
		checked++
		if got, err := readAll(s, d); err != nil || FromBytes(got) != d {
			t.Errorf("acknowledged blob %s lost or corrupt: %v", d, err)
		}
	}
	for d := range deleted {
		if _, err := s.Stat(ctx, d); !errors.Is(err, ErrNotFound) {
			t.Errorf("acknowledged delete of %s undone: %v", d, err)
		}
	}
	err = s.Walk(ctx, func(info Info) error {
		got, err := readAll(s, info.Digest)
		if err != nil {
			return err
		}
		if FromBytes(got) != info.Digest || int64(len(got)) != info.Size {
			t.Errorf("visible blob %s is partial or corrupt", info.Digest)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	resumed := 0
	for id, c := range uploads {
		if c.done {
			continue
		}
		u, err := s.ResumeUpload(ctx, id)
		if err != nil {
			if c.acked > 0 && !c.finishing {
				t.Errorf("acknowledged suspend of %s at %d lost: %v", id, c.acked, err)
			}
			continue
		}
		if !slices.Contains(c.sizes, u.Size()) || u.Size() < c.acked {
			t.Errorf("resumed %s at %d; suspends started at %v, acknowledged at %d", id, u.Size(), c.sizes, c.acked)
			u.Cancel()
			continue
		}
		content := killContent(round, c.w, c.i)
		u.Write(content[u.Size():])
		if _, err := u.Commit(ctx, FromBytes(content)); err != nil {
			t.Errorf("finishing resumed upload %s: %v", id, err)
		}
		resumed++
	}
	purged, err := s.PurgeUploads(ctx, farFuture)
	if err != nil {
		t.Fatal(err)
	}
	checkUploadsEmpty(t, fsys.OS, dir)
	t.Logf("round %d: %d acknowledged blobs checked, %d suspended uploads resumed and finished, %d abandoned uploads purged",
		round, checked, resumed, purged)
}

func readAll(s Store, d Digest) ([]byte, error) {
	r, err := s.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// TestKillChild is the child process of TestKill. It uploads until killed,
// writing one line to stdout for each acknowledged operation.
func TestKillChild(t *testing.T) {
	dir := os.Getenv(killDirEnv)
	if dir == "" {
		t.Skip("run by TestKill")
	}
	round, _ := strconv.Atoi(os.Getenv("FLINT_BLOB_KILL_ROUND"))
	s, err := NewFS(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	report := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(os.Stdout, format+"\n", args...)
	}
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "kill child:", err)
		os.Exit(3)
	}
	for w := range 4 {
		go func() {
			var mine []Digest
			for i := 0; ; i++ {
				content := killContent(round, w, i)
				d := FromBytes(content)
				u, err := s.NewUpload(ctx)
				if err != nil {
					fail(err)
				}
				switch i % 5 {
				case 4:
					// A client that went away mid-upload: leave it suspended.
					u.Write(content[:len(content)/2])
					report("B %s %d %d %d", u.ID(), w, i, u.Size())
					if err := u.Suspend(); err != nil {
						fail(err)
					}
					report("S %s %d", u.ID(), u.Size())
					continue
				case 0, 1, 2:
					u.Write(content)
					if _, err := u.Commit(ctx, d); err != nil {
						fail(err)
					}
					report("C %s", d)
					mine = append(mine, d)
				case 3:
					id := u.ID()
					cuts := []int{len(content) / 3, 2 * len(content) / 3, len(content)}
					prev := 0
					for j, cut := range cuts {
						if j > 0 {
							if u, err = s.ResumeUpload(ctx, id); err != nil {
								fail(err)
							}
						}
						u.Write(content[prev:cut])
						prev = cut
						if j == len(cuts)-1 {
							break
						}
						report("B %s %d %d %d", id, w, i, u.Size())
						if err := u.Suspend(); err != nil {
							fail(err)
						}
						report("S %s %d", id, u.Size())
					}
					report("F %s", id)
					if _, err := u.Commit(ctx, d); err != nil {
						fail(err)
					}
					report("C %s %s", d, id)
				}
				if len(mine) > 3 {
					report("X %s", mine[0])
					if err := s.Delete(ctx, mine[0]); err != nil {
						fail(err)
					}
					report("D %s", mine[0])
					mine = mine[1:]
				}
			}
		}()
	}
	time.Sleep(30 * time.Second)
	fail(errors.New("not killed within 30s"))
}
