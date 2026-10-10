package meta

import (
	"bufio"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const killChildEnv = "FLINT_META_KILL_CHILD"

// TestKillChild is the child process of TestProcessKill. It runs the
// workload on the store in $FLINT_META_KILL_CHILD and reports every
// acknowledged commit on stdout until it is killed.
func TestKillChild(t *testing.T) {
	dir := os.Getenv(killChildEnv)
	if dir == "" {
		t.Skip("child process of TestProcessKill")
	}
	s, err := Open(dir, Options{SegmentSize: 16 << 10, SnapshotBytes: 64 << 10, Logger: quiet})
	if err != nil {
		fmt.Printf("error %v\n", err)
		os.Exit(1)
	}
	w := newWorkload(6, 2)
	w.adopt(s)
	var mu sync.Mutex
	w.onAck = func(kind byte, g, i int, seq Seq) {
		mu.Lock()
		fmt.Printf("%c %d %d %d\n", kind, g, i, seq)
		mu.Unlock()
	}
	fmt.Println("ready")
	w.run(s, 1<<30)
	select {} // wait to be killed
}

// TestProcessKill runs the store in a child process under concurrent load,
// kills it with SIGKILL at a random moment, reopens the store, and checks
// that every commit the child acknowledged is present and no partial batch
// is visible. The page cache survives SIGKILL, so this covers process
// crashes and the recovery code, not missing fsyncs.
func TestProcessKill(t *testing.T) {
	if os.Getenv(killChildEnv) != "" {
		t.Skip("in the child")
	}
	dir := filepath.Join(t.TempDir(), "meta")
	w := newWorkload(6, 2)
	r := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 3))
	for it := range iterations(5, 2) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestKillChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), killChildEnv+"="+dir)
		cmd.Stderr = os.Stderr
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		done := make(chan int)
		go func() {
			acks := 0
			sc := bufio.NewScanner(out)
			for sc.Scan() {
				var kind byte
				var g, i int
				var seq Seq
				if sc.Text() == "ready" {
					close(ready)
					continue
				}
				if _, err := fmt.Sscanf(sc.Text(), "%c %d %d %d", &kind, &g, &i, &seq); err != nil {
					t.Errorf("child: %s", sc.Text())
					continue
				}
				acks++
				w.mu.Lock()
				switch kind {
				case 'w':
					w.acked[g], w.ver[g] = i, seq
				case 'c':
					w.casAck = max(w.casAck, i)
				}
				w.maxSeq = max(w.maxSeq, seq)
				w.mu.Unlock()
			}
			done <- acks
		}()
		select {
		case <-ready:
		case <-time.After(60 * time.Second):
			cmd.Process.Kill()
			t.Fatal("child did not start")
		}
		time.Sleep(time.Duration(20+r.IntN(200)) * time.Millisecond)
		if err := cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		cmd.Wait()
		acks := <-done
		if acks == 0 {
			t.Fatalf("iteration %d: the child acknowledged nothing before it was killed", it)
		}
		s, err := Open(dir, Options{Logger: quiet})
		if err != nil {
			t.Fatalf("iteration %d: reopening after SIGKILL: %v", it, err)
		}
		err = w.check(s, true)
		s.Close()
		if err != nil {
			t.Fatalf("iteration %d (%d acks): %v", it, acks, err)
		}
		t.Logf("iteration %d: %d acknowledged commits survived SIGKILL", it, acks)
	}
}
