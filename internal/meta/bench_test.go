package meta

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

// BenchmarkCommit measures commit throughput and latency with group commit
// on the real filesystem, at several levels of concurrency. Each commit is
// a typical one-key batch. The "nosync" variants skip the log fsync to
// show the CPU cost of the commit path itself.
//
//	go test ./internal/meta -run '^$' -bench Commit
func BenchmarkCommit(b *testing.B) {
	for _, fsName := range []string{"os", "nosync"} {
		for _, writers := range []int{1, 16, 128} {
			b.Run(fmt.Sprintf("%s/writers=%d", fsName, writers), func(b *testing.B) {
				var fs fsys.FS = fsys.OS
				if fsName == "nosync" {
					fs = noSyncFS{fsys.OS}
				}
				s, err := Open(filepath.Join(b.TempDir(), "meta"), Options{FS: fs, Logger: quiet, SnapshotBytes: -1})
				if err != nil {
					b.Fatal(err)
				}
				defer s.Close()
				value := make([]byte, 120)
				var next atomic.Int64
				lat := make([][]time.Duration, writers)
				b.ResetTimer()
				var wg sync.WaitGroup
				for w := range writers {
					wg.Go(func() {
						for {
							i := next.Add(1)
							if i > int64(b.N) {
								return
							}
							var batch Batch
							batch.Put(fmt.Appendf(nil, "oci\x00tag\x00repo\x00name-%d\x00tag-%d", w, i), value)
							start := time.Now()
							if _, err := s.Commit(context.Background(), &batch); err != nil {
								b.Error(err)
								return
							}
							lat[w] = append(lat[w], time.Since(start))
						}
					})
				}
				wg.Wait()
				b.StopTimer()
				all := slices.Concat(lat...)
				slices.Sort(all)
				if len(all) > 0 {
					b.ReportMetric(float64(all[len(all)/2].Microseconds()), "p50-µs")
					b.ReportMetric(float64(all[len(all)*99/100].Microseconds()), "p99-µs")
				}
				st := s.Stats()
				b.ReportMetric(float64(st.Commits)/float64(max(st.GroupCommits, 1)), "commits/fsync")
				b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "commits/s")
			})
		}
	}
}

// noSyncFS is a filesystem whose file fsyncs do nothing.
type noSyncFS struct{ fsys.FS }

func (n noSyncFS) OpenFile(name string, flag int, perm fs.FileMode) (fsys.File, error) {
	f, err := n.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return noSync{f}, nil
}

// BenchmarkIndexMemory measures the heap the index needs per record, for
// records shaped like OCI blob links: a key of about 110 bytes and a value
// of 48 bytes. It reports total heap bytes per record and the overhead
// beyond the key and value bytes themselves. "commits" builds the index
// the way live commits do, in group-commit-sized transactions in random
// key order; "snapshot" builds it the way startup loads a snapshot.
//
//	go test ./internal/meta -run '^$' -bench IndexMemory -benchtime 1x
func BenchmarkIndexMemory(b *testing.B) {
	const n = 1_000_000
	key := func(i int) []byte {
		sum := sha256.Sum256(fmt.Appendf(nil, "%d", i))
		return fmt.Appendf(nil, "oci\x00blob\x00team-%d/service-%d\x00app\x00sha256:%s", i%37, i%1000, hex.EncodeToString(sum[:]))
	}
	value := make([]byte, 48)
	payload := 0
	for i := range n {
		payload += len(key(i)) + len(value)
	}
	measure := func(b *testing.B, build func() tree) {
		for range b.N {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			t := build()
			runtime.GC()
			runtime.ReadMemStats(&after)
			if t.count != n {
				b.Fatalf("built %d records", t.count)
			}
			per := float64(after.HeapAlloc-before.HeapAlloc) / n
			b.ReportMetric(per, "B/record")
			b.ReportMetric(per-float64(payload)/n, "overhead-B/record")
			runtime.KeepAlive(t)
		}
	}
	b.Run("commits", func(b *testing.B) {
		measure(b, func() tree {
			t := emptyTree()
			for i := 0; i < n; i += 100 {
				x := t.txn()
				for j := i; j < i+100; j++ {
					x.put(key(j), value, Seq(j+1))
				}
				t = x.tree()
			}
			return t
		})
	})
	b.Run("snapshot", func(b *testing.B) {
		keys := make([][]byte, n)
		for i := range keys {
			keys[i] = key(i)
		}
		slices.SortFunc(keys, bytes.Compare)
		measure(b, func() tree {
			bl := newBuilder()
			for i, k := range keys {
				bl.add(k, value, Seq(i+1))
			}
			return bl.finish()
		})
	})
}
