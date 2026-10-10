package meta

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
)

// workload is a concurrent commit load whose acknowledged effects can be
// checked after any crash.
//
// Each of the writers commits batches 1, 2, 3, ... in order. Batch i of
// writer g sets w<g>/ctr and w<g>/mirror to i, adds w<g>/item/<i>, deletes
// w<g>/item/<i-3>, and requires w<g>/ctr to be at the version of batch i-1.
// After a crash the state of writer g must be exactly the effect of some
// prefix of its batches that includes every acknowledged one: at most one
// unacknowledged batch (the one in flight) may also be present, and no
// batch may be partly present.
//
// The counters increment the shared key cas/ctr with compare-and-swap
// commits, so preconditions are exercised under contention: after a crash
// the counter holds at least the highest acknowledged value, plus at most
// one in-flight increment per counter goroutine.
type workload struct {
	writers  int
	counters int

	mu      sync.Mutex
	acked   []int // per writer: last acknowledged batch
	ver     []Seq // per writer: version of w<g>/ctr after acked
	casAck  int   // highest acknowledged counter value
	maxSeq  Seq   // highest acknowledged sequence number
	onAck   func(kind byte, g, i int, seq Seq)
	payload func(g, i int) []byte
}

func newWorkload(writers, counters int) *workload {
	return &workload{
		writers:  writers,
		counters: counters,
		acked:    make([]int, writers),
		ver:      make([]Seq, writers),
		payload:  defaultPayload,
	}
}

func defaultPayload(g, i int) []byte {
	n := (g*7919 + i*104729) % 700
	if i%17 == 0 {
		n += 3000 // some batches span segment boundaries
	}
	return bytes.Repeat([]byte{byte('a' + (g+i)%26)}, n)
}

func wkey(g int, name string) []byte { return fmt.Appendf(nil, "w%02d/%s", g, name) }

func itemKey(g, i int) []byte { return fmt.Appendf(nil, "w%02d/item/%08d", g, i) }

// run commits from every writer and counter until each has done budget
// batches or a commit fails with anything but a conflict.
func (w *workload) run(s Store, budget int) {
	var wg sync.WaitGroup
	for g := range w.writers {
		wg.Go(func() { w.writer(s, g, budget) })
	}
	for range w.counters {
		wg.Go(func() { w.counter(s, budget) })
	}
	wg.Wait()
}

func (w *workload) writer(s Store, g, budget int) {
	w.mu.Lock()
	i, ver := w.acked[g], w.ver[g]
	w.mu.Unlock()
	for range budget {
		i++
		var b Batch
		b.Require(wkey(g, "ctr"), ver)
		b.Put(wkey(g, "ctr"), strconv.AppendInt(nil, int64(i), 10))
		b.Put(wkey(g, "mirror"), strconv.AppendInt(nil, int64(i), 10))
		b.Put(itemKey(g, i), w.payload(g, i))
		b.Delete(itemKey(g, i-3))
		b.SetOrigin(Origin{Actor: "test", Action: "writer", Target: fmt.Sprint(g)})
		seq, err := s.Commit(context.Background(), &b)
		if err != nil {
			return
		}
		ver = seq
		w.mu.Lock()
		w.acked[g], w.ver[g], w.maxSeq = i, seq, max(w.maxSeq, seq)
		w.mu.Unlock()
		if w.onAck != nil {
			w.onAck('w', g, i, seq)
		}
	}
}

func (w *workload) counter(s Store, budget int) {
	key := []byte("cas/ctr")
	for done := 0; done < budget; {
		v := s.View()
		r, _ := v.Get(key)
		v.Release()
		n, _ := strconv.Atoi(string(r.Value))
		var b Batch
		b.Require(key, r.Version)
		b.Put(key, strconv.AppendInt(nil, int64(n+1), 10))
		seq, err := s.Commit(context.Background(), &b)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return
		}
		done++
		w.mu.Lock()
		w.casAck, w.maxSeq = max(w.casAck, n+1), max(w.maxSeq, seq)
		w.mu.Unlock()
		if w.onAck != nil {
			w.onAck('c', 0, n+1, seq)
		}
	}
}

func atoi(b []byte) int { n, _ := strconv.Atoi(string(b)); return n }

// check verifies the store against everything acknowledged so far. With
// inFlight, each writer and counter may also have one unacknowledged batch
// applied. It then adopts the store's state as the new baseline.
func (w *workload) check(s Store, inFlight bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := s.View()
	defer v.Release()
	slack := 0
	if inFlight {
		slack = 1
	}
	if v.Seq() < w.maxSeq {
		return fmt.Errorf("store is at seq %d, but seq %d was acknowledged", v.Seq(), w.maxSeq)
	}
	for g := range w.writers {
		ctr, ok := v.Get(wkey(g, "ctr"))
		mirror, mok := v.Get(wkey(g, "mirror"))
		c := atoi(ctr.Value)
		if ok != mok || atoi(mirror.Value) != c || ctr.Version != mirror.Version {
			return fmt.Errorf("writer %d: partial batch: ctr=%q@%d mirror=%q@%d", g, ctr.Value, ctr.Version, mirror.Value, mirror.Version)
		}
		if c < w.acked[g] || c > w.acked[g]+slack {
			return fmt.Errorf("writer %d: at batch %d, but batch %d was acknowledged", g, c, w.acked[g])
		}
		if c == w.acked[g] && w.acked[g] > 0 && ctr.Version != w.ver[g] {
			return fmt.Errorf("writer %d: batch %d at version %d, acknowledged as %d", g, c, ctr.Version, w.ver[g])
		}
		var items []int
		var bad error
		v.Scan(wkey(g, "item/"), nil, func(k []byte, r Record) bool {
			i := atoi(k[len(k)-8:])
			items = append(items, i)
			if !bytes.Equal(r.Value, w.payload(g, i)) {
				bad = fmt.Errorf("writer %d: item %d has the wrong value", g, i)
			}
			if i == c && r.Version != ctr.Version {
				bad = fmt.Errorf("writer %d: item %d at version %d, ctr at %d", g, i, r.Version, ctr.Version)
			}
			return true
		})
		if bad != nil {
			return bad
		}
		var want []int
		for i := max(1, c-2); i <= c; i++ {
			want = append(want, i)
		}
		if fmt.Sprint(items) != fmt.Sprint(want) {
			return fmt.Errorf("writer %d at batch %d: items %v, want %v", g, c, items, want)
		}
		w.acked[g], w.ver[g] = c, ctr.Version
	}
	if w.counters > 0 {
		r, _ := v.Get([]byte("cas/ctr"))
		n := atoi(r.Value)
		if n < w.casAck || n > w.casAck+slack*w.counters {
			return fmt.Errorf("counter is %d, acknowledged %d with %d counters", n, w.casAck, w.counters)
		}
		w.casAck = n
	}
	// Nothing outside the workload's keys exists.
	var stray error
	v.Scan(nil, nil, func(k []byte, _ Record) bool {
		if !bytes.HasPrefix(k, []byte("w")) && !bytes.Equal(k, []byte("cas/ctr")) {
			stray = fmt.Errorf("unexpected key %q", k)
			return false
		}
		return true
	})
	w.maxSeq = v.Seq()
	return stray
}

// adopt takes the store's state as the baseline without checking it.
func (w *workload) adopt(s Store) {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := s.View()
	defer v.Release()
	for g := range w.writers {
		r, _ := v.Get(wkey(g, "ctr"))
		w.acked[g], w.ver[g] = atoi(r.Value), r.Version
	}
	r, _ := v.Get([]byte("cas/ctr"))
	w.casAck, w.maxSeq = atoi(r.Value), v.Seq()
}
