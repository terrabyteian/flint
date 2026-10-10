package meta

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

// model is a reference implementation of the index.
type model map[string]Record

func (m model) clone() model {
	c := make(model, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// checkTree verifies t's structure and that it holds exactly m.
func checkTree(t *testing.T, tr tree, m model) {
	t.Helper()
	if tr.count != len(m) {
		t.Fatalf("count = %d, want %d", tr.count, len(m))
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var got []string
	tr.scan(nil, func(k []byte, r Record) bool {
		got = append(got, string(k))
		want := m[string(k)]
		if !bytes.Equal(r.Value, want.Value) || r.Version != want.Version {
			t.Fatalf("key %q = (%q, %d), want (%q, %d)", k, r.Value, r.Version, want.Value, want.Version)
		}
		return true
	})
	if !slices.Equal(got, keys) {
		t.Fatalf("scan returned %d keys, want %d", len(got), len(keys))
	}
	for _, k := range keys {
		r, ok := tr.get([]byte(k))
		if !ok || !bytes.Equal(r.Value, m[k].Value) {
			t.Fatalf("get(%q) = %q, %v", k, r.Value, ok)
		}
	}
	checkNode(t, tr.root, nil, nil, true)
}

// checkNode checks key order and separator bounds: every key in n is in [lo, hi).
func checkNode(t *testing.T, n *node, lo, hi []byte, root bool) int {
	t.Helper()
	if n.isLeaf() {
		for i := range n.len() {
			k := n.key(i)
			if lo != nil && bytes.Compare(k, lo) < 0 || hi != nil && bytes.Compare(k, hi) >= 0 {
				t.Fatalf("leaf key %q outside [%q, %q)", k, lo, hi)
			}
			if i > 0 && bytes.Compare(n.key(i-1), k) >= 0 {
				t.Fatalf("leaf keys out of order: %q, %q", n.key(i-1), k)
			}
		}
		if !root && n.len() == 0 {
			t.Fatal("empty non-root leaf")
		}
		return 1
	}
	if len(n.keys) != len(n.children)-1 {
		t.Fatalf("inner node has %d keys and %d children", len(n.keys), len(n.children))
	}
	if len(n.children) > maxChildren {
		t.Fatalf("inner node has %d children", len(n.children))
	}
	if root && len(n.children) < 2 {
		t.Fatal("inner root with one child")
	}
	depth := -1
	for i, c := range n.children {
		clo, chi := lo, hi
		if i > 0 {
			clo = n.keys[i-1]
		}
		if i < len(n.keys) {
			chi = n.keys[i]
		}
		d := checkNode(t, c, clo, chi, false)
		if depth >= 0 && d != depth {
			t.Fatal("unbalanced tree")
		}
		depth = d
	}
	return depth + 1
}

func TestTreeRandomOps(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	tr := emptyTree()
	m := model{}
	type saved struct {
		t tree
		m model
	}
	var history []saved
	seq := Seq(0)
	for round := range 300 {
		x := tr.txn()
		for range r.IntN(200) + 1 {
			seq++
			k := fmt.Appendf(nil, "key/%05d", r.IntN(3000))
			if r.IntN(3) == 0 {
				x.delete(k)
				delete(m, string(k))
				continue
			}
			v := bytes.Repeat([]byte{byte(seq)}, r.IntN(300))
			if r.IntN(50) == 0 {
				v = make([]byte, 20<<10) // larger than a leaf
			}
			x.put(k, v, seq)
			m[string(k)] = Record{Value: v, Version: seq}
		}
		tr = x.tree()
		if round%10 == 0 {
			history = append(history, saved{tr, m.clone()})
		}
		if round%50 == 0 {
			checkTree(t, tr, m)
		}
	}
	checkTree(t, tr, m)
	// Old trees are unchanged by later transactions.
	for _, h := range history {
		checkTree(t, h.t, h.m)
	}
	// Delete everything.
	x := tr.txn()
	for k := range m {
		x.delete([]byte(k))
	}
	checkTree(t, x.tree(), model{})
}

func TestTreeScanFrom(t *testing.T) {
	x := emptyTree().txn()
	for i := range 1000 {
		x.put(fmt.Appendf(nil, "k%04d", i*2), nil, 1)
	}
	tr := x.tree()
	for _, start := range []int{-1, 0, 1, 999, 1000, 1998, 1999, 2000} {
		var first []byte
		var startKey []byte
		if start >= 0 {
			startKey = fmt.Appendf(nil, "k%04d", start)
		}
		tr.scan(startKey, func(k []byte, _ Record) bool { first = k; return false })
		want := max(start, 0)
		want += want % 2
		if want >= 2000 {
			if first != nil {
				t.Errorf("scan from %d returned %q, want nothing", start, first)
			}
			continue
		}
		if string(first) != fmt.Sprintf("k%04d", want) {
			t.Errorf("scan from %d starts at %q, want k%04d", start, first, want)
		}
	}
}

func TestBuilder(t *testing.T) {
	for _, n := range []int{0, 1, 95, 96, 97, 5000, 100000} {
		b := newBuilder()
		m := model{}
		for i := range n {
			k := fmt.Appendf(nil, "k%07d", i)
			v := fmt.Appendf(nil, "v%d", i)
			if !b.add(k, v, Seq(i+1)) {
				t.Fatal("add rejected an increasing key")
			}
			m[string(k)] = Record{Value: v, Version: Seq(i + 1)}
		}
		tr := b.finish()
		checkTree(t, tr, m)
		// The built tree accepts further changes.
		x := tr.txn()
		x.put([]byte("a"), []byte("x"), 9)
		x.delete([]byte("k0000000"))
		m["a"] = Record{Value: []byte("x"), Version: 9}
		delete(m, "k0000000")
		checkTree(t, x.tree(), m)
	}
	b := newBuilder()
	b.add([]byte("b"), nil, 1)
	if b.add([]byte("a"), nil, 1) || b.add([]byte("b"), nil, 1) {
		t.Fatal("builder accepted a non-increasing key")
	}
}

// TestValuesNotAliased checks that appending to a returned key or value
// cannot change the index.
func TestValuesNotAliased(t *testing.T) {
	x := emptyTree().txn()
	x.put([]byte("a"), []byte("1"), 1)
	x.put([]byte("b"), []byte("2"), 1)
	tr := x.tree()
	r, _ := tr.get([]byte("a"))
	_ = append(r.Value, 'X')
	tr.scan(nil, func(k []byte, _ Record) bool { _ = append(k, 'Y'); return true })
	if r, _ := tr.get([]byte("b")); string(r.Value) != "2" {
		t.Fatalf("b = %q after appending to a's value", r.Value)
	}
}
