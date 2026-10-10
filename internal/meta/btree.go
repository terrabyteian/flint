package meta

import (
	"bytes"
	"encoding/binary"
	"slices"
	"sort"
	"sync/atomic"
)

// The index is a copy-on-write B+tree. A published tree is never modified,
// so a view is a root pointer and needs no locks. Writers build the next
// tree in a txn: nodes the txn creates carry its generation and are
// modified in place; any other node is cloned before its first change.
//
// To keep memory and garbage-collector cost low, a leaf packs all of its
// entries into one byte slice plus an offset table, so a leaf costs two
// pointers no matter how many records it holds. An entry is
//
//	uvarint(len(key)) key version(8 bytes, little endian) value
//
// Record values handed to readers are subslices of a published leaf's
// buffer, which is never written again.

const (
	maxLeafEntries = 128
	maxLeafBytes   = 16 << 10
	maxChildren    = 64
)

var genCounter atomic.Uint64

type node struct {
	gen uint64

	// Leaves: entry i is buf[offs[i]:offs[i+1]]; len(offs) is entries+1.
	buf  []byte
	offs []uint32

	// Inner nodes: every key in children[i+1] is >= keys[i], and every key
	// in children[i] is < keys[i].
	keys     [][]byte
	children []*node
}

func newLeaf(gen uint64) *node { return &node{gen: gen, offs: []uint32{0}} }

func (n *node) isLeaf() bool { return n.children == nil }

func (n *node) len() int {
	if n.isLeaf() {
		return len(n.offs) - 1
	}
	return len(n.children)
}

func (n *node) entry(i int) []byte { return n.buf[n.offs[i]:n.offs[i+1]] }

func (n *node) key(i int) []byte { k, _, _ := decodeEntry(n.entry(i)); return k }

func decodeEntry(e []byte) (key []byte, ver Seq, val []byte) {
	kl, w := binary.Uvarint(e)
	k := w + int(kl)
	// Cap both slices so that a caller's append cannot write into the leaf.
	return e[w:k:k], Seq(binary.LittleEndian.Uint64(e[k:])), e[k+8 : len(e) : len(e)]
}

func appendEntry(dst, key, val []byte, ver Seq) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(key)))
	dst = append(dst, key...)
	dst = binary.LittleEndian.AppendUint64(dst, uint64(ver))
	return append(dst, val...)
}

// search returns the index of the first entry whose key is >= key, and
// whether that key equals key.
func (n *node) search(key []byte) (int, bool) {
	i := sort.Search(n.len(), func(i int) bool { return bytes.Compare(n.key(i), key) >= 0 })
	return i, i < n.len() && bytes.Equal(n.key(i), key)
}

// childIndex returns the index of the child that holds key.
func (n *node) childIndex(key []byte) int {
	return sort.Search(len(n.keys), func(i int) bool { return bytes.Compare(n.keys[i], key) > 0 })
}

func (n *node) overfull() bool {
	if n.isLeaf() {
		return n.len() > maxLeafEntries || (len(n.buf) > maxLeafBytes && n.len() > 1)
	}
	return len(n.children) > maxChildren
}

func (n *node) underfull() bool {
	if n.isLeaf() {
		return n.len() < maxLeafEntries/4 && len(n.buf) < maxLeafBytes/4
	}
	return len(n.children) < maxChildren/4
}

func (n *node) clone(gen uint64) *node {
	c := &node{gen: gen}
	if n.isLeaf() {
		c.buf = make([]byte, len(n.buf), len(n.buf)+len(n.buf)/8+64)
		copy(c.buf, n.buf)
		c.offs = make([]uint32, len(n.offs), len(n.offs)+4)
		copy(c.offs, n.offs)
		return c
	}
	c.keys = make([][]byte, len(n.keys), maxChildren)
	copy(c.keys, n.keys)
	c.children = make([]*node, len(n.children), maxChildren+1)
	copy(c.children, n.children)
	return c
}

// splice replaces leaf entries [i, j) with ents. The node must be owned.
func (n *node) splice(i, j int, ents ...[]byte) {
	start, end := int(n.offs[i]), int(n.offs[j])
	add := 0
	for _, e := range ents {
		add += len(e)
	}
	delta := add - (end - start)
	oldLen := len(n.buf)
	newLen := oldLen + delta
	if newLen > cap(n.buf) {
		nb := make([]byte, newLen, newLen+newLen/4)
		copy(nb, n.buf[:start])
		copy(nb[start+add:], n.buf[end:])
		n.buf = nb
	} else {
		n.buf = n.buf[:max(oldLen, newLen)]
		copy(n.buf[start+add:], n.buf[end:oldLen])
		n.buf = n.buf[:newLen]
	}
	ends := make([]uint32, len(ents))
	p := start
	for k, e := range ents {
		copy(n.buf[p:], e)
		p += len(e)
		ends[k] = uint32(p)
	}
	n.offs = slices.Replace(n.offs, i+1, j+1, ends...)
	for k := i + 1 + len(ents); k < len(n.offs); k++ {
		n.offs[k] = uint32(int(n.offs[k]) + delta)
	}
}

// tree is an immutable index root.
type tree struct {
	root  *node
	count int
}

func emptyTree() tree { return tree{root: newLeaf(0)} }

func (t tree) get(key []byte) (Record, bool) {
	n := t.root
	for !n.isLeaf() {
		n = n.children[n.childIndex(key)]
	}
	i, ok := n.search(key)
	if !ok {
		return Record{}, false
	}
	_, ver, val := decodeEntry(n.entry(i))
	return Record{Value: val, Version: ver}, true
}

// scan calls fn for each entry with key >= start, in order, until fn returns false.
func (t tree) scan(start []byte, fn func(key []byte, r Record) bool) {
	t.root.scan(start, fn)
}

func (n *node) scan(start []byte, fn func(key []byte, r Record) bool) bool {
	if n.isLeaf() {
		i := 0
		if start != nil {
			i, _ = n.search(start)
		}
		for ; i < n.len(); i++ {
			k, ver, val := decodeEntry(n.entry(i))
			if !fn(k, Record{Value: val, Version: ver}) {
				return false
			}
		}
		return true
	}
	c := 0
	if start != nil {
		c = n.childIndex(start)
	}
	for ; c < len(n.children); c++ {
		if !n.children[c].scan(start, fn) {
			return false
		}
		start = nil
	}
	return true
}

// txn builds a new tree from an old one. It is not safe for concurrent use.
type txn struct {
	gen     uint64
	t       tree
	scratch []byte
}

func (t tree) txn() *txn { return &txn{gen: genCounter.Add(1), t: t} }

// tree returns the tree built so far. The txn must not be used afterwards,
// because the returned tree may be published and must not change.
func (x *txn) tree() tree { return x.t }

func (x *txn) get(key []byte) (Record, bool) { return x.t.get(key) }

func (x *txn) own(n *node) *node {
	if n.gen == x.gen {
		return n
	}
	return n.clone(x.gen)
}

func (x *txn) put(key, val []byte, ver Seq) {
	x.scratch = appendEntry(x.scratch[:0], key, val, ver)
	root, added := x.insert(x.t.root, key, x.scratch)
	if root.overfull() {
		l, r, sep := x.split(root)
		root = &node{gen: x.gen, keys: append(make([][]byte, 0, maxChildren), sep), children: append(make([]*node, 0, maxChildren+1), l, r)}
	}
	x.t.root = root
	if added {
		x.t.count++
	}
}

func (x *txn) insert(n *node, key, ent []byte) (*node, bool) {
	n = x.own(n)
	if n.isLeaf() {
		i, found := n.search(key)
		if found {
			n.splice(i, i+1, ent)
		} else {
			n.splice(i, i, ent)
		}
		return n, !found
	}
	c := n.childIndex(key)
	child, added := x.insert(n.children[c], key, ent)
	n.children[c] = child
	if child.overfull() {
		l, r, sep := x.split(child)
		n.children[c] = l
		n.children = slices.Insert(n.children, c+1, r)
		n.keys = slices.Insert(n.keys, c, sep)
	}
	return n, added
}

func (x *txn) delete(key []byte) {
	if _, ok := x.t.get(key); !ok {
		return
	}
	root := x.remove(x.t.root, key)
	for !root.isLeaf() && len(root.children) == 1 {
		root = root.children[0]
	}
	x.t.root = root
	x.t.count--
}

func (x *txn) remove(n *node, key []byte) *node {
	n = x.own(n)
	if n.isLeaf() {
		i, _ := n.search(key)
		n.splice(i, i+1)
		return n
	}
	c := n.childIndex(key)
	n.children[c] = x.remove(n.children[c], key)
	if n.children[c].underfull() && len(n.children) > 1 {
		x.rebalance(n, c)
	}
	return n
}

// rebalance merges underfull child c of n with a neighbor, splitting the
// result again if it is too big. n must be owned.
func (x *txn) rebalance(n *node, c int) {
	a := c
	if a == len(n.children)-1 {
		a--
	}
	left, right := n.children[a], n.children[a+1]
	m := x.own(left)
	if m.isLeaf() {
		ents := make([][]byte, right.len())
		for i := range ents {
			ents[i] = right.entry(i)
		}
		m.splice(m.len(), m.len(), ents...)
	} else {
		m.keys = append(append(m.keys, n.keys[a]), right.keys...)
		m.children = append(m.children, right.children...)
	}
	if m.overfull() {
		l, r, sep := x.split(m)
		n.children[a], n.children[a+1] = l, r
		n.keys[a] = sep
		return
	}
	n.children[a] = m
	n.children = slices.Delete(n.children, a+1, a+2)
	n.keys = slices.Delete(n.keys, a, a+1)
}

// split divides an owned, overfull node into two halves and returns them
// with the separator key: the smallest key of the right half.
func (x *txn) split(n *node) (l, r *node, sep []byte) {
	if !n.isLeaf() {
		mid := len(n.children) / 2
		r = &node{gen: x.gen, keys: make([][]byte, 0, maxChildren), children: make([]*node, 0, maxChildren+1)}
		r.keys = append(r.keys, n.keys[mid:]...)
		r.children = append(r.children, n.children[mid:]...)
		sep = n.keys[mid-1]
		clear(n.keys[mid-1:])
		clear(n.children[mid:])
		n.keys = n.keys[:mid-1]
		n.children = n.children[:mid]
		return n, r, sep
	}
	// Split by bytes so leaves holding large values stay balanced.
	mid := sort.Search(n.len(), func(i int) bool { return int(n.offs[i]) >= len(n.buf)/2 })
	mid = min(max(mid, 1), n.len()-1)
	if n.len() > maxLeafEntries {
		mid = n.len() / 2
	}
	r = newLeaf(x.gen)
	ents := make([][]byte, n.len()-mid)
	for i := range ents {
		ents[i] = n.entry(mid + i)
	}
	r.splice(0, 0, ents...)
	n.splice(mid, n.len())
	return n, r, bytes.Clone(r.key(0))
}

// builder bulk-loads a tree from entries in strictly increasing key order.
type builder struct {
	gen    uint64
	leaves []*node
	cur    *node
	ents   [][]byte
	bytes  int
	count  int
	last   []byte
	buf    []byte
}

func newBuilder() *builder { return &builder{gen: genCounter.Add(1)} }

// Leaves are filled to three quarters so that later inserts do not split
// every leaf at once.
const (
	fillEntries  = maxLeafEntries * 3 / 4
	fillBytes    = maxLeafBytes * 3 / 4
	fillChildren = maxChildren * 3 / 4
)

// add appends an entry. It reports false if key is not greater than the previous key.
func (b *builder) add(key, val []byte, ver Seq) bool {
	return b.addEntry(appendEntry(nil, key, val, ver))
}

// addEntry appends an encoded entry, which it does not retain. It reports
// false if the entry is malformed or its key is not greater than the
// previous key.
func (b *builder) addEntry(e []byte) bool {
	kl, w := binary.Uvarint(e)
	if w <= 0 || kl > uint64(len(e)-w) || len(e)-w-int(kl) < 8 {
		return false
	}
	key := e[w : w+int(kl)]
	if b.count > 0 && bytes.Compare(key, b.last) <= 0 {
		return false
	}
	b.count++
	start := len(b.buf)
	b.buf = append(b.buf, e...)
	b.ents = append(b.ents, b.buf[start:])
	b.bytes += len(e)
	b.last = b.buf[start+w : start+w+int(kl)]
	if len(b.ents) >= fillEntries || b.bytes >= fillBytes {
		b.flush()
	}
	return true
}

func (b *builder) flush() {
	if len(b.ents) == 0 {
		return
	}
	l := &node{gen: b.gen, buf: make([]byte, 0, b.bytes), offs: make([]uint32, 1, len(b.ents)+1)}
	for _, e := range b.ents {
		l.buf = append(l.buf, e...)
		l.offs = append(l.offs, uint32(len(l.buf)))
	}
	b.leaves = append(b.leaves, l)
	b.last = l.key(l.len() - 1)
	b.ents, b.bytes, b.buf = b.ents[:0], 0, b.buf[:0]
}

func (b *builder) finish() tree {
	b.flush()
	if len(b.leaves) == 0 {
		return emptyTree()
	}
	level := b.leaves
	for len(level) > 1 {
		groups := (len(level) + fillChildren - 1) / fillChildren
		next := make([]*node, 0, groups)
		for g := range groups {
			lo, hi := g*len(level)/groups, (g+1)*len(level)/groups
			n := &node{gen: b.gen, keys: make([][]byte, 0, maxChildren), children: make([]*node, 0, maxChildren+1)}
			n.children = append(n.children, level[lo:hi]...)
			for _, c := range level[lo+1 : hi] {
				n.keys = append(n.keys, bytes.Clone(firstKey(c)))
			}
			next = append(next, n)
		}
		level = next
	}
	return tree{root: level[0], count: b.count}
}

func firstKey(n *node) []byte {
	for !n.isLeaf() {
		n = n.children[0]
	}
	return n.key(0)
}
