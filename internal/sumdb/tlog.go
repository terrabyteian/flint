package sumdb

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
)

// A checksum database's log is a Merkle tree over its records, as RFC
// 6962 defines it: a record's hash is the SHA-256 of a zero byte and the
// record, and a node's the SHA-256 of a one byte and its two children's
// hashes. The node at level l and index k covers records k·2^l through
// (k+1)·2^l-1, and is complete in a tree of n records if they all are in
// it. The hash of a tree of n = 2^a + 2^b + ... records, a > b > ..., is
// that of its complete subtrees from the left, joined from the right:
// the hash of the level-a node joined with the hash of the rest.
//
// The database serves the hashes of complete nodes in tiles of height 8:
// the tile at level t and index i holds those of the nodes at level 8t
// with indexes 256i through 256i+w-1, w hashes of 32 bytes. A full tile
// has 256, and the path "tile/8/<t>/<i>", where i is written in groups
// of three digits, all but the last prefixed with "x", as "x001/234". A
// partial tile, at the right edge of a tree, has fewer, and its path
// ends ".p/<w>"; once the tile fills, the database may serve only the
// full tile, whose hashes start with the partial tile's.
//
// The partial tiles of a tree hold the hashes of its complete subtrees,
// so they are authentic once they compute the hash of a tree head the
// database signed. A full tile is then authentic once its hashes compute
// the node the tile above it holds, which is authentic in turn.

// Hash is the hash of a record or node of a checksum database's log.
type Hash [sha256.Size]byte

// recordHash returns the hash of a record.
func recordHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	var x Hash
	h.Sum(x[:0])
	return x
}

// nodeHash returns the hash of a node with children left and right.
func nodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left[:])
	h.Write(right[:])
	var x Hash
	h.Sum(x[:0])
	return x
}

// The height and width of a tile.
const (
	tileHeight = 8
	tileWidth  = 1 << tileHeight
)

// A TileReader reads the tile at path below a checksum database's URL,
// such as "tile/8/0/x001/234", or "tile/8/1/007.p/12" for a partial
// tile. check verifies a full tile: a reader that caches tiles caches
// one only once check passes. A partial tile, and a full tile read in
// place of one, are verified only together with other tiles, so they
// come without a check, and are never cached.
type TileReader func(ctx context.Context, path string, check func([]byte) error) ([]byte, error)

// tilePath returns the path of the tile at level t and index i, with w
// hashes.
func tilePath(t int, i int64, w int) string {
	s := fmt.Sprintf("%03d", i%1000)
	for i /= 1000; i > 0; i /= 1000 {
		s = fmt.Sprintf("x%03d/", i%1000) + s
	}
	p := "tile/" + strconv.Itoa(tileHeight) + "/" + strconv.Itoa(t) + "/" + s
	if w < tileWidth {
		p += ".p/" + strconv.Itoa(w)
	}
	return p
}

// parseTile returns the first w hashes of a tile, which must have w if
// it is partial or tileWidth if it is full.
func parseTile(b []byte, w int, path string) ([]Hash, error) {
	if len(b) != w*sha256.Size && len(b) != tileWidth*sha256.Size {
		return nil, fmt.Errorf("%w: the tile %s has %d bytes, not %d hashes", ErrBadNote, path, len(b), w)
	}
	hs := make([]Hash, w)
	for i := range hs {
		copy(hs[i][:], b[i*sha256.Size:])
	}
	return hs, nil
}

// subtreeHash returns the hash of the node whose descendants at some
// level have hashes hs, a power of two of them.
func subtreeHash(hs []Hash) Hash {
	hs = append([]Hash(nil), hs...)
	for n := len(hs); n > 1; n /= 2 {
		for i := 0; i < n/2; i++ {
			hs[i] = nodeHash(hs[2*i], hs[2*i+1])
		}
	}
	return hs[0]
}

// tileID names a tile by its level and index.
type tileID struct {
	level int
	index int64
}

// A Prover reads the authentic hashes of a tree's nodes from the
// database's tiles, to check that the tree contains records and is
// consistent with smaller trees of the database. It keeps the tree's
// partial tiles, which it reads once; full tiles never change, so it
// reads them again when a proof needs them, from a reader that caches
// them. It is safe for concurrent use.
type Prover struct {
	tree  Tree
	read  TileReader
	tiles map[tileID][]Hash // the partial tiles, by level and index
}

// NewProver returns the Prover of tree, a tree head the database
// signed, reading tiles with read: it reads the tree's partial tiles,
// and checks that they compute the tree's hash.
func NewProver(ctx context.Context, tree Tree, read TileReader) (*Prover, error) {
	p := &Prover{tree: tree, read: read, tiles: map[tileID][]Hash{}}
	for t := 0; tree.N>>(tileHeight*t) > 0; t++ {
		nodes := tree.N >> (tileHeight * t)
		w := int(nodes % tileWidth)
		if w == 0 {
			continue
		}
		i := nodes / tileWidth
		path := tilePath(t, i, w)
		b, err := read(ctx, path, nil)
		if err != nil {
			var ferr error
			if b, ferr = read(ctx, tilePath(t, i, tileWidth), nil); ferr != nil {
				return nil, err
			}
		}
		if p.tiles[tileID{t, i}], err = parseTile(b, w, path); err != nil {
			return nil, err
		}
	}
	h, err := p.treeHash(ctx, tree.N)
	if err != nil {
		return nil, err
	}
	if h != tree.Hash {
		return nil, fmt.Errorf("%w: the tiles of the tree of %d records do not compute its hash", ErrBadNote, tree.N)
	}
	return p, nil
}

// Tree returns the tree p proves.
func (p *Prover) Tree() Tree { return p.tree }

// Includes checks that p's tree contains record r.
func (p *Prover) Includes(ctx context.Context, r *Record) error {
	if r.ID >= p.tree.N {
		return fmt.Errorf("%w: record %d is not in a tree of %d records", ErrBadNote, r.ID, p.tree.N)
	}
	h, err := p.node(ctx, 0, r.ID)
	if err != nil {
		return err
	}
	if h != recordHash(r.data) {
		return fmt.Errorf("%w: record %d of the tree of %d records is not the record of %s@%s", ErrBadNote,
			r.ID, p.tree.N, r.Path, r.Version)
	}
	return nil
}

// Consistent checks that older, a tree head the database signed with
// no more records than p's tree, is of the same log: its records are the
// start of p's tree.
func (p *Prover) Consistent(ctx context.Context, older Tree) error {
	if older.N > p.tree.N {
		return fmt.Errorf("sumdb: the tree of %d records cannot prove the tree of %d records", p.tree.N, older.N)
	}
	h, err := p.treeHash(ctx, older.N)
	if err != nil {
		return err
	}
	if h != older.Hash {
		return fmt.Errorf("%w: the tree of %d records is not the start of the tree of %d records", ErrBadNote,
			older.N, p.tree.N)
	}
	return nil
}

// treeHash returns the hash of the tree of p's first n records, from
// its complete subtrees, which are p's complete nodes; the empty tree's
// hash is zero.
func (p *Prover) treeHash(ctx context.Context, n int64) (Hash, error) {
	var h Hash
	end := n
	for l := 0; end > 0; l++ {
		if n&(1<<l) == 0 {
			continue
		}
		end -= 1 << l
		x, err := p.node(ctx, l, end>>l)
		if err != nil {
			return Hash{}, err
		}
		if end+1<<l == n {
			h = x
		} else {
			h = nodeHash(x, h)
		}
	}
	return h, nil
}

// node returns the hash of the complete node at level l and index k,
// from the tile that holds its descendants at the level of tiles below
// it.
func (p *Prover) node(ctx context.Context, l int, k int64) (Hash, error) {
	if k >= p.tree.N>>l {
		return Hash{}, fmt.Errorf("sumdb: the node %d at level %d is not complete in a tree of %d records", k, l, p.tree.N)
	}
	t, s := l/tileHeight, l%tileHeight
	first := k << s
	hs, err := p.tile(ctx, t, first/tileWidth)
	if err != nil {
		return Hash{}, err
	}
	i := int(first % tileWidth)
	return subtreeHash(hs[i : i+1<<s]), nil
}

// tile returns the hashes of the tile at level t and index i of p's
// tree: a partial tile NewProver read, or a full tile, read and checked
// against the node the tile above it holds.
func (p *Prover) tile(ctx context.Context, t int, i int64) ([]Hash, error) {
	if hs, ok := p.tiles[tileID{t, i}]; ok {
		return hs, nil
	}
	want, err := p.node(ctx, (t+1)*tileHeight, i)
	if err != nil {
		return nil, err
	}
	path := tilePath(t, i, tileWidth)
	check := func(b []byte) error {
		hs, err := parseTile(b, tileWidth, path)
		if err == nil && subtreeHash(hs) != want {
			err = fmt.Errorf("%w: the tile %s is not of the tree of %d records", ErrBadNote, path, p.tree.N)
		}
		return err
	}
	b, err := p.read(ctx, path, check)
	if err == nil {
		// A reader may return a tile it cached before without checking.
		err = check(b)
	}
	if err != nil {
		return nil, err
	}
	hs, _ := parseTile(b, tileWidth, path)
	return hs, nil
}
