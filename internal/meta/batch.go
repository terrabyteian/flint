package meta

import "bytes"

// Batch is a set of operations committed atomically. A Batch copies the
// keys and values it is given. It must not be changed while a Commit of it
// is in progress.
type Batch struct {
	ops    []Op
	reqs   []require
	origin Origin
	size   int // encoded size of ops, approximately
}

type require struct {
	key []byte
	v   Seq
}

// Put sets key to value.
func (b *Batch) Put(key, value []byte) {
	v := bytes.Clone(value)
	if v == nil {
		v = []byte{}
	}
	b.ops = append(b.ops, Op{Key: bytes.Clone(key), Value: v})
	b.size += len(key) + len(value) + 11
}

// Delete removes key. Deleting an absent key is not an error.
func (b *Batch) Delete(key []byte) {
	b.ops = append(b.ops, Op{Delete: true, Key: bytes.Clone(key)})
	b.size += len(key) + 6
}

// Require adds a precondition: key must be at version v, where 0 means absent.
// Preconditions are checked against the state before the batch's own operations.
func (b *Batch) Require(key []byte, v Seq) {
	b.reqs = append(b.reqs, require{key: bytes.Clone(key), v: v})
}

// SetOrigin records who made the change, why, and to what, for the audit log.
func (b *Batch) SetOrigin(o Origin) { b.origin = o }

// Len reports the number of operations in the batch.
func (b *Batch) Len() int { return len(b.ops) }
