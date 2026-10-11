package cargo

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// Metadata keys. Every key starts with the package's namespace, and parts
// are separated by 0x00, which cannot occur in a repository name, a crate
// name, or a version:
//
//	cargo\0crate\0<repo>\0<normalized name>              hosted crate: its name as first published; kept
//	                                                     forever, and rewritten by every change to the
//	                                                     crate, so its version is the index file's ETag
//	cargo\0version\0<repo>\0<normalized name>\0<version>  hosted version: its index line, .crate digest and
//	                                                     size, publish time; kept as a tombstone after delete
//
// <normalized name> is the crate name lowercase with "-" and "_" equal
// (Normalize), and <version> the version without build metadata, so names
// and versions that crates.io would take for the same collide by
// precondition. The digest a live version record holds is a blob garbage
// collection must keep; a tombstone holds none. Proxy repositories keep
// what they cache in the shared proxy cache (upstream.Marks): index files
// and the upstream's config.json under cache\0doc, .crate files under
// cache\0file.
const (
	nsCrate   = "cargo\x00crate\x00"
	nsVersion = "cargo\x00version\x00"

	recordFormat = 1 // the schema version byte that starts every value
)

func key(ns string, parts ...string) []byte {
	n := len(ns)
	for _, p := range parts {
		n += len(p) + 1
	}
	b := make([]byte, 0, n)
	b = append(b, ns...)
	for i, p := range parts {
		if i > 0 {
			b = append(b, 0)
		}
		b = append(b, p...)
	}
	return b
}

func crateKey(repo, norm string) []byte       { return key(nsCrate, repo, norm) }
func versionKey(repo, norm, vk string) []byte { return key(nsVersion, repo, norm, vk) }
func versionsPrefix(repo, norm string) []byte { return append(key(nsVersion, repo, norm), 0) }

var errBadRecord = errors.New("cargo: malformed metadata record")

// enc builds a record value.
type enc []byte

func newEnc() enc                  { return enc{recordFormat} }
func (e enc) uvarint(v uint64) enc { return binary.AppendUvarint(e, v) }
func (e enc) varint(v int64) enc   { return binary.AppendVarint(e, v) }
func (e enc) str(s string) enc     { return append(e.uvarint(uint64(len(s))), s...) }
func (e enc) bytes(b []byte) enc   { return append(e.uvarint(uint64(len(b))), b...) }

// digest appends d, or a zero byte for the zero digest.
func (e enc) digest(d blob.Digest) enc {
	if d.IsZero() {
		return append(e, 0)
	}
	sum, _ := hex.DecodeString(d.Hex())
	return append(append(e, 1), sum...)
}

func (e enc) time(t time.Time) enc {
	if t.IsZero() {
		return e.varint(0)
	}
	return e.varint(t.UnixNano())
}

// dec reads a record value. Errors are sticky: after the first, every
// read returns a zero value and done reports the failure.
type dec struct {
	b   []byte
	err error
}

func newDec(b []byte) *dec {
	d := &dec{b: b}
	if len(b) == 0 || b[0] != recordFormat {
		d.err = errBadRecord
		return d
	}
	d.b = b[1:]
	return d
}

func (d *dec) uvarint() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.err = errBadRecord
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *dec) varint() int64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.err = errBadRecord
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *dec) raw(n uint64) []byte {
	if d.err != nil {
		return nil
	}
	if n > uint64(len(d.b)) {
		d.err = errBadRecord
		return nil
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v
}

func (d *dec) str() string   { return string(d.raw(d.uvarint())) }
func (d *dec) bytes() []byte { return append([]byte(nil), d.raw(d.uvarint())...) }

func (d *dec) time() time.Time {
	if n := d.varint(); n != 0 {
		return time.Unix(0, n).UTC()
	}
	return time.Time{}
}

func (d *dec) digest() blob.Digest {
	b := d.raw(1)
	if b == nil || b[0] == 0 {
		return blob.Digest{}
	}
	sum := d.raw(32)
	if sum == nil {
		return blob.Digest{}
	}
	dg, err := blob.ParseDigest("sha256:" + hex.EncodeToString(sum))
	if err != nil {
		d.err = errBadRecord
	}
	return dg
}

// done returns the decoding error, or an error if bytes are left over.
func (d *dec) done() error {
	if d.err == nil && len(d.b) != 0 {
		d.err = errBadRecord
	}
	return d.err
}

// crateRecord is a hosted crate. It is created by the first publish and
// kept forever, also once every version is deleted, so the repository
// keeps owning the name and its spelling.
type crateRecord struct {
	Name    string // as first published
	Created time.Time
}

func (c *crateRecord) encode() []byte { return newEnc().str(c.Name).time(c.Created) }

func decodeCrate(b []byte) (*crateRecord, error) {
	d := newDec(b)
	c := &crateRecord{Name: d.str(), Created: d.time()}
	if err := d.done(); err != nil {
		return nil, err
	}
	return c, nil
}

// Version record kinds.
const (
	kindLive      = 1 // a published version, yanked or not
	kindTombstone = 2 // a deleted version, which can never be published again
)

// versionRecord is a published version of a hosted crate, or the
// tombstone of a deleted one, which keeps only Kind, Vers, and Deleted.
type versionRecord struct {
	Kind byte
	Vers string // as published, with any build metadata
	// Line is the version's index line, JSON, with its yanked field.
	Line        []byte
	Digest      blob.Digest // the .crate file's
	Size        int64
	Published   time.Time
	Description string
	Deleted     time.Time
}

func (v *versionRecord) encode() []byte {
	e := append(newEnc(), v.Kind).str(v.Vers)
	if v.Kind == kindTombstone {
		return e.time(v.Deleted)
	}
	return e.bytes(v.Line).digest(v.Digest).uvarint(uint64(v.Size)).time(v.Published).str(v.Description)
}

func decodeVersion(b []byte) (*versionRecord, error) {
	d := newDec(b)
	v := &versionRecord{}
	if k := d.raw(1); k != nil {
		v.Kind = k[0]
	}
	v.Vers = d.str()
	switch v.Kind {
	case kindTombstone:
		v.Deleted = d.time()
	case kindLive:
		v.Line, v.Digest, v.Size, v.Published, v.Description = d.bytes(), d.digest(), int64(d.uvarint()), d.time(), d.str()
	default:
		return nil, errBadRecord
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	if v.Kind == kindLive && v.Digest.IsZero() {
		return nil, errBadRecord
	}
	return v, nil
}

// References calls fn, until it returns an error, with the digest of each
// .crate file a hosted Cargo repository holds in v. A tombstone holds
// none. What proxy repositories cache is in the shared proxy cache, which
// upstream.References reports.
func References(v meta.View, fn func(blob.Digest) error) error {
	var err error
	v.Scan([]byte(nsVersion), nil, func(k []byte, rec meta.Record) bool {
		vr, derr := decodeVersion(rec.Value)
		if derr != nil {
			err = fmt.Errorf("cargo: metadata key %q: %w", k, derr)
			return false
		}
		if vr.Kind == kindLive {
			err = fn(vr.Digest)
		}
		return err == nil
	})
	return err
}
