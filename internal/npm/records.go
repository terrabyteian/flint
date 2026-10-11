package npm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// Metadata keys. Every key starts with the package's namespace, and parts
// are separated by 0x00, which cannot occur in a repository name, a
// package name, or a version:
//
//	npm\0pkg\0<repo>\0<name>                 hosted package: its dist-tags, times, and readme;
//	                                         kept forever, so the repository keeps owning the name
//	npm\0version\0<repo>\0<name>\0<version>  hosted version: its manifest, tarball, and digests;
//	                                         kept as a tombstone after unpublish
//
// The package record's version in the metadata store is the package's
// _rev. The digests that live records hold are blobs garbage collection
// must keep; a tombstone holds none.
const (
	nsPkg     = "npm\x00pkg\x00"
	nsVersion = "npm\x00version\x00"

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

func pkgKey(repo, name string) []byte              { return key(nsPkg, repo, name) }
func versionKey(repo, name, version string) []byte { return key(nsVersion, repo, name, version) }
func versionPrefix(repo, name string) []byte       { return append(key(nsVersion, repo, name), 0) }

var errBadRecord = errors.New("npm: malformed metadata record")

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
func (d *dec) byte() byte {
	if b := d.raw(1); b != nil {
		return b[0]
	}
	return 0
}

func (d *dec) time() time.Time {
	if n := d.varint(); n != 0 {
		return time.Unix(0, n).UTC()
	}
	return time.Time{}
}

func (d *dec) digest() blob.Digest {
	if d.byte() != 1 {
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

// distTag is a dist-tag: a name that points at a version.
type distTag struct {
	Tag, Version string
}

// pkgRecord is a hosted package. It is created by the first publish and
// kept forever, also once every version is unpublished, so the
// repository keeps owning the name. A package has a "latest" dist-tag
// exactly when it has a live version.
type pkgRecord struct {
	Created  time.Time
	Modified time.Time
	Tags     []distTag // sorted by tag
	// Readme is the readme published last, a blob of ReadmeSize bytes,
	// or zero if no version had one.
	Readme         blob.Digest
	ReadmeSize     int64
	ReadmeFilename string
}

func (p *pkgRecord) encode() []byte {
	e := newEnc().time(p.Created).time(p.Modified).uvarint(uint64(len(p.Tags)))
	for _, t := range p.Tags {
		e = e.str(t.Tag).str(t.Version)
	}
	return e.digest(p.Readme).uvarint(uint64(p.ReadmeSize)).str(p.ReadmeFilename)
}

func decodePkg(b []byte) (*pkgRecord, error) {
	d := newDec(b)
	p := &pkgRecord{Created: d.time(), Modified: d.time()}
	n := d.uvarint()
	if n > uint64(len(b)) {
		return nil, errBadRecord
	}
	for range n {
		p.Tags = append(p.Tags, distTag{d.str(), d.str()})
	}
	p.Readme, p.ReadmeSize, p.ReadmeFilename = d.digest(), int64(d.uvarint()), d.str()
	if err := d.done(); err != nil {
		return nil, err
	}
	return p, nil
}

// tag returns the version tag points at, or "".
func (p *pkgRecord) tag(tag string) string {
	if i, ok := slices.BinarySearchFunc(p.Tags, tag, func(t distTag, s string) int { return strings.Compare(t.Tag, s) }); ok {
		return p.Tags[i].Version
	}
	return ""
}

// setTag points tag at version, or removes it if version is "".
func (p *pkgRecord) setTag(tag, version string) {
	i, ok := slices.BinarySearchFunc(p.Tags, tag, func(t distTag, s string) int { return strings.Compare(t.Tag, s) })
	switch {
	case ok && version == "":
		p.Tags = slices.Delete(p.Tags, i, i+1)
	case ok:
		p.Tags[i].Version = version
	case version != "":
		p.Tags = slices.Insert(p.Tags, i, distTag{tag, version})
	}
}

// Version record kinds.
const (
	kindLive      = 1 // a published version
	kindTombstone = 2 // an unpublished version, which can never be published again
)

// versionRecord is a published version, or the tombstone it leaves when
// it is unpublished, which keeps only Kind, Published, and Unpublished.
type versionRecord struct {
	Kind byte
	// Manifest is the version's manifest, the package.json document npm
	// published, without the fields flint sets itself (dist, deprecated)
	// and the readme: a JSON object of ManifestSize bytes.
	Manifest     blob.Digest
	ManifestSize int64
	// Tarball is the package tarball, Size bytes, with its sha512 and
	// sha1 digests, which npm checks as dist.integrity and dist.shasum.
	Tarball    blob.Digest
	Size       int64
	SHA512     []byte
	SHA1       []byte
	Published  time.Time
	Deprecated string
	// Provenance is the Sigstore bundle published with the version, a
	// blob of ProvenanceSize bytes, and PredicateType the type of its
	// attestation; zero and "" without one.
	Provenance     blob.Digest
	ProvenanceSize int64
	PredicateType  string
	Unpublished    time.Time
}

func (r *versionRecord) encode() []byte {
	e := append(newEnc(), r.Kind)
	if r.Kind == kindTombstone {
		return e.time(r.Published).time(r.Unpublished)
	}
	e = e.digest(r.Manifest).uvarint(uint64(r.ManifestSize))
	e = e.digest(r.Tarball).uvarint(uint64(r.Size)).bytes(r.SHA512).bytes(r.SHA1)
	e = e.time(r.Published).str(r.Deprecated)
	return e.digest(r.Provenance).uvarint(uint64(r.ProvenanceSize)).str(r.PredicateType)
}

func decodeVersion(b []byte) (*versionRecord, error) {
	d := newDec(b)
	r := &versionRecord{Kind: d.byte()}
	switch r.Kind {
	case kindTombstone:
		r.Published, r.Unpublished = d.time(), d.time()
	case kindLive:
		r.Manifest, r.ManifestSize = d.digest(), int64(d.uvarint())
		r.Tarball, r.Size, r.SHA512, r.SHA1 = d.digest(), int64(d.uvarint()), d.bytes(), d.bytes()
		r.Published, r.Deprecated = d.time(), d.str()
		r.Provenance, r.ProvenanceSize, r.PredicateType = d.digest(), int64(d.uvarint()), d.str()
	default:
		return nil, errBadRecord
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	return r, nil
}

// refs returns the blobs a version record references: none for a
// tombstone.
func (r *versionRecord) refs() []blob.Digest {
	if r.Kind == kindTombstone {
		return nil
	}
	return nonZero(r.Manifest, r.Tarball, r.Provenance)
}

// nonZero returns the digests of ds that are not zero.
func nonZero(ds ...blob.Digest) []blob.Digest {
	out := ds[:0]
	for _, d := range ds {
		if !d.IsZero() {
			out = append(out, d)
		}
	}
	return out
}

// References calls fn, until it returns an error, with the digest of each
// blob that v links into an npm repository: every live version's
// manifest, tarball, and provenance bundle, and every package's readme. A
// tombstone links none. A digest linked in several places is reported
// once for each.
func References(v meta.View, fn func(blob.Digest) error) error {
	var err error
	for ns, refs := range GCMarker() {
		v.Scan([]byte(ns), nil, func(k []byte, rec meta.Record) bool {
			ds, derr := refs(k, rec.Value)
			if derr != nil {
				err = fmt.Errorf("npm: metadata key %q: %w", k, derr)
				return false
			}
			for _, d := range ds {
				if err = fn(d); err != nil {
					return false
				}
			}
			return true
		})
		if err != nil {
			return err
		}
	}
	return nil
}
