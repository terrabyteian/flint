package pypi

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
)

// Metadata keys. Every key starts with the package's namespace, and parts
// are separated by 0x00, which cannot occur in a repository name, a
// normalized project name, or a file name:
//
//	pypi\0project\0<repo>\0<project>                hosted project: its display name; kept forever
//	pypi\0file\0<repo>\0<filename>                  hosted file, kept as a tombstone after delete;
//	                                                or a file a proxy repository cached
//	pypi\0index\0<repo>\0<project>\0<filename>      a hosted project's live files
//	pypi\0metadata\0<repo>\0<filename>              core-metadata file a proxy repository cached
//	pypi\0page\0<repo>\0<project>                   project page a proxy repository cached
//	pypi\0pulled\0file\0<repo>\0<filename>          last pull of a file cached by a size-limited proxy
//	pypi\0pulled\0metadata\0<repo>\0<filename>      last pull of a core-metadata file, likewise
//
// <project> is the PEP 503 normalized name. The digests that file, page,
// and metadata records hold are blobs garbage collection must keep; a
// tombstone holds none.
const (
	nsProject  = "pypi\x00project\x00"
	nsFile     = "pypi\x00file\x00"
	nsIndex    = "pypi\x00index\x00"
	nsMetadata = "pypi\x00metadata\x00"
	nsPage     = "pypi\x00page\x00"
	nsPulled   = "pypi\x00pulled\x00"

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

func projectKey(repo, project string) []byte     { return key(nsProject, repo, project) }
func fileKey(repo, filename string) []byte       { return key(nsFile, repo, filename) }
func metadataKey(repo, filename string) []byte   { return key(nsMetadata, repo, filename) }
func pageKey(repo, project string) []byte        { return key(nsPage, repo, project) }
func indexPrefix(repo, project string) []byte    { return append(key(nsIndex, repo, project), 0) }
func indexKey(repo, project, file string) []byte { return key(nsIndex, repo, project, file) }

// pulledKey returns the pull-time key of a cached item's key, which
// starts with "pypi\0".
func pulledKey(k []byte) []byte {
	return append([]byte(nsPulled), k[len("pypi\x00"):]...)
}

var errBadRecord = errors.New("pypi: malformed metadata record")

// enc builds a record value.
type enc []byte

func newEnc() enc                  { return enc{recordFormat} }
func (e enc) uvarint(v uint64) enc { return binary.AppendUvarint(e, v) }
func (e enc) varint(v int64) enc   { return binary.AppendVarint(e, v) }
func (e enc) str(s string) enc     { return append(e.uvarint(uint64(len(s))), s...) }
func (e enc) bytes(b []byte) enc   { return append(e.uvarint(uint64(len(b))), b...) }
func (e enc) bool(v bool) enc {
	if v {
		return append(e, 1)
	}
	return append(e, 0)
}

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
func (d *dec) bool() bool    { b := d.raw(1); return b != nil && b[0] == 1 }
func (d *dec) time() time.Time {
	if n := d.varint(); n != 0 {
		return time.Unix(0, n).UTC()
	}
	return time.Time{}
}

func (d *dec) digest() blob.Digest {
	if !d.bool() {
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

// projectRecord is a hosted project. It is created by the first upload
// and kept forever, also once every file is deleted, so the repository
// keeps owning the name.
type projectRecord struct {
	Name    string // the name as first uploaded
	Created time.Time
}

func (p *projectRecord) encode() []byte { return newEnc().str(p.Name).time(p.Created) }

func decodeProject(b []byte) (*projectRecord, error) {
	d := newDec(b)
	p := &projectRecord{Name: d.str(), Created: d.time()}
	return p, d.done()
}

// File record kinds.
const (
	kindHosted    = 1 // a live hosted file
	kindTombstone = 2 // a deleted hosted file, whose name can never be used again
	kindCached    = 3 // a file a proxy repository cached
)

// fileRecord is a hosted file, a tombstone, or a cached proxy file.
// Tombstones keep only Kind, Project, Version, and Deleted; cached files
// only Kind, Project, Digest, and Size.
type fileRecord struct {
	Kind    byte
	Project string
	Version string // as uploaded
	Digest  blob.Digest
	Size    int64
	MD5     []byte // 16 bytes, or nil
	Blake2b []byte // 32 bytes, or nil

	Uploaded       time.Time
	Deleted        time.Time
	RequiresPython string
	PackageType    string
	PythonVersion  string
	Yanked         bool
	YankedReason   string
	// Meta is the file's core metadata, a blob of MetaSize bytes: what
	// the distribution contains, or, when it holds none flint can read,
	// what the upload form said. MetaServed says whether it is served
	// as the PEP 658 metadata file, which only metadata from the
	// distribution itself is.
	Meta       blob.Digest
	MetaSize   int64
	MetaServed bool
}

func (f *fileRecord) encode() []byte {
	e := newEnc()
	e = append(e, f.Kind)
	e = e.str(f.Project)
	switch f.Kind {
	case kindTombstone:
		return e.str(f.Version).time(f.Deleted)
	case kindCached:
		return e.digest(f.Digest).uvarint(uint64(f.Size))
	}
	e = e.str(f.Version).digest(f.Digest).uvarint(uint64(f.Size)).bytes(f.MD5).bytes(f.Blake2b)
	e = e.time(f.Uploaded).str(f.RequiresPython).str(f.PackageType).str(f.PythonVersion)
	e = e.bool(f.Yanked).str(f.YankedReason)
	return e.digest(f.Meta).uvarint(uint64(f.MetaSize)).bool(f.MetaServed)
}

func decodeFile(b []byte) (*fileRecord, error) {
	d := newDec(b)
	f := &fileRecord{}
	if k := d.raw(1); k != nil {
		f.Kind = k[0]
	}
	f.Project = d.str()
	switch f.Kind {
	case kindTombstone:
		f.Version, f.Deleted = d.str(), d.time()
	case kindCached:
		f.Digest, f.Size = d.digest(), int64(d.uvarint())
	case kindHosted:
		f.Version, f.Digest, f.Size, f.MD5, f.Blake2b = d.str(), d.digest(), int64(d.uvarint()), d.bytes(), d.bytes()
		f.Uploaded, f.RequiresPython, f.PackageType, f.PythonVersion = d.time(), d.str(), d.str(), d.str()
		f.Yanked, f.YankedReason = d.bool(), d.str()
		f.Meta, f.MetaSize, f.MetaServed = d.digest(), int64(d.uvarint()), d.bool()
	default:
		return nil, errBadRecord
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	return f, nil
}

// blobRecord is a blob a proxy repository cached: a core-metadata file.
type blobRecord struct {
	Digest blob.Digest
	Size   int64
}

func (r *blobRecord) encode() []byte { return newEnc().digest(r.Digest).uvarint(uint64(r.Size)) }

func decodeBlobRecord(b []byte) (*blobRecord, error) {
	d := newDec(b)
	r := &blobRecord{Digest: d.digest(), Size: int64(d.uvarint())}
	if err := d.done(); err != nil {
		return nil, err
	}
	return r, nil
}

// pageRecord is a project page a proxy repository cached: a blob holding
// the page in flint's own form (see pageDoc), and the upstream's ETag for
// a conditional revalidation.
type pageRecord struct {
	Digest  blob.Digest
	Size    int64
	ETag    string
	Fetched time.Time
}

func (p *pageRecord) encode() []byte {
	return newEnc().digest(p.Digest).uvarint(uint64(p.Size)).str(p.ETag).time(p.Fetched)
}

func decodePage(b []byte) (*pageRecord, error) {
	d := newDec(b)
	p := &pageRecord{Digest: d.digest(), Size: int64(d.uvarint()), ETag: d.str(), Fetched: d.time()}
	if err := d.done(); err != nil {
		return nil, err
	}
	return p, nil
}
