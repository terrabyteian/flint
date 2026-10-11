package maven

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// Metadata keys of hosted repositories. Every key starts with the
// package's namespace, and parts are separated by 0x00, which cannot
// occur in a repository name, a path, or a coordinate:
//
//	maven\0file\0<repo>\0<path>                              file: digest, size, md5, sha1,
//	                                                         sha512, upload time; kept as a
//	                                                         tombstone after delete
//	maven\0version\0<repo>\0<groupId>\0<artifactId>\0<version>  version index: first and last
//	                                                         upload, snapshot flag, latest
//	                                                         snapshot timestamp and build,
//	                                                         live files; kept forever
//	maven\0plugin\0<repo>\0<groupId>\0<artifactId>           plugin prefix and name, from
//	                                                         group-level metadata
//
// Proxy repositories cache files and maven-metadata.xml in the shared
// proxy cache (cache\0file and cache\0doc), which upstream.Marks
// covers. The digest a live file record holds is a blob garbage
// collection must keep; a tombstone holds none, and version and plugin
// records reference no blob.
const (
	nsFile    = "maven\x00file\x00"
	nsVersion = "maven\x00version\x00"
	nsPlugin  = "maven\x00plugin\x00"

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

func fileKey(repo, path string) []byte { return key(nsFile, repo, path) }
func versionKey(repo, group, artifact, version string) []byte {
	return key(nsVersion, repo, group, artifact, version)
}

// versionPrefix is the prefix of an artifact's version keys.
func versionPrefix(repo, group, artifact string) []byte {
	return append(key(nsVersion, repo, group, artifact), 0)
}

func pluginKey(repo, group, artifact string) []byte { return key(nsPlugin, repo, group, artifact) }

// pluginPrefix is the prefix of a group's plugin keys.
func pluginPrefix(repo, group string) []byte { return append(key(nsPlugin, repo, group), 0) }

var errBadRecord = errors.New("maven: malformed metadata record")

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

// File record kinds.
const (
	kindLive      = 1 // a hosted file
	kindTombstone = 2 // a deleted hosted file, whose name can never be used again
)

// fileRecord is a hosted file, or a tombstone, which keeps only Kind and
// Deleted.
type fileRecord struct {
	Kind   byte
	Digest blob.Digest
	Size   int64
	// MD5, SHA1, and SHA512 are the raw digests computed at upload, for
	// checksum sidecars and headers.
	MD5, SHA1, SHA512 []byte
	Uploaded          time.Time
	Deleted           time.Time
}

func (f *fileRecord) encode() []byte {
	e := append(newEnc(), f.Kind)
	if f.Kind == kindTombstone {
		return e.time(f.Deleted)
	}
	return e.digest(f.Digest).uvarint(uint64(f.Size)).bytes(f.MD5).bytes(f.SHA1).bytes(f.SHA512).time(f.Uploaded)
}

func decodeFile(b []byte) (*fileRecord, error) {
	d := newDec(b)
	f := &fileRecord{}
	if k := d.raw(1); k != nil {
		f.Kind = k[0]
	}
	switch f.Kind {
	case kindTombstone:
		f.Deleted = d.time()
	case kindLive:
		f.Digest, f.Size = d.digest(), int64(d.uvarint())
		f.MD5, f.SHA1, f.SHA512, f.Uploaded = d.bytes(), d.bytes(), d.bytes(), d.time()
		if d.err == nil && f.Digest.IsZero() {
			d.err = errBadRecord
		}
	default:
		if d.err == nil {
			d.err = errBadRecord
		}
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	return f, nil
}

// versionRecord indexes a version of an artifact in a hosted repository,
// for metadata generation and ownership. It is written by the version's
// first upload and kept forever, also once every file is deleted, so the
// repository keeps owning the artifact.
type versionRecord struct {
	Created  time.Time // the first upload
	Updated  time.Time // the last upload
	Snapshot bool
	// Timestamp and Build are the latest timestamped snapshot file's.
	Timestamp string
	Build     int
	// Files is the number of live files of the version, which metadata
	// lists only while it is positive.
	Files int
}

func (v *versionRecord) encode() []byte {
	return newEnc().time(v.Created).time(v.Updated).bool(v.Snapshot).str(v.Timestamp).uvarint(uint64(v.Build)).
		uvarint(uint64(v.Files))
}

func decodeVersion(b []byte) (*versionRecord, error) {
	d := newDec(b)
	v := &versionRecord{Created: d.time(), Updated: d.time(), Snapshot: d.bool(), Timestamp: d.str(),
		Build: int(d.uvarint()), Files: int(d.uvarint())}
	if err := d.done(); err != nil {
		return nil, err
	}
	return v, nil
}

// pluginRecord is a Maven plugin's entry in its group's metadata.
type pluginRecord struct {
	Prefix, Name string
}

func (p *pluginRecord) encode() []byte { return newEnc().str(p.Prefix).str(p.Name) }

func decodePlugin(b []byte) (*pluginRecord, error) {
	d := newDec(b)
	p := &pluginRecord{Prefix: d.str(), Name: d.str()}
	return p, d.done()
}

// References calls fn, until it returns an error, with the digest of each
// blob a live file of a hosted Maven repository links. A tombstone links
// none. Files and metadata proxy repositories cached are in the shared
// proxy cache, which upstream.References reports.
func References(v meta.View, fn func(blob.Digest) error) error {
	var err error
	v.Scan([]byte(nsFile), nil, func(k []byte, rec meta.Record) bool {
		f, derr := decodeFile(rec.Value)
		if derr != nil {
			err = fmt.Errorf("maven: metadata key %q: %w", k, derr)
			return false
		}
		if f.Kind == kindLive {
			err = fn(f.Digest)
		}
		return err == nil
	})
	return err
}
