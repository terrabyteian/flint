package oci

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// Metadata keys. Every key starts with its owner's namespace, and parts are
// separated by 0x00, which cannot occur in a repository name, tag, or
// digest, so a prefix scan never matches a longer name:
//
//	oci\0blob\0<repo>\0<name>\0<digest>                     blob link
//	oci\0manifest\0<repo>\0<name>\0<digest>                 manifest record
//	oci\0tag\0<repo>\0<name>\0<tag>                         tag: manifest digest
//	oci\0referrer\0<repo>\0<name>\0<subject>\0<digest>      referrer index entry
//	oci\0upload\0<id>                                       upload session
//
// <repo> is the configured repository and <name> the image name below it,
// so "docker-local/team/app" is repo "docker-local", name "team/app".
// Every link batch also reads the garbage collector's keys (gc.Guard), and
// GCMarker tells the garbage collector what each record references.
const (
	nsBlob     = "oci\x00blob\x00"
	nsManifest = "oci\x00manifest\x00"
	nsTag      = "oci\x00tag\x00"
	nsReferrer = "oci\x00referrer\x00"
	nsUpload   = "oci\x00upload\x00"

	recordFormat = 1 // the schema version byte that starts every value
)

// prefix returns ns + repo \0 name \0.
func prefix(ns string, r *repoName) []byte {
	b := make([]byte, 0, len(ns)+len(r.repo)+len(r.name)+2+72)
	b = append(b, ns...)
	b = append(b, r.repo...)
	b = append(b, 0)
	b = append(b, r.name...)
	return append(b, 0)
}

func blobKey(r *repoName, d blob.Digest) []byte {
	return append(prefix(nsBlob, r), d.String()...)
}

func manifestKey(r *repoName, d blob.Digest) []byte {
	return append(prefix(nsManifest, r), d.String()...)
}

func tagKey(r *repoName, tag string) []byte { return append(prefix(nsTag, r), tag...) }

func referrerPrefix(r *repoName, subject blob.Digest) []byte {
	return append(append(prefix(nsReferrer, r), subject.String()...), 0)
}

func referrerKey(r *repoName, subject, d blob.Digest) []byte {
	return append(referrerPrefix(r, subject), d.String()...)
}

func uploadKey(id string) []byte { return []byte(nsUpload + id) }

var errBadRecord = errors.New("oci: malformed metadata record")

// enc builds a record value.
type enc []byte

func newEnc() enc                  { return enc{recordFormat} }
func (e enc) uvarint(v uint64) enc { return binary.AppendUvarint(e, v) }
func (e enc) varint(v int64) enc   { return binary.AppendVarint(e, v) }
func (e enc) str(s string) enc     { return append(e.uvarint(uint64(len(s))), s...) }
func (e enc) digest(d blob.Digest) enc {
	sum, _ := hex.DecodeString(d.Hex())
	return append(e, sum...)
}

// dec reads a record value. Errors are sticky: after the first, every
// read returns a zero value and err reports the failure.
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

func (d *dec) bytes(n uint64) []byte {
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

func (d *dec) str() string { return string(d.bytes(d.uvarint())) }

func (d *dec) byte() byte {
	b := d.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (d *dec) digest() blob.Digest {
	sum := d.bytes(32)
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

// A blob link makes a committed blob visible in one repository name. Its
// value records the blob's size, so HEAD needs no filesystem access.
func encodeBlobLink(size int64) []byte { return newEnc().uvarint(uint64(size)) }

func decodeBlobLink(b []byte) (size int64, err error) {
	d := newDec(b)
	size = int64(d.uvarint())
	return size, d.done()
}

// A tag record holds the digest of the manifest the tag points to.
func encodeTag(d blob.Digest) []byte { return newEnc().digest(d) }

func decodeTag(b []byte) (blob.Digest, error) {
	d := newDec(b)
	dg := d.digest()
	return dg, d.done()
}

// refKind says what a manifest references: a blob or a child manifest.
type refKind byte

const (
	refBlob     refKind = 0
	refManifest refKind = 1
)

// manifestRecord describes a manifest stored in a repository name. The
// manifest's bytes are a blob, stored under the manifest's digest.
type manifestRecord struct {
	MediaType    string
	Size         int64
	ArtifactType string      // reported by the referrers API
	Subject      blob.Digest // zero if the manifest has no subject
	Annotations  string      // the manifest's annotations as a JSON object, or ""
	Refs         []manifestRef
}

// manifestRef is a blob or child manifest a manifest references; garbage
// collection marks these.
type manifestRef struct {
	Kind   refKind
	Digest blob.Digest
}

func (m *manifestRecord) encode() []byte {
	e := newEnc().str(m.MediaType).uvarint(uint64(m.Size)).str(m.ArtifactType)
	if m.Subject.IsZero() {
		e = append(e, 0)
	} else {
		e = append(e, 1).digest(m.Subject)
	}
	e = e.str(m.Annotations).uvarint(uint64(len(m.Refs)))
	for _, r := range m.Refs {
		e = append(e, byte(r.Kind)).digest(r.Digest)
	}
	return e
}

func decodeManifest(b []byte) (*manifestRecord, error) {
	d := newDec(b)
	m := &manifestRecord{MediaType: d.str(), Size: int64(d.uvarint()), ArtifactType: d.str()}
	if d.byte() == 1 {
		m.Subject = d.digest()
	}
	m.Annotations = d.str()
	n := d.uvarint()
	if n > uint64(len(d.b))/33 {
		return nil, errBadRecord
	}
	m.Refs = make([]manifestRef, 0, n)
	for range n {
		m.Refs = append(m.Refs, manifestRef{Kind: refKind(d.byte()), Digest: d.digest()})
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	return m, nil
}

// An upload session ties a blob store upload to the repository name it was
// started in, and records when, so abandoned sessions can expire.
type uploadRecord struct {
	Name    string // full repository name
	Started time.Time
}

func (u *uploadRecord) encode() []byte {
	return newEnc().varint(u.Started.UnixNano()).str(u.Name)
}

func decodeUpload(b []byte) (*uploadRecord, error) {
	d := newDec(b)
	u := &uploadRecord{Started: time.Unix(0, d.varint())}
	u.Name = d.str()
	if err := d.done(); err != nil {
		return nil, err
	}
	return u, nil
}

// References calls fn, until it returns an error, with the digest of each
// blob that v links into an OCI repository, hosted or proxy: every blob
// link and every manifest, whose bytes are a blob too. A manifest is
// stored only once everything it references is linked in its repository,
// so these are all the blobs OCI repositories need. A digest linked in
// several repositories is reported once for each.
func References(v meta.View, fn func(blob.Digest) error) error {
	var err error
	for _, ns := range []string{nsBlob, nsManifest} {
		v.Scan([]byte(ns), nil, func(k []byte, _ meta.Record) bool {
			i := bytes.LastIndexByte(k, 0)
			d, perr := blob.ParseDigest(string(k[i+1:]))
			if perr != nil {
				err = fmt.Errorf("oci: metadata key %q: %w", k, perr)
				return false
			}
			err = fn(d)
			return err == nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
