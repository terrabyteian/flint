package upstream

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// Metadata keys of the shared proxy cache, which every format whose
// proxy uses DocCache or PathCache writes through them. Parts are
// separated by 0x00, which cannot occur in a repository name:
//
//	cache\0doc\0<repo>\0<key>            document a proxy repository cached (DocCache):
//	                                     blob digest, upstream ETag and Last-Modified,
//	                                     content type, URL, fetch time
//	cache\0file\0<repo>\0<path>          immutable file a proxy repository cached
//	                                     (PathCache): blob digest, size, content type,
//	                                     the other digests verified or computed
//	cache\0pulled\0file\0<repo>\0<path>  last pull of a file cached by a size-limited
//	                                     proxy repository
//
// <key> is chosen by the format and may itself contain 0x00. The digest
// a doc or file record holds is a blob garbage collection must keep;
// pulled records reference none. Marks and References report them.
const (
	NSDoc    = "cache\x00doc\x00"
	NSFile   = "cache\x00file\x00"
	NSPulled = "cache\x00pulled\x00"

	recordFormat = 1 // the schema version byte that starts every value
)

// DocKey returns the metadata key of document key of repository repo.
func DocKey(repo, key string) []byte { return []byte(NSDoc + repo + "\x00" + key) }

// FileKey returns the metadata key of the file at path of repository
// repo.
func FileKey(repo, path string) []byte { return []byte(NSFile + repo + "\x00" + path) }

// pulledKey returns the pull-time key of a file key.
func pulledKey(k []byte) []byte {
	return append([]byte(NSPulled), k[len("cache\x00"):]...)
}

// ErrBadRecord means a proxy cache record could not be decoded.
var ErrBadRecord = errors.New("upstream: malformed proxy cache record")

// DocRecord is a document a proxy repository cached: a blob holding the
// upstream's bytes verbatim, and what revalidating it needs.
type DocRecord struct {
	Digest       blob.Digest
	Size         int64
	ContentType  string
	ETag         string
	LastModified string
	// URL is where the document was fetched from, after redirects, which
	// relative links in it resolve against.
	URL     string
	Fetched time.Time
}

func (d *DocRecord) encode() []byte {
	return newEnc().digest(d.Digest).uvarint(uint64(d.Size)).str(d.ContentType).str(d.ETag).
		str(d.LastModified).str(d.URL).time(d.Fetched)
}

// DecodeDocRecord decodes a cache\0doc record.
func DecodeDocRecord(b []byte) (*DocRecord, error) {
	d := newDec(b)
	r := &DocRecord{Digest: d.digest(), Size: int64(d.uvarint()), ContentType: d.str(), ETag: d.str(),
		LastModified: d.str(), URL: d.str(), Fetched: d.time()}
	if err := d.done(); err != nil {
		return nil, err
	}
	if r.Digest.IsZero() {
		return nil, ErrBadRecord
	}
	return r, nil
}

// FileRecord is an immutable file a proxy repository cached.
type FileRecord struct {
	Digest      blob.Digest
	Size        int64
	ContentType string
	// Sums are the other digests verified or computed when the file was
	// fetched, by algorithm.
	Sums    Sums
	Fetched time.Time
}

func (f *FileRecord) encode() []byte {
	e := newEnc().digest(f.Digest).uvarint(uint64(f.Size)).str(f.ContentType).uvarint(uint64(len(f.Sums)))
	for _, alg := range slices.Sorted(func(yield func(string) bool) {
		for k := range f.Sums {
			if !yield(k) {
				return
			}
		}
	}) {
		e = e.str(alg).bytes(f.Sums[alg])
	}
	return e.time(f.Fetched)
}

// DecodeFileRecord decodes a cache\0file record.
func DecodeFileRecord(b []byte) (*FileRecord, error) {
	d := newDec(b)
	f := &FileRecord{Digest: d.digest(), Size: int64(d.uvarint()), ContentType: d.str()}
	n := d.uvarint()
	if n > 16 {
		return nil, ErrBadRecord
	}
	if n > 0 {
		f.Sums = make(Sums, n)
	}
	for range n {
		alg := d.str()
		f.Sums[alg] = d.bytes()
	}
	f.Fetched = d.time()
	if err := d.done(); err != nil {
		return nil, err
	}
	if f.Digest.IsZero() {
		return nil, ErrBadRecord
	}
	return f, nil
}

// Marks are, for every key prefix the shared proxy cache writes, the
// function that returns the blob digests a record under it references,
// or nil if its records reference none: the garbage collector's marker
// registration for these keys.
var Marks = map[string]func(key, value []byte) ([]blob.Digest, error){
	NSDoc: func(_, value []byte) ([]blob.Digest, error) {
		r, err := DecodeDocRecord(value)
		if err != nil {
			return nil, err
		}
		return []blob.Digest{r.Digest}, nil
	},
	NSFile: func(_, value []byte) ([]blob.Digest, error) {
		f, err := DecodeFileRecord(value)
		if err != nil {
			return nil, err
		}
		return []blob.Digest{f.Digest}, nil
	},
	NSPulled: nil,
}

// References calls fn with each blob the shared proxy cache's records in
// v reference, for backups to check that they hold them all.
func References(v meta.View, fn func(blob.Digest) error) error {
	var err error
	for _, pfx := range []string{NSDoc, NSFile} {
		mark := Marks[pfx]
		v.Scan([]byte(pfx), nil, func(k []byte, rec meta.Record) bool {
			ds, derr := mark(k, rec.Value)
			if derr != nil {
				err = fmt.Errorf("upstream: metadata key %q: %w", k, derr)
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
		d.err = ErrBadRecord
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
		d.err = ErrBadRecord
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
		d.err = ErrBadRecord
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
		d.err = ErrBadRecord
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
		d.err = ErrBadRecord
	}
	return dg
}

// done returns the decoding error, or an error if bytes are left over.
func (d *dec) done() error {
	if d.err == nil && len(d.b) != 0 {
		d.err = ErrBadRecord
	}
	return d.err
}
