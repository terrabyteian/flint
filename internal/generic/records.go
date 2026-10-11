package generic

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
// are separated by 0x00, which cannot occur in a repository name or a
// file path:
//
//	generic\0file\0<repo>\0<path>   hosted file: digest, size, content type, upload time;
//	                                kept as a tombstone after delete in an immutable repository
//
// The digest a live file record holds is a blob garbage collection must
// keep; a tombstone holds none. Files a proxy repository cached are
// records of the shared proxy cache (cache\0file and cache\0doc), which
// the upstream package owns.
const (
	nsFile = "generic\x00file\x00"

	recordFormat = 1 // the schema version byte that starts every value
)

// fileKey returns the key of the file at path in repository repo; with
// path empty or ending in "/", it is the prefix of the files below it.
func fileKey(repo, path string) []byte {
	b := make([]byte, 0, len(nsFile)+len(repo)+1+len(path))
	b = append(b, nsFile...)
	b = append(b, repo...)
	b = append(b, 0)
	return append(b, path...)
}

var errBadRecord = errors.New("generic: malformed metadata record")

// File record kinds.
const (
	kindFile      = 1 // a live file
	kindTombstone = 2 // a deleted file, whose path can never be used again
)

// fileRecord is a hosted file, or the tombstone of one. A tombstone
// keeps only Kind and Deleted.
type fileRecord struct {
	Kind        byte
	Digest      blob.Digest
	Size        int64
	ContentType string
	Uploaded    time.Time
	Deleted     time.Time
}

func (f *fileRecord) encode() []byte {
	b := []byte{recordFormat, f.Kind}
	if f.Kind == kindTombstone {
		return appendTime(b, f.Deleted)
	}
	sum, _ := hex.DecodeString(f.Digest.Hex())
	b = append(b, sum...)
	b = binary.AppendUvarint(b, uint64(f.Size))
	b = binary.AppendUvarint(b, uint64(len(f.ContentType)))
	b = append(b, f.ContentType...)
	return appendTime(b, f.Uploaded)
}

func appendTime(b []byte, t time.Time) []byte {
	if t.IsZero() {
		return binary.AppendVarint(b, 0)
	}
	return binary.AppendVarint(b, t.UnixNano())
}

func decodeFile(b []byte) (*fileRecord, error) {
	if len(b) < 2 || b[0] != recordFormat {
		return nil, errBadRecord
	}
	f := &fileRecord{Kind: b[1]}
	b = b[2:]
	readTime := func() (time.Time, bool) {
		v, n := binary.Varint(b)
		if n <= 0 {
			return time.Time{}, false
		}
		b = b[n:]
		if v == 0 {
			return time.Time{}, true
		}
		return time.Unix(0, v).UTC(), true
	}
	var ok bool
	switch f.Kind {
	case kindTombstone:
		if f.Deleted, ok = readTime(); !ok {
			return nil, errBadRecord
		}
	case kindFile:
		if len(b) < 32 {
			return nil, errBadRecord
		}
		d, err := blob.ParseDigest("sha256:" + hex.EncodeToString(b[:32]))
		if err != nil {
			return nil, errBadRecord
		}
		f.Digest, b = d, b[32:]
		size, n := binary.Uvarint(b)
		if n <= 0 || size > 1<<62 {
			return nil, errBadRecord
		}
		f.Size, b = int64(size), b[n:]
		l, n := binary.Uvarint(b)
		if n <= 0 || l > uint64(len(b)-n) {
			return nil, errBadRecord
		}
		f.ContentType, b = string(b[n:n+int(l)]), b[n+int(l):]
		if f.Uploaded, ok = readTime(); !ok {
			return nil, errBadRecord
		}
	default:
		return nil, errBadRecord
	}
	if len(b) != 0 {
		return nil, errBadRecord
	}
	return f, nil
}

// References calls fn, until it returns an error, with the digest of each
// blob that v links into a generic files repository: every live hosted
// file. A tombstone links none. Files a proxy repository cached are
// records of the shared proxy cache, which upstream.References reports.
func References(v meta.View, fn func(blob.Digest) error) error {
	var err error
	v.Scan([]byte(nsFile), nil, func(k []byte, rec meta.Record) bool {
		f, derr := decodeFile(rec.Value)
		switch {
		case derr != nil:
			err = fmt.Errorf("generic: metadata key %q: %w", k, derr)
		case f.Kind == kindFile:
			err = fn(f.Digest)
		}
		return err == nil
	})
	return err
}
