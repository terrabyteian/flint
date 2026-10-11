package pypi

import (
	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
)

// GCMarker returns the PyPI marker for the garbage collector, which says
// what each record of hosted and proxy repositories references:
//
//   - a hosted file references its bytes and its core metadata; a
//     tombstone references nothing;
//   - a file or core-metadata file a proxy repository cached references
//     its bytes;
//   - project, index, and name records, and pull times, reference
//     nothing.
//
// Every function reads its record, so one that cannot be read makes a
// run refuse to delete anything. Project pages a proxy repository cached
// are documents of the shared proxy cache, whose marker is
// upstream.Marks.
func GCMarker() gc.Marker {
	return gc.Marker{
		nsProject:  projectRefs,
		nsFile:     fileRefs,
		nsIndex:    emptyRefs,
		nsName:     nameRefs,
		nsMetadata: fileRefs,
		nsPulled:   pulledRefs,
	}
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

// fileRefs returns a file's bytes and core metadata.
func fileRefs(_, value []byte) ([]blob.Digest, error) {
	f, err := decodeFile(value)
	if err != nil {
		return nil, err
	}
	return nonZero(f.Digest, f.Meta), nil
}

func projectRefs(_, value []byte) ([]blob.Digest, error) {
	_, err := decodeProject(value)
	return nil, err
}

func nameRefs(_, value []byte) ([]blob.Digest, error) {
	_, err := decodeName(value)
	return nil, err
}

func emptyRefs(_, value []byte) ([]blob.Digest, error) {
	return nil, newDec(value).done()
}

func pulledRefs(_, value []byte) ([]blob.Digest, error) {
	d := newDec(value)
	d.varint()
	return nil, d.done()
}
