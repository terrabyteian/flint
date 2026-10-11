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
//   - a project page a proxy repository cached references the blob that
//     holds it;
//   - project, index, and name records, and pull times, reference
//     nothing.
//
// Every function reads its record, so one that cannot be read makes a
// run refuse to delete anything.
func GCMarker() gc.Marker {
	return gc.Marker{
		nsProject:  projectRefs,
		nsFile:     fileRefs,
		nsIndex:    emptyRefs,
		nsName:     nameRefs,
		nsMetadata: fileRefs,
		nsPage:     pageRefs,
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

// pageRefs returns the blob that holds a cached project page.
func pageRefs(_, value []byte) ([]blob.Digest, error) {
	p, err := decodePage(value)
	if err != nil {
		return nil, err
	}
	return nonZero(p.Digest), nil
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
