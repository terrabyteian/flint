package npm

import (
	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
)

// GCMarker returns the npm marker for the garbage collector, which says
// what each record of hosted repositories references:
//
//   - a package references its readme;
//   - a live version references its manifest, its tarball, and its
//     provenance bundle; a tombstone references nothing.
//
// Every function reads its record, so one that cannot be read makes a
// run refuse to delete anything.
func GCMarker() gc.Marker {
	return gc.Marker{
		nsPkg:     pkgRefs,
		nsVersion: versionRefs,
	}
}

func pkgRefs(_, value []byte) ([]blob.Digest, error) {
	p, err := decodePkg(value)
	if err != nil {
		return nil, err
	}
	return nonZero(p.Readme), nil
}

func versionRefs(_, value []byte) ([]blob.Digest, error) {
	r, err := decodeVersion(value)
	if err != nil {
		return nil, err
	}
	return r.refs(), nil
}
