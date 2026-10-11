package cargo

import (
	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
)

// GCMarker returns the Cargo marker for the garbage collector, which says
// what each record of hosted repositories references:
//
//   - a published version, yanked or not, references its .crate file; a
//     tombstone references nothing;
//   - a crate record references nothing.
//
// Every function reads its record, so one that cannot be read makes a run
// refuse to delete anything. What proxy repositories cache is in the
// shared proxy cache, whose marker is upstream.Marks.
func GCMarker() gc.Marker {
	return gc.Marker{
		nsCrate:   crateRefs,
		nsVersion: versionRefs,
	}
}

func crateRefs(_, value []byte) ([]blob.Digest, error) {
	_, err := decodeCrate(value)
	return nil, err
}

func versionRefs(_, value []byte) ([]blob.Digest, error) {
	v, err := decodeVersion(value)
	if err != nil || v.Kind == kindTombstone {
		return nil, err
	}
	return []blob.Digest{v.Digest}, nil
}
