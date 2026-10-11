package generic

import (
	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
)

// GCMarker returns the generic files marker for the garbage collector,
// which says what each record references: a live hosted file references
// its bytes, and a tombstone nothing. The function reads its record, so
// one that cannot be read makes a run refuse to delete anything. Files a
// proxy repository cached are records of the shared proxy cache, whose
// marker is upstream.Marks.
func GCMarker() gc.Marker {
	return gc.Marker{nsFile: fileRefs}
}

func fileRefs(_, value []byte) ([]blob.Digest, error) {
	f, err := decodeFile(value)
	if err != nil || f.Kind == kindTombstone {
		return nil, err
	}
	return []blob.Digest{f.Digest}, nil
}
