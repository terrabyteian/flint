package maven

import (
	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
)

// GCMarker returns the Maven marker for the garbage collector, which says
// what each record of hosted repositories references:
//
//   - a file references its bytes; a tombstone references nothing;
//   - version and plugin records reference nothing.
//
// Every function reads its record, so one that cannot be read makes a run
// refuse to delete anything. Files and metadata proxy repositories cached
// are in the shared proxy cache, whose marker is upstream.Marks.
func GCMarker() gc.Marker {
	return gc.Marker{
		nsFile:    fileRefs,
		nsVersion: versionRefs,
		nsPlugin:  pluginRefs,
	}
}

func fileRefs(_, value []byte) ([]blob.Digest, error) {
	f, err := decodeFile(value)
	if err != nil || f.Kind != kindLive {
		return nil, err
	}
	return []blob.Digest{f.Digest}, nil
}

func versionRefs(_, value []byte) ([]blob.Digest, error) {
	_, err := decodeVersion(value)
	return nil, err
}

func pluginRefs(_, value []byte) ([]blob.Digest, error) {
	_, err := decodePlugin(value)
	return nil, err
}
