package oci

import (
	"bytes"
	"fmt"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
)

// GCMarker returns the OCI marker for the garbage collector, which says
// what each record of hosted and proxy repositories references:
//
//   - a blob link references its blob;
//   - a manifest record references the manifest's own bytes and every
//     blob and child manifest it lists;
//   - a tag references the manifest it points to;
//   - a referrers entry references the referring manifest, but not its
//     subject, which need not exist;
//   - upload sessions and proxy repositories' last-pull times reference
//     nothing.
func GCMarker() gc.Marker {
	return gc.Marker{
		nsBlob:     keyDigestRefs,
		nsManifest: manifestRefs,
		nsTag:      tagRefs,
		nsReferrer: keyDigestRefs,
		nsUpload:   nil,
		nsPulled:   nil,
	}
}

// keyDigest parses the digest that ends key, after its last separator.
func keyDigest(key []byte) (blob.Digest, error) {
	i := bytes.LastIndexByte(key, 0)
	d, err := blob.ParseDigest(string(key[i+1:]))
	if err != nil {
		return d, fmt.Errorf("the key does not end with a digest: %w", err)
	}
	return d, nil
}

// keyDigestRefs returns the digest that ends the key.
func keyDigestRefs(key, _ []byte) ([]blob.Digest, error) {
	d, err := keyDigest(key)
	if err != nil {
		return nil, err
	}
	return []blob.Digest{d}, nil
}

// manifestRefs returns a manifest's own digest and everything it
// references.
func manifestRefs(key, value []byte) ([]blob.Digest, error) {
	d, err := keyDigest(key)
	if err != nil {
		return nil, err
	}
	m, err := decodeManifest(value)
	if err != nil {
		return nil, err
	}
	out := make([]blob.Digest, 0, 1+len(m.Refs))
	out = append(out, d)
	for _, r := range m.Refs {
		out = append(out, r.Digest)
	}
	return out, nil
}

// tagRefs returns the manifest a tag points to.
func tagRefs(_, value []byte) ([]blob.Digest, error) {
	d, err := decodeTag(value)
	if err != nil {
		return nil, err
	}
	return []blob.Digest{d}, nil
}
