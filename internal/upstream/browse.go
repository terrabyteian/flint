package upstream

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/meta"
)

// CacheView is the web UI's view of the files proxy repositories of
// every format cached in the shared proxy cache (PathCache's records), as
// a tree of their paths. It lists what is cached and never contacts an
// upstream. The paths are cache keys, which for most formats are the
// request paths within the repository.
type CacheView struct {
	Meta meta.Store
}

var _ browse.Files = CacheView{}

// ListFiles implements browse.Files. A repository that cached nothing,
// or that is not a proxy repository, lists no entries.
func (c CacheView) ListFiles(repo, dir string, q browse.Query) ([]browse.Entry, bool, error) {
	if dir != "" && !strings.HasSuffix(dir, "/") {
		return nil, false, browse.ErrNotFound
	}
	v := c.Meta.View()
	defer v.Release()
	pfx := FileKey(repo, dir)
	var after []byte
	if q.After != "" {
		after = append(bytes.Clone(pfx), q.After...)
		if strings.HasSuffix(q.After, "/") {
			// Past every path below the directory: UTF-8 has no 0xff.
			after = append(after, 0xff)
		}
	}
	var out []browse.Entry
	more := false
	var failure error
	for {
		var next []byte
		v.Scan(pfx, after, func(k []byte, r meta.Record) bool {
			rel := string(k[len(pfx):])
			if i := strings.IndexByte(rel, '/'); i >= 0 {
				name := rel[:i+1]
				if q.Match(name) {
					if q.Full(len(out)) {
						more = true
						return false
					}
					out = append(out, browse.Entry{Name: name, Dir: true})
				}
				// Continue past every path below the directory.
				next = append(append(bytes.Clone(pfx), name...), 0xff)
				return false
			}
			if !q.Match(rel) {
				return true
			}
			f, err := DecodeFileRecord(r.Value)
			if err != nil {
				failure = fmt.Errorf("upstream: proxy cache record %q: %w", k, err)
				return false
			}
			if q.Full(len(out)) {
				more = true
				return false
			}
			out = append(out, browse.Entry{Name: rel, Size: f.Size, Digest: f.Digest.String(), Time: f.Fetched})
			return true
		})
		if failure != nil || more || next == nil {
			break
		}
		after = next
	}
	if failure != nil {
		return nil, false, failure
	}
	if dir != "" && len(out) == 0 && q.After == "" && q.Filter == "" {
		return nil, false, browse.ErrNotFound
	}
	return out, more, nil
}
