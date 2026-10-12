package generic

import (
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/repo"
)

// The web UI's view of hosted generic files repositories: their
// directories and live files. What proxy repositories cache is in the
// shared proxy cache, which the upstream package shows.

var _ browse.Files = (*Handler)(nil)

// ListFiles implements browse.Files.
func (h *Handler) ListFiles(name, dir string, q browse.Query) ([]browse.Entry, bool, error) {
	rp := h.repos[name]
	if rp == nil || rp.typ != config.TypeHosted || dir != "" && !strings.HasSuffix(dir, "/") {
		return nil, false, browse.ErrNotFound
	}
	v := h.meta.View()
	entries, err := list(v, rp.name, dir, nil)
	v.Release()
	if err != nil {
		return nil, false, err
	}
	if dir != "" && len(entries) == 0 {
		return nil, false, browse.ErrNotFound
	}
	base := repo.Path(config.FormatGeneric, rp.name)
	var out []browse.Entry
	for _, e := range entries {
		if q.After != "" && e.Name <= q.After || !q.Match(e.Name) {
			continue
		}
		if q.Full(len(out)) {
			return out, true, nil
		}
		be := browse.Entry{Name: e.Name, Dir: e.Type == "directory"}
		if !be.Dir {
			be.Size, be.Time, be.URL = *e.Size, *e.Uploaded, base+escapePath(dir+e.Name)
			if d, err := blob.ParseDigest("sha256:" + e.SHA256); err == nil {
				be.Digest = d.String()
			}
		}
		out = append(out, be)
	}
	return out, false, nil
}
