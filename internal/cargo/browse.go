package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"

	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
)

// The web UI's view of hosted Cargo repositories: crates and their
// published versions, yanked or not. What proxy repositories cache is
// in the shared proxy cache, which the upstream package shows.

var _ browse.Packages = (*Handler)(nil)

func (h *Handler) browseRepo(name string) (*repository, error) {
	rp := h.repos[name]
	if rp == nil || rp.typ != config.TypeHosted {
		return nil, browse.ErrNotFound
	}
	return rp, nil
}

// ListPackages implements browse.Packages.
func (h *Handler) ListPackages(name string, q browse.Query) ([]browse.Package, bool, error) {
	rp, err := h.browseRepo(name)
	if err != nil {
		return nil, false, err
	}
	v := h.meta.View()
	defer v.Release()
	pfx := []byte(nsCrate + rp.name + "\x00")
	var after []byte
	if q.After != "" {
		after = append(bytes.Clone(pfx), Normalize(q.After)...)
	}
	var out []browse.Package
	more := false
	var failure error
	v.Scan(pfx, after, func(k []byte, r meta.Record) bool {
		c, err := decodeCrate(r.Value)
		if err != nil {
			failure = fmt.Errorf("cargo: crate record %q: %w", k, err)
			return false
		}
		if !q.Match(c.Name) {
			return true
		}
		versions, err := liveVersions(v, rp, string(k[len(pfx):]))
		if err != nil {
			failure = err
			return false
		}
		if len(versions) == 0 {
			return true // every version deleted
		}
		if q.Full(len(out)) {
			more = true
			return false
		}
		p := browse.Package{Name: c.Name, Versions: len(versions)}
		for _, vr := range versions {
			if p.Latest == "" || compareVersions(vr.Vers, p.Latest) > 0 {
				p.Latest = vr.Vers
				p.Summary = vr.Description
			}
			if vr.Published.After(p.Updated) {
				p.Updated = vr.Published
			}
		}
		out = append(out, p)
		return true
	})
	return out, more, failure
}

// liveVersions returns a hosted crate's published versions, yanked or
// not.
func liveVersions(v meta.View, rp *repository, norm string) ([]*versionRecord, error) {
	var out []*versionRecord
	var failure error
	v.Scan(versionsPrefix(rp.name, norm), nil, func(k []byte, r meta.Record) bool {
		vr, err := decodeVersion(r.Value)
		if err != nil {
			failure = fmt.Errorf("cargo: version record %q: %w", k, err)
			return false
		}
		if vr.Kind == kindLive {
			out = append(out, vr)
		}
		return true
	})
	return out, failure
}

// Package implements browse.Packages.
func (h *Handler) Package(_ context.Context, name, crate string) (*browse.PackageDetail, error) {
	rp, err := h.browseRepo(name)
	if err != nil {
		return nil, err
	}
	v := h.meta.View()
	defer v.Release()
	norm := Normalize(crate)
	rec, ok := v.Get(crateKey(rp.name, norm))
	if !ok {
		return nil, browse.ErrNotFound
	}
	c, err := decodeCrate(rec.Value)
	if err != nil {
		return nil, err
	}
	versions, err := liveVersions(v, rp, norm)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, browse.ErrNotFound
	}
	slices.SortFunc(versions, func(a, b *versionRecord) int { return compareVersions(b.Vers, a.Vers) })
	out := &browse.PackageDetail{Name: c.Name, Summary: versions[0].Description}
	base := repo.Path(config.FormatCargo, rp.name) + "api/v1/crates/" + url.PathEscape(c.Name) + "/"
	for _, vr := range versions {
		bv := browse.Version{Version: vr.Vers, Published: vr.Published}
		var line struct {
			Yanked bool `json:"yanked"`
		}
		if json.Unmarshal(vr.Line, &line) == nil && line.Yanked {
			bv.Notes = append(bv.Notes, "yanked")
		}
		bv.Files = []browse.File{{Name: c.Name + "-" + vr.Vers + ".crate", Size: vr.Size, Digest: vr.Digest.String(),
			Time: vr.Published, URL: base + url.PathEscape(vr.Vers) + "/download"}}
		out.Versions = append(out.Versions, bv)
	}
	return out, nil
}
