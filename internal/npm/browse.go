package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
)

// The web UI's view of hosted npm repositories: packages, their
// dist-tags, and their published versions. What proxy repositories cache
// is in the shared proxy cache, which the upstream package shows.

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
	pfx := []byte(nsPkg + rp.name + "\x00")
	var after []byte
	if q.After != "" {
		after = append(bytes.Clone(pfx), q.After...)
	}
	var out []browse.Package
	more := false
	var failure error
	v.Scan(pfx, after, func(k []byte, r meta.Record) bool {
		pkg := string(k[len(pfx):])
		if !q.Match(pkg) {
			return true
		}
		p, err := decodePkg(r.Value)
		if err != nil {
			failure = fmt.Errorf("npm: package record %q: %w", k, err)
			return false
		}
		live, err := liveVersions(v, rp, pkg)
		if err != nil {
			failure = err
			return false
		}
		if len(live) == 0 {
			return true // every version unpublished
		}
		if q.Full(len(out)) {
			more = true
			return false
		}
		out = append(out, browse.Package{Name: pkg, Latest: p.tag("latest"), Versions: len(live), Updated: p.Modified})
		return true
	})
	return out, more, failure
}

// liveVersions returns a hosted package's published versions.
func liveVersions(v meta.View, rp *repository, name string) (map[string]*versionRecord, error) {
	all, err := hostedVersions(v, rp, name)
	for ver, vr := range all {
		if vr.Kind != kindLive {
			delete(all, ver)
		}
	}
	return all, err
}

// Package implements browse.Packages.
func (h *Handler) Package(ctx context.Context, name, pkg string) (*browse.PackageDetail, error) {
	rp, err := h.browseRepo(name)
	if err != nil {
		return nil, err
	}
	v := h.meta.View()
	p, _, err := hostedPackage(v, rp, pkg)
	var live map[string]*versionRecord
	if err == nil && p != nil {
		live, err = liveVersions(v, rp, pkg)
	}
	v.Release()
	if err != nil {
		return nil, err
	}
	if len(live) == 0 {
		return nil, browse.ErrNotFound
	}
	out := &browse.PackageDetail{Name: pkg}
	for _, t := range p.Tags {
		out.Tags = append(out.Tags, browse.Tag{Name: t.Tag, Version: t.Version})
	}
	base := repo.Path(config.FormatNPM, rp.name)
	for ver, vr := range live {
		bv := browse.Version{Version: ver, Published: vr.Published}
		if vr.Deprecated != "" {
			bv.Notes = append(bv.Notes, "deprecated: "+vr.Deprecated)
		}
		if !vr.Provenance.IsZero() {
			bv.Notes = append(bv.Notes, "provenance")
		}
		file := tarballName(pkg, ver)
		bv.Files = []browse.File{{Name: file, Size: vr.Size, Digest: vr.Tarball.String(), Time: vr.Published,
			URL: base + pkg + "/-/" + file}}
		out.Versions = append(out.Versions, bv)
	}
	slices.SortFunc(out.Versions, func(a, b browse.Version) int { return compareVersions(b.Version, a.Version) })
	if latest := live[p.tag("latest")]; latest != nil {
		out.Summary = h.description(ctx, latest)
	}
	return out, nil
}

// description reads the description in a version's manifest, or
// returns "".
func (h *Handler) description(ctx context.Context, vr *versionRecord) string {
	b, err := h.readBlob(ctx, vr.Manifest, vr.ManifestSize)
	if err != nil {
		return ""
	}
	var m struct {
		Description string `json:"description"`
	}
	json.Unmarshal(b, &m)
	return m.Description
}
