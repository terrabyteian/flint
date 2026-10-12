package maven

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
)

// The web UI's view of hosted Maven repositories: artifacts, named
// groupId:artifactId, their versions, and each version's live files.
// What proxy repositories cache is in the shared proxy cache, which the
// upstream package shows.

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
	pfx := []byte(nsVersion + rp.name + "\x00")
	var after []byte
	if g, a, ok := strings.Cut(q.After, ":"); ok {
		// Past every version of the artifact named After.
		after = append(append(append(bytes.Clone(pfx), g...), 0), append([]byte(a), 1)...)
	}
	var out []browse.Package
	more := false
	for !more {
		var group, artifact string
		v.Scan(pfx, after, func(k []byte, _ meta.Record) bool {
			parts := strings.Split(string(k[len(pfx):]), "\x00")
			if len(parts) == 3 {
				group, artifact = parts[0], parts[1]
			}
			return false
		})
		if group == "" {
			break
		}
		after = append(append(append(bytes.Clone(pfx), group...), 0), append([]byte(artifact), 1)...)
		pkgName := group + ":" + artifact
		if !q.Match(pkgName) {
			continue
		}
		versions, err := artifactVersions(v, rp, group, artifact)
		if err != nil {
			return nil, false, err
		}
		if len(versions) == 0 {
			continue // every file deleted
		}
		if q.Full(len(out)) {
			more = true
			break
		}
		p := browse.Package{Name: pkgName, Versions: len(versions)}
		for ver, vr := range versions {
			if p.Latest == "" || CompareVersions(ver, p.Latest) > 0 {
				p.Latest = ver
			}
			if vr.Updated.After(p.Updated) {
				p.Updated = vr.Updated
			}
		}
		out = append(out, p)
	}
	return out, more, nil
}

// artifactVersions returns an artifact's versions that have live files.
func artifactVersions(v meta.View, rp *repository, group, artifact string) (map[string]*versionRecord, error) {
	out := map[string]*versionRecord{}
	var failure error
	pfx := versionPrefix(rp.name, group, artifact)
	v.Scan(pfx, nil, func(k []byte, r meta.Record) bool {
		vr, err := decodeVersion(r.Value)
		if err != nil {
			failure = fmt.Errorf("maven: version record %q: %w", k, err)
			return false
		}
		if vr.Files > 0 {
			out[string(k[len(pfx):])] = vr
		}
		return true
	})
	return out, failure
}

// Package implements browse.Packages for an artifact named
// groupId:artifactId.
func (h *Handler) Package(_ context.Context, name, pkg string) (*browse.PackageDetail, error) {
	rp, err := h.browseRepo(name)
	if err != nil {
		return nil, err
	}
	group, artifact, ok := strings.Cut(pkg, ":")
	if !ok || !validName(group) || !validName(artifact) {
		return nil, browse.ErrNotFound
	}
	v := h.meta.View()
	defer v.Release()
	versions, err := artifactVersions(v, rp, group, artifact)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, browse.ErrNotFound
	}
	out := &browse.PackageDetail{Name: pkg}
	base := repo.Path(config.FormatMaven, rp.name)
	for ver, vr := range versions {
		bv := browse.Version{Version: ver, Published: vr.Updated}
		if vr.Snapshot {
			bv.Notes = append(bv.Notes, "snapshot")
		}
		dir := strings.ReplaceAll(group, ".", "/") + "/" + artifact + "/" + ver + "/"
		pfx := fileKey(rp.name, dir)
		var failure error
		v.Scan(pfx, nil, func(k []byte, r meta.Record) bool {
			file := string(k[len(pfx):])
			if strings.Contains(file, "/") {
				return true
			}
			f, err := decodeFile(r.Value)
			if err != nil {
				failure = fmt.Errorf("maven: file record %q: %w", k, err)
				return false
			}
			if f.Kind == kindLive {
				bv.Files = append(bv.Files, browse.File{Name: file, Size: f.Size, Digest: f.Digest.String(),
					Time: f.Uploaded, URL: base + dir + file})
			}
			return true
		})
		if failure != nil {
			return nil, failure
		}
		out.Versions = append(out.Versions, bv)
	}
	slices.SortFunc(out.Versions, func(a, b browse.Version) int { return CompareVersions(b.Version, a.Version) })
	return out, nil
}
