package pypi

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
)

// The web UI's view of PyPI repositories: a hosted repository's projects
// and their live files, and the files a proxy repository cached, by
// project. Virtual repositories have none of their own.

var _ browse.Packages = (*Handler)(nil)

// browseRepo returns the hosted or proxy repository named name.
func (h *Handler) browseRepo(name string) (*repository, error) {
	rp := h.repos[name]
	if rp == nil || rp.typ == config.TypeVirtual {
		return nil, browse.ErrNotFound
	}
	return rp, nil
}

// browseFile is a file with the project and version it belongs to.
type browseFile struct {
	project, version string
	file             browse.File
	rec              *fileRecord
}

// ListPackages implements browse.Packages.
func (h *Handler) ListPackages(name string, q browse.Query) ([]browse.Package, bool, error) {
	rp, err := h.browseRepo(name)
	if err != nil {
		return nil, false, err
	}
	v := h.view()
	defer v.Release()
	if rp.typ == config.TypeProxy {
		files, err := cachedFiles(v, rp, "")
		if err != nil {
			return nil, false, err
		}
		return listByProject(files, q)
	}
	var out []browse.Package
	more := false
	var failure error
	pfx := []byte(nsProject + rp.name + "\x00")
	var after []byte
	if q.After != "" {
		after = append(bytes.Clone(pfx), Normalize(q.After)...)
	}
	v.Scan(pfx, after, func(k []byte, r meta.Record) bool {
		pr, err := decodeProject(r.Value)
		if err != nil {
			failure = fmt.Errorf("pypi: project record %q: %w", k, err)
			return false
		}
		if !q.Match(pr.Name) {
			return true
		}
		if q.Full(len(out)) {
			more = true
			return false
		}
		files, err := hostedFiles(v, rp, string(k[len(pfx):]))
		if err != nil {
			failure = err
			return false
		}
		p := summarize(pr.Name, files)
		if p.Updated.IsZero() {
			p.Updated = pr.Created
		}
		out = append(out, p)
		return true
	})
	return out, more, failure
}

// listByProject lists the projects of files, a page of them as q asks.
func listByProject(files []browseFile, q browse.Query) ([]browse.Package, bool, error) {
	byProject := map[string][]browseFile{}
	for _, f := range files {
		byProject[f.project] = append(byProject[f.project], f)
	}
	names := slices.Sorted(func(yield func(string) bool) {
		for p := range byProject {
			if !yield(p) {
				return
			}
		}
	})
	var out []browse.Package
	for _, p := range names {
		if q.After != "" && p <= Normalize(q.After) || !q.Match(p) {
			continue
		}
		if q.Full(len(out)) {
			return out, true, nil
		}
		out = append(out, summarize(p, byProject[p]))
	}
	return out, false, nil
}

// summarize describes a project from its files.
func summarize(name string, files []browseFile) browse.Package {
	p := browse.Package{Name: name}
	versions := map[string]bool{}
	for _, f := range files {
		versions[f.version] = true
		if f.version != "" && (p.Latest == "" || compareVersions(f.version, p.Latest) > 0) {
			p.Latest = f.version
		}
		if f.file.Time.After(p.Updated) {
			p.Updated = f.file.Time
		}
	}
	p.Versions = len(versions)
	return p
}

// Package implements browse.Packages.
func (h *Handler) Package(ctx context.Context, name, project string) (*browse.PackageDetail, error) {
	rp, err := h.browseRepo(name)
	if err != nil {
		return nil, err
	}
	project = Normalize(project)
	v := h.view()
	display := project
	var files []browseFile
	if rp.typ == config.TypeProxy {
		files, err = cachedFiles(v, rp, project)
	} else if rec, ok := v.Get(projectKey(rp.name, project)); ok {
		var pr *projectRecord
		if pr, err = decodeProject(rec.Value); err == nil {
			display = pr.Name
			files, err = hostedFiles(v, rp, project)
		}
	}
	v.Release()
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, browse.ErrNotFound
	}
	out := &browse.PackageDetail{Name: display}
	byVersion := map[string]*browse.Version{}
	var newest *browseFile
	for i, f := range files {
		ver := byVersion[f.version]
		if ver == nil {
			ver = &browse.Version{Version: f.version}
			byVersion[f.version] = ver
		}
		ver.Files = append(ver.Files, f.file)
		if f.file.Time.After(ver.Published) {
			ver.Published = f.file.Time
		}
		if r := f.rec; r != nil && r.Yanked {
			note := "yanked"
			if r.YankedReason != "" {
				note += ": " + r.YankedReason
			}
			if !slices.Contains(ver.Notes, note) {
				ver.Notes = append(ver.Notes, note)
			}
		}
		if f.rec != nil && !f.rec.Meta.IsZero() &&
			(newest == nil || compareVersions(f.version, newest.version) > 0) {
			newest = &files[i]
		}
	}
	for _, ver := range byVersion {
		slices.SortFunc(ver.Files, func(a, b browse.File) int { return strings.Compare(a.Name, b.Name) })
		out.Versions = append(out.Versions, *ver)
	}
	slices.SortFunc(out.Versions, func(a, b browse.Version) int { return compareVersions(b.Version, a.Version) })
	if newest != nil {
		out.Summary = h.summary(ctx, newest.rec)
	}
	return out, nil
}

// summary reads the Summary field of a hosted file's core metadata, or
// returns "".
func (h *Handler) summary(ctx context.Context, f *fileRecord) string {
	rd, err := h.blobs.Open(ctx, f.Meta)
	if err != nil {
		return ""
	}
	defer rd.Close()
	sc := bufio.NewScanner(io.LimitReader(rd, 64<<10))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // the end of the headers
		}
		if s, ok := strings.CutPrefix(line, "Summary:"); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// hostedFiles returns the live files of a hosted project.
func hostedFiles(v meta.View, rp *repository, project string) ([]browseFile, error) {
	var out []browseFile
	var failure error
	pfx := indexPrefix(rp.name, project)
	v.Scan(pfx, nil, func(k []byte, _ meta.Record) bool {
		filename := string(k[len(pfx):])
		rec, ok := v.Get(fileKey(rp.name, filename))
		if !ok {
			return true
		}
		f, err := decodeFile(rec.Value)
		if err != nil {
			failure = fmt.Errorf("pypi: file record of %s in %s: %w", filename, rp.name, err)
			return false
		}
		if f.Kind == kindHosted {
			out = append(out, browseFile{project: project, version: f.Version, rec: f,
				file: browse.File{Name: filename, Size: f.Size, Digest: f.Digest.String(), Time: f.Uploaded,
					URL: fileDownload(rp.name, project, filename)}})
		}
		return true
	})
	return out, failure
}

// cachedFiles returns the files a proxy repository cached, of project
// only if it is not "".
func cachedFiles(v meta.View, rp *repository, project string) ([]browseFile, error) {
	var out []browseFile
	var failure error
	pfx := []byte(nsFile + rp.name + "\x00")
	v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
		f, err := decodeFile(rec.Value)
		if err != nil {
			failure = fmt.Errorf("pypi: file record %q: %w", k, err)
			return false
		}
		if f.Kind != kindCached || project != "" && f.Project != project {
			return true
		}
		filename := string(k[len(pfx):])
		d, _ := parseFilename(filename, f.Project)
		out = append(out, browseFile{project: f.Project, version: d.Version,
			file: browse.File{Name: filename, Size: f.Size, Digest: f.Digest.String(),
				URL: fileDownload(rp.name, f.Project, filename)}})
		return true
	})
	return out, failure
}

// fileDownload is the path a file is downloaded from.
func fileDownload(name, project, filename string) string {
	return repo.Path(config.FormatPyPI, name) + "files/" + project + "/" + url.PathEscape(filename)
}
