package pypi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/server"
	"github.com/terrabyteian/flint/internal/upstream"
)

// The JSON API, /pypi/<repo>/pypi/<project>/json, follows PyPI's: the
// latest release's metadata in "info", every release's files in
// "releases", and the latest release's files in "urls". The version
// endpoint, /pypi/<repo>/pypi/<project>/<version>/json, describes one
// release and has no "releases", as on PyPI. "info" comes from the core
// metadata of the release's files; for a release without any, it holds
// only what the file names and index say.

// jsonInfo is the "info" object.
type jsonInfo struct {
	Author                 string            `json:"author"`
	AuthorEmail            string            `json:"author_email"`
	BugtrackURL            *string           `json:"bugtrack_url"`
	Classifiers            []string          `json:"classifiers"`
	Description            string            `json:"description"`
	DescriptionContentType *string           `json:"description_content_type"`
	DocsURL                *string           `json:"docs_url"`
	DownloadURL            string            `json:"download_url"`
	Downloads              map[string]int    `json:"downloads"`
	Dynamic                []string          `json:"dynamic"`
	HomePage               string            `json:"home_page"`
	Keywords               string            `json:"keywords"`
	License                string            `json:"license"`
	LicenseExpression      *string           `json:"license_expression"`
	LicenseFiles           []string          `json:"license_files"`
	Maintainer             string            `json:"maintainer"`
	MaintainerEmail        string            `json:"maintainer_email"`
	Name                   string            `json:"name"`
	PackageURL             string            `json:"package_url"`
	Platform               *string           `json:"platform"`
	ProjectURL             string            `json:"project_url"`
	ProjectURLs            map[string]string `json:"project_urls"`
	ProvidesExtra          []string          `json:"provides_extra"`
	ReleaseURL             string            `json:"release_url"`
	RequiresDist           []string          `json:"requires_dist"`
	RequiresPython         string            `json:"requires_python"`
	Summary                string            `json:"summary"`
	Version                string            `json:"version"`
	Yanked                 bool              `json:"yanked"`
	YankedReason           *string           `json:"yanked_reason"`
}

// jsonFile is a file in "releases" and "urls".
type jsonFile struct {
	CommentText       string            `json:"comment_text"`
	Digests           map[string]string `json:"digests"`
	Downloads         int               `json:"downloads"`
	Filename          string            `json:"filename"`
	HasSig            bool              `json:"has_sig"`
	MD5Digest         string            `json:"md5_digest"`
	PackageType       string            `json:"packagetype"`
	PythonVersion     string            `json:"python_version"`
	RequiresPython    *string           `json:"requires_python"`
	Size              int64             `json:"size"`
	UploadTime        string            `json:"upload_time"`
	UploadTimeISO8601 *string           `json:"upload_time_iso_8601"`
	URL               string            `json:"url"`
	Yanked            bool              `json:"yanked"`
	YankedReason      *string           `json:"yanked_reason"`
}

// release is one version's files.
type release struct {
	version string
	files   []*file
}

// yanked reports whether every file of the release is yanked.
func (rl *release) yanked() bool {
	for _, f := range rl.files {
		if !f.Yanked {
			return false
		}
	}
	return true
}

// releases groups a project's files by version, in PEP 440 order.
func releases(p *projectDoc) []*release {
	byVersion := map[string]*release{}
	var out []*release
	for _, f := range p.Files {
		if f.Version == "" {
			continue
		}
		c := canonicalVersion(f.Version)
		rl := byVersion[c]
		if rl == nil {
			rl = &release{version: f.Version}
			byVersion[c] = rl
			out = append(out, rl)
		}
		rl.files = append(rl.files, f)
	}
	slices.SortStableFunc(out, func(a, b *release) int { return compareVersions(a.version, b.version) })
	return out
}

// latest returns the release the JSON API describes by default: the
// highest final release not yanked, else the highest release not yanked,
// else the highest.
func latest(rls []*release) *release {
	for _, final := range []bool{true, false} {
		for i := len(rls) - 1; i >= 0; i-- {
			rl := rls[i]
			if rl.yanked() {
				continue
			}
			if v, ok := parseVersion(rl.version); final && (!ok || v.prerelease()) {
				continue
			}
			return rl
		}
	}
	if len(rls) == 0 {
		return nil
	}
	return rls[len(rls)-1]
}

// serveJSON serves the JSON API for project, or for one version of it.
func (h *Handler) serveJSON(w http.ResponseWriter, r *http.Request, rp *repository, project, version string) {
	ctx := r.Context()
	actor := h.actor(r)
	p, result, err := h.projectOf(ctx, actor, rp, project)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if rp.typ == config.TypeProxy {
		h.pm.Requests.With(rp.name, result).Inc()
	}
	rls := releases(p)
	var rl *release
	if version != "" {
		want := canonicalVersion(version)
		for _, x := range rls {
			if canonicalVersion(x.version) == want {
				rl = x
			}
		}
	} else {
		rl = latest(rls)
	}
	if rl == nil {
		writeError(w, http.StatusNotFound, "project %s has no release %s", project, version)
		return
	}
	info := server.Info(ctx)
	scheme, host := info.Scheme, info.Host
	if scheme == "" {
		scheme, host = "http", r.Host
	}
	base := scheme + "://" + host + "/pypi/" + rp.name + "/"
	out := struct {
		Info            *jsonInfo              `json:"info"`
		LastSerial      int64                  `json:"last_serial"`
		Releases        map[string][]*jsonFile `json:"releases,omitempty"`
		URLs            []*jsonFile            `json:"urls"`
		Vulnerabilities []any                  `json:"vulnerabilities"`
	}{
		Info:            h.jsonInfo(ctx, actor, p, rl, base),
		LastSerial:      h.serial(rp, project),
		URLs:            []*jsonFile{},
		Vulnerabilities: []any{},
	}
	for _, f := range rl.files {
		out.URLs = append(out.URLs, toJSONFile(p.Name, f, base))
	}
	if version == "" {
		out.Releases = map[string][]*jsonFile{}
		for _, x := range rls {
			files := []*jsonFile{}
			for _, f := range x.files {
				files = append(files, toJSONFile(p.Name, f, base))
			}
			out.Releases[x.version] = files
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=0, must-revalidate")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(out)
}

// toJSONFile describes a file for the JSON API, with an absolute URL
// below base, the repository's URL.
func toJSONFile(project string, f *file, base string) *jsonFile {
	jf := &jsonFile{
		Digests: map[string]string{}, Downloads: -1, Filename: f.Filename, MD5Digest: f.MD5,
		Size: f.Size, URL: base + "files/" + project + "/" + url.PathEscape(f.Filename), Yanked: f.Yanked,
	}
	if f.SHA256 != "" {
		jf.Digests["sha256"] = f.SHA256
	}
	if f.MD5 != "" {
		jf.Digests["md5"] = f.MD5
	}
	if f.Blake2b256 != "" {
		jf.Digests["blake2b_256"] = f.Blake2b256
	}
	if f.rec != nil {
		jf.PackageType, jf.PythonVersion = f.rec.PackageType, f.rec.PythonVersion
	} else {
		d, _ := parseFilename(f.Filename, project)
		jf.PackageType, jf.PythonVersion = d.PackageType, d.PythonVersion
	}
	if f.RequiresPython != "" {
		jf.RequiresPython = &f.RequiresPython
	}
	if !f.UploadTime.IsZero() {
		jf.UploadTime = f.UploadTime.UTC().Format("2006-01-02T15:04:05")
		iso := formatTime(f.UploadTime)
		jf.UploadTimeISO8601 = &iso
	}
	if f.Yanked {
		reason := f.YankedReason
		jf.YankedReason = &reason
	}
	return jf
}

// jsonInfo builds "info" for release rl of project p, from the core
// metadata of one of its files: a wheel's if there is one, as the most
// reliable.
func (h *Handler) jsonInfo(ctx context.Context, actor string, p *projectDoc, rl *release, base string) *jsonInfo {
	page := base + "simple/" + p.Name + "/"
	info := &jsonInfo{
		Name: p.Name, Version: rl.version, Classifiers: []string{}, PackageURL: page, ProjectURL: page, ReleaseURL: page,
		Downloads: map[string]int{"last_day": -1, "last_week": -1, "last_month": -1}, Yanked: rl.yanked(),
	}
	if info.Yanked {
		reason := rl.files[0].YankedReason
		info.YankedReason = &reason
	}
	files := slices.Clone(rl.files)
	slices.SortStableFunc(files, func(a, b *file) int {
		return boolRank(!strings.HasSuffix(a.Filename, ".whl")) - boolRank(!strings.HasSuffix(b.Filename, ".whl"))
	})
	for _, f := range files {
		if info.RequiresPython == "" {
			info.RequiresPython = f.RequiresPython
		}
	}
	var md *coreMetadata
	for _, f := range files {
		if b := h.readMetadata(ctx, actor, p.Name, f); b != nil {
			md = parseMetadata(b)
			break
		}
	}
	if md == nil {
		return info
	}
	if n := md.get("name"); n != "" {
		info.Name = n
	}
	info.Summary = md.get("summary")
	info.Description = md.description()
	info.Author, info.AuthorEmail = md.get("author"), md.get("author-email")
	info.Maintainer, info.MaintainerEmail = md.get("maintainer"), md.get("maintainer-email")
	info.License, info.Keywords = md.get("license"), md.get("keywords")
	info.HomePage, info.DownloadURL = md.get("home-page"), md.get("download-url")
	if rp := md.get("requires-python"); rp != "" {
		info.RequiresPython = rp
	}
	optional := func(name string) *string {
		if v := md.get(name); v != "" {
			return &v
		}
		return nil
	}
	info.DescriptionContentType = optional("description-content-type")
	info.LicenseExpression = optional("license-expression")
	info.Platform = optional("platform")
	if cs := md.all("classifier"); cs != nil {
		info.Classifiers = cs
	}
	info.RequiresDist = md.all("requires-dist")
	info.ProvidesExtra = md.all("provides-extra")
	info.Dynamic = md.all("dynamic")
	info.LicenseFiles = md.all("license-file")
	for _, pu := range md.all("project-url") {
		label, u, ok := strings.Cut(pu, ",")
		if !ok {
			continue
		}
		if info.ProjectURLs == nil {
			info.ProjectURLs = map[string]string{}
		}
		info.ProjectURLs[strings.TrimSpace(label)] = strings.TrimSpace(u)
	}
	return info
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// readMetadata returns a file's core metadata, or nil if it has none
// flint can get: a hosted file's stored metadata, or a proxy file's
// core-metadata file, cached or fetched.
func (h *Handler) readMetadata(ctx context.Context, actor, project string, f *file) []byte {
	var d blob.Digest
	switch {
	case f.rec != nil:
		d = f.rec.Meta
	case f.src != nil && f.src.proxy != nil && f.Metadata && f.MetadataSHA256 != "":
		if cd, _, ok := h.cachedBlob(metadataKey(f.src.name, f.Filename), project); ok {
			d = cd
			break
		}
		md, _ := blob.ParseDigest("sha256:" + f.MetadataSHA256)
		u, err := url.Parse(f.URL)
		if err != nil {
			return nil
		}
		u.Path += ".metadata"
		u.RawPath = ""
		body, err := h.fetchMetadata(ctx, actor, f.src, project, f.Filename, u.String(), md)
		if err != nil {
			h.log.DebugContext(ctx, "fetching core metadata for the JSON API failed", "file", f.Filename, "err", err)
			return nil
		}
		return body
	}
	if d.IsZero() {
		return nil
	}
	rc, err := h.blobs.Open(ctx, d)
	if err != nil {
		return nil
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxMetadataSize))
	if err != nil {
		return nil
	}
	return b
}

// serial returns the JSON API's last_serial for project in rp: the
// metadata sequence number of its latest change flint knows of.
func (h *Handler) serial(rp *repository, project string) int64 {
	v := h.view()
	defer v.Release()
	return h.serialIn(v, rp, project)
}

func (h *Handler) serialIn(v meta.View, rp *repository, project string) int64 {
	var s meta.Seq
	switch rp.typ {
	case config.TypeHosted:
		if rec, ok := v.Get(projectKey(rp.name, project)); ok {
			s = rec.Version
		}
		pfx := indexPrefix(rp.name, project)
		v.Scan(pfx, nil, func(k []byte, _ meta.Record) bool {
			if rec, ok := v.Get(fileKey(rp.name, string(k[len(pfx):]))); ok {
				s = max(s, rec.Version)
			}
			return true
		})
	case config.TypeProxy:
		if rec, ok := v.Get(upstream.DocKey(rp.name, project)); ok {
			s = rec.Version
		}
	case config.TypeVirtual:
		var out int64
		for _, m := range rp.virtual.Members {
			if mr := h.repos[m.Name]; mr != nil {
				out = max(out, h.serialIn(v, mr, project))
			}
		}
		return out
	}
	return int64(s)
}
