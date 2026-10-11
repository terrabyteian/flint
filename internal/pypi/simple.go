package pypi

import (
	"bytes"
	"encoding/json"
	"html"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The simple repository API's media types (PEP 691), and the API version
// flint serves: 1.1 adds the project's versions and each file's size and
// upload time (PEP 700).
const (
	mtSimpleJSON = "application/vnd.pypi.simple.v1+json"
	mtSimpleHTML = "application/vnd.pypi.simple.v1+html"
	mtHTML       = "text/html"
	apiVersion   = "1.1"
)

// file is a distribution file as an index lists it. Proxy repositories
// store their cached project pages in this form (see projectDoc), so its
// JSON field names are part of the page format.
type file struct {
	Filename       string    `json:"filename"`
	URL            string    `json:"url,omitempty"` // a proxy's upstream URL for the file
	Version        string    `json:"version,omitempty"`
	SHA256         string    `json:"sha256,omitempty"` // lowercase hex; "" if unknown
	MD5            string    `json:"md5,omitempty"`
	Blake2b256     string    `json:"blake2b_256,omitempty"`
	Size           int64     `json:"size"` // -1 if unknown
	UploadTime     time.Time `json:"upload-time,omitzero"`
	RequiresPython string    `json:"requires-python,omitempty"`
	Yanked         bool      `json:"yanked,omitempty"`
	YankedReason   string    `json:"yanked-reason,omitempty"`
	// Metadata reports that a core-metadata file (PEP 658) is served for
	// the file, with MetadataSHA256 its digest if known.
	Metadata       bool   `json:"metadata,omitempty"`
	MetadataSHA256 string `json:"metadata-sha256,omitempty"`

	src *repository // the hosted or proxy repository that serves the file
	rec *fileRecord // a hosted file's record
}

// pageFormat is the version of projectDoc's JSON form.
const pageFormat = 1

// projectDoc is a project's files as one repository serves them.
type projectDoc struct {
	Format   int      `json:"flint-page"`
	Name     string   `json:"name"`     // the normalized name
	Versions []string `json:"versions"` // every version that has files, in PEP 440 order
	Files    []*file  `json:"files"`    // sorted by file name
}

// find returns the file called filename, or nil.
func (p *projectDoc) find(filename string) *file {
	i, ok := slices.BinarySearchFunc(p.Files, filename, func(f *file, name string) int { return strings.Compare(f.Filename, name) })
	if !ok {
		return nil
	}
	return p.Files[i]
}

// sortFiles sorts the files by name and fills in Versions from them,
// keeping versions the upstream listed without files.
func (p *projectDoc) finish() {
	slices.SortFunc(p.Files, func(a, b *file) int { return strings.Compare(a.Filename, b.Filename) })
	p.Files = slices.CompactFunc(p.Files, func(a, b *file) bool { return a.Filename == b.Filename })
	seen := map[string]bool{}
	var vs []string
	for _, v := range p.Versions {
		if c := canonicalVersion(v); !seen[c] {
			seen[c] = true
			vs = append(vs, v)
		}
	}
	for _, f := range p.Files {
		if c := canonicalVersion(f.Version); f.Version != "" && !seen[c] {
			seen[c] = true
			vs = append(vs, f.Version)
		}
	}
	sortVersions(vs)
	if vs == nil {
		vs = []string{}
	}
	p.Versions = vs
}

// negotiate picks the response format for a simple API request: the
// format query parameter if set, else the Accept header (PEP 691), else
// text/html. It reports false if the client accepts none of them.
func negotiate(r *http.Request) (string, bool) {
	if f := r.URL.Query().Get("format"); f != "" {
		// An unescaped "+" in the query reads as a space.
		switch f = strings.ReplaceAll(f, " ", "+"); f {
		case mtSimpleJSON, mtSimpleHTML, mtHTML:
			return f, true
		}
		return "", false
	}
	accept := r.Header.Values("Accept")
	if len(accept) == 0 {
		return mtHTML, true
	}
	type rank struct {
		q    float64
		spec int // 2 for an exact type, 1 for type/*, 0 for */*
		pos  int // position in the header; earlier wins
	}
	best := map[string]rank{}
	pos := 0
	for _, h := range accept {
		for item := range strings.SplitSeq(h, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(item))
			pos++
			if err != nil {
				continue
			}
			q := 1.0
			if s, ok := params["q"]; ok {
				if v, err := strconv.ParseFloat(s, 64); err == nil && v >= 0 && v <= 1 {
					q = v
				}
			}
			mt = strings.Replace(mt, ".latest+", ".v1+", 1)
			for _, cand := range []string{mtHTML, mtSimpleJSON, mtSimpleHTML} {
				typ, _, _ := strings.Cut(cand, "/")
				spec := -1
				switch mt {
				case cand:
					spec = 2
				case typ + "/*":
					spec = 1
				case "*/*":
					spec = 0
				}
				if spec < 0 {
					continue
				}
				cur, seen := best[cand]
				// The most specific matching entry decides the quality.
				if !seen || spec > cur.spec {
					best[cand] = rank{q, spec, pos}
				}
			}
		}
	}
	choice, top := "", rank{}
	for _, cand := range []string{mtHTML, mtSimpleJSON, mtSimpleHTML} {
		r, ok := best[cand]
		if !ok || r.q <= 0 {
			continue
		}
		if choice == "" || r.q > top.q || r.q == top.q && (r.spec > top.spec || r.spec == top.spec && r.pos < top.pos) {
			choice, top = cand, r
		}
	}
	return choice, choice != ""
}

// contentType returns the Content-Type header of a simple API format.
func contentType(format string) string {
	if format == mtHTML {
		return "text/html; charset=utf-8"
	}
	return format
}

// formatTime formats an upload time as PEP 700 asks: RFC 3339 in UTC.
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.999999Z07:00")
}

// fileURL returns the link from a project page, at
// /pypi/<repo>/simple/<project>/, to a file of the project.
func fileURL(project, filename string) string {
	return "../../files/" + project + "/" + url.PathEscape(filename)
}

// renderProject renders a project page in format.
func renderProject(p *projectDoc, format string) []byte {
	var b bytes.Buffer
	if format == mtSimpleJSON {
		type jsonFile struct {
			Filename       string            `json:"filename"`
			URL            string            `json:"url"`
			Hashes         map[string]string `json:"hashes"`
			RequiresPython string            `json:"requires-python,omitempty"`
			CoreMetadata   any               `json:"core-metadata,omitempty"`
			DistInfoMeta   any               `json:"dist-info-metadata,omitempty"`
			Yanked         any               `json:"yanked"`
			Size           *int64            `json:"size,omitempty"`
			UploadTime     string            `json:"upload-time,omitempty"`
		}
		out := struct {
			Meta     map[string]string `json:"meta"`
			Name     string            `json:"name"`
			Versions []string          `json:"versions"`
			Files    []jsonFile        `json:"files"`
		}{Meta: map[string]string{"api-version": apiVersion}, Name: p.Name, Versions: p.Versions, Files: make([]jsonFile, 0, len(p.Files))}
		for _, f := range p.Files {
			jf := jsonFile{Filename: f.Filename, URL: fileURL(p.Name, f.Filename), Hashes: map[string]string{},
				RequiresPython: f.RequiresPython, Yanked: false}
			if f.SHA256 != "" {
				jf.Hashes["sha256"] = f.SHA256
			}
			if f.Metadata {
				var m any = true
				if f.MetadataSHA256 != "" {
					m = map[string]string{"sha256": f.MetadataSHA256}
				}
				jf.CoreMetadata, jf.DistInfoMeta = m, m
			}
			if f.Yanked {
				jf.Yanked = true
				if f.YankedReason != "" {
					jf.Yanked = f.YankedReason
				}
			}
			if f.Size >= 0 {
				jf.Size = &f.Size
			}
			if !f.UploadTime.IsZero() {
				jf.UploadTime = formatTime(f.UploadTime)
			}
			out.Files = append(out.Files, jf)
		}
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.Encode(out)
		return b.Bytes()
	}
	name := html.EscapeString(p.Name)
	b.WriteString("<!DOCTYPE html>\n<html>\n  <head>\n    <meta name=\"pypi:repository-version\" content=\"" + apiVersion + "\">\n")
	b.WriteString("    <title>Links for " + name + "</title>\n  </head>\n  <body>\n    <h1>Links for " + name + "</h1>\n")
	for _, f := range p.Files {
		href := fileURL(p.Name, f.Filename)
		if f.SHA256 != "" {
			href += "#sha256=" + f.SHA256
		}
		b.WriteString(`    <a href="` + html.EscapeString(href) + `"`)
		if f.RequiresPython != "" {
			b.WriteString(` data-requires-python="` + html.EscapeString(f.RequiresPython) + `"`)
		}
		if f.Metadata {
			v := "true"
			if f.MetadataSHA256 != "" {
				v = "sha256=" + f.MetadataSHA256
			}
			b.WriteString(` data-dist-info-metadata="` + v + `" data-core-metadata="` + v + `"`)
		}
		if f.Yanked {
			b.WriteString(` data-yanked="` + html.EscapeString(f.YankedReason) + `"`)
		}
		b.WriteString(">" + html.EscapeString(f.Filename) + "</a><br>\n")
	}
	b.WriteString("  </body>\n</html>\n")
	return b.Bytes()
}

// renderIndex renders the root index, listing projects by normalized
// name, in format.
func renderIndex(projects []string, format string) []byte {
	var b bytes.Buffer
	if format == mtSimpleJSON {
		type project struct {
			Name string `json:"name"`
		}
		out := struct {
			Meta     map[string]string `json:"meta"`
			Projects []project         `json:"projects"`
		}{Meta: map[string]string{"api-version": apiVersion}, Projects: make([]project, 0, len(projects))}
		for _, p := range projects {
			out.Projects = append(out.Projects, project{p})
		}
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.Encode(out)
		return b.Bytes()
	}
	b.WriteString("<!DOCTYPE html>\n<html>\n  <head>\n    <meta name=\"pypi:repository-version\" content=\"" + apiVersion + "\">\n")
	b.WriteString("    <title>Simple index</title>\n  </head>\n  <body>\n")
	for _, p := range projects {
		e := html.EscapeString(p)
		b.WriteString(`    <a href="` + e + `/">` + e + "</a><br>\n")
	}
	b.WriteString("  </body>\n</html>\n")
	return b.Bytes()
}
