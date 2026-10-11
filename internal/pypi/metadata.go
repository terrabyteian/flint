package pypi

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// maxMetadataSize bounds a core-metadata file, which holds the project's
// long description.
const maxMetadataSize = 16 << 20

// errNoMetadata means a distribution holds no core metadata flint can read.
var errNoMetadata = errors.New("no core metadata found")

// wheelMetadata returns the core metadata of a wheel: the METADATA file of
// its single top-level .dist-info directory, which must name the project
// and version. A wheel without it is invalid.
func wheelMetadata(ra io.ReaderAt, size int64, project, version string) ([]byte, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, fmt.Errorf("the wheel is not a valid zip archive: %v", err)
	}
	var found *zip.File
	for _, f := range zr.File {
		dir, name, ok := strings.Cut(f.Name, "/")
		if !ok || name != "METADATA" || !strings.HasSuffix(dir, ".dist-info") {
			continue
		}
		stem := strings.TrimSuffix(dir, ".dist-info")
		i := strings.LastIndexByte(stem, '-')
		if i <= 0 || Normalize(stem[:i]) != project || canonicalVersion(stem[i+1:]) != canonicalVersion(version) {
			continue
		}
		if found != nil {
			return nil, errors.New("the wheel has more than one .dist-info/METADATA")
		}
		found = f
	}
	if found == nil {
		return nil, fmt.Errorf("the wheel has no %s-%s.dist-info/METADATA", project, version)
	}
	if found.UncompressedSize64 > maxMetadataSize {
		return nil, errors.New("the wheel's METADATA is too large")
	}
	rc, err := found.Open()
	if err != nil {
		return nil, fmt.Errorf("reading the wheel's METADATA: %v", err)
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxMetadataSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading the wheel's METADATA: %v", err)
	}
	if len(b) > maxMetadataSize {
		return nil, errors.New("the wheel's METADATA is too large")
	}
	if err := checkMetadata(parseMetadata(b), project, version); err != nil {
		return nil, fmt.Errorf("the wheel's METADATA %v", err)
	}
	return b, nil
}

// checkMetadata checks that metadata names project and version.
func checkMetadata(m *coreMetadata, project, version string) error {
	if Normalize(m.get("name")) != project {
		return fmt.Errorf("names project %q, not %s", m.get("name"), project)
	}
	if canonicalVersion(m.get("version")) != canonicalVersion(version) {
		return fmt.Errorf("names version %q, not %s", m.get("version"), version)
	}
	return nil
}

// sdistMetadata returns the core metadata of a source distribution: the
// PKG-INFO file in its top-level directory, if it names the project and
// version. A .tar.gz is read as a stream; a .zip needs ra.
func sdistMetadata(r io.Reader, ra io.ReaderAt, size int64, filename, project, version string) ([]byte, error) {
	var b []byte
	switch {
	case strings.HasSuffix(filename, ".tar.gz"):
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, errNoMetadata
		}
		tr := tar.NewReader(zr)
		for {
			hd, err := tr.Next()
			if err != nil {
				return nil, errNoMetadata
			}
			if !isPkgInfo(hd.Name) || hd.Typeflag != tar.TypeReg || hd.Size > maxMetadataSize {
				continue
			}
			if b, err = io.ReadAll(io.LimitReader(tr, maxMetadataSize)); err != nil {
				return nil, errNoMetadata
			}
			break
		}
	case strings.HasSuffix(filename, ".zip"):
		zr, err := zip.NewReader(ra, size)
		if err != nil {
			return nil, errNoMetadata
		}
		for _, f := range zr.File {
			if !isPkgInfo(f.Name) || f.UncompressedSize64 > maxMetadataSize {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, errNoMetadata
			}
			b, err = io.ReadAll(io.LimitReader(rc, maxMetadataSize))
			rc.Close()
			if err != nil {
				return nil, errNoMetadata
			}
			break
		}
	}
	if b == nil || checkMetadata(parseMetadata(b), project, version) != nil {
		return nil, errNoMetadata
	}
	return b, nil
}

// isPkgInfo reports whether an archive member is <top>/PKG-INFO.
func isPkgInfo(name string) bool {
	name = path.Clean(strings.TrimPrefix(name, "./"))
	dir, file, ok := strings.Cut(name, "/")
	return ok && dir != "" && file == "PKG-INFO"
}

// reliableSdistMetadata reports whether a source distribution's metadata
// may be served as its core-metadata file: PEP 643 makes it reliable
// from metadata version 2.2, for the fields not marked dynamic. flint
// serves it only with no dynamic fields, since installers take the file
// as the final word on dependencies.
func reliableSdistMetadata(m *coreMetadata) bool {
	return compareVersions(m.get("metadata-version"), "2.2") >= 0 && len(m.all("dynamic")) == 0
}

// coreMetadata is a parsed core-metadata file: email-header fields by
// lowercased name, and the body, which holds the description.
type coreMetadata struct {
	fields map[string][]string
	body   string
}

// parseMetadata parses a core-metadata file leniently: fields until the
// first empty line, continuation lines indented, and the rest as the
// body.
func parseMetadata(b []byte) *coreMetadata {
	m := &coreMetadata{fields: map[string][]string{}}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	var last string
	for s != "" {
		line, rest, _ := strings.Cut(s, "\n")
		s = rest
		if line == "" {
			m.body = s
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if vs := m.fields[last]; len(vs) > 0 {
				cont := strings.TrimLeft(line, " \t")
				if last == "description" {
					cont = strings.TrimPrefix(cont, "|")
				}
				vs[len(vs)-1] += "\n" + cont
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		last = strings.ToLower(strings.TrimSpace(name))
		m.fields[last] = append(m.fields[last], strings.TrimSpace(value))
	}
	return m
}

func (m *coreMetadata) get(name string) string {
	if vs := m.fields[name]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func (m *coreMetadata) all(name string) []string { return m.fields[name] }

// description returns the long description: the body, or the
// Description field of older metadata versions.
func (m *coreMetadata) description() string {
	if d := m.get("description"); d != "" {
		return d
	}
	return m.body
}

// formFields maps upload form fields to core-metadata field names, for
// the metadata synthesized from an upload whose distribution holds none.
var formFields = []struct{ form, field string }{
	{"summary", "Summary"},
	{"home_page", "Home-page"},
	{"download_url", "Download-URL"},
	{"author", "Author"},
	{"author_email", "Author-email"},
	{"maintainer", "Maintainer"},
	{"maintainer_email", "Maintainer-email"},
	{"license", "License"},
	{"license_expression", "License-Expression"},
	{"license_file", "License-File"},
	{"keywords", "Keywords"},
	{"platform", "Platform"},
	{"supported_platform", "Supported-Platform"},
	{"classifiers", "Classifier"},
	{"requires_dist", "Requires-Dist"},
	{"provides_dist", "Provides-Dist"},
	{"obsoletes_dist", "Obsoletes-Dist"},
	{"requires_external", "Requires-External"},
	{"requires_python", "Requires-Python"},
	{"project_urls", "Project-URL"},
	{"provides_extra", "Provides-Extra"},
	{"dynamic", "Dynamic"},
	{"description_content_type", "Description-Content-Type"},
}

// formMetadata writes core metadata from the fields of an upload form.
func formMetadata(form map[string][]string) []byte {
	var b bytes.Buffer
	mv := "2.1"
	if v := first(form, "metadata_version"); v != "" {
		mv = v
	}
	field := func(name, value string) {
		b.WriteString(name + ": " + strings.ReplaceAll(value, "\n", "\n        ") + "\n")
	}
	field("Metadata-Version", mv)
	field("Name", first(form, "name"))
	field("Version", first(form, "version"))
	for _, f := range formFields {
		for _, v := range form[f.form] {
			if v != "" && v != "UNKNOWN" {
				field(f.field, v)
			}
		}
	}
	b.WriteString("\n")
	b.WriteString(first(form, "description"))
	return b.Bytes()
}

func first(form map[string][]string, name string) string {
	if vs := form[name]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}
