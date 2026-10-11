package cargo

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
)

// indexLine is a line of a crate's index file, as Cargo reads it: one
// version of the crate. Hosted repositories build it from the publish
// request's JSON, as the Cargo reference specifies, so flint never parses
// a Cargo.toml.
type indexLine struct {
	Name     string              `json:"name"`
	Vers     string              `json:"vers"`
	Deps     []indexDep          `json:"deps"`
	Cksum    string              `json:"cksum"`
	Features map[string][]string `json:"features"`
	Yanked   bool                `json:"yanked"`
	Links    *string             `json:"links,omitempty"`
	// V is the index format version: 2 when Features2 is set.
	V         int                 `json:"v,omitempty"`
	Features2 map[string][]string `json:"features2,omitempty"`
	// RustVersion is the minimum supported Rust version.
	RustVersion string `json:"rust_version,omitempty"`
	// Pubtime is when the version was published, in RFC 3339.
	Pubtime string `json:"pubtime,omitempty"`
}

// indexDep is a dependency in an index line.
type indexDep struct {
	Name            string   `json:"name"`
	Req             string   `json:"req"`
	Features        []string `json:"features"`
	Optional        bool     `json:"optional"`
	DefaultFeatures bool     `json:"default_features"`
	Target          *string  `json:"target"`
	Kind            string   `json:"kind"`
	// Registry is the index URL of the registry the dependency comes
	// from; nil means the registry the line is served by.
	Registry *string `json:"registry,omitempty"`
	// Package is the dependency's real name when Name is a rename.
	Package *string `json:"package,omitempty"`
}

// publishMeta is the JSON part of a publish request.
type publishMeta struct {
	Name        string              `json:"name"`
	Vers        string              `json:"vers"`
	Deps        []publishDep        `json:"deps"`
	Features    map[string][]string `json:"features"`
	Description *string             `json:"description"`
	Links       *string             `json:"links"`
	RustVersion *string             `json:"rust_version"`
}

// publishDep is a dependency in a publish request.
type publishDep struct {
	Name               string   `json:"name"`
	VersionReq         string   `json:"version_req"`
	Features           []string `json:"features"`
	Optional           bool     `json:"optional"`
	DefaultFeatures    bool     `json:"default_features"`
	Target             *string  `json:"target"`
	Kind               string   `json:"kind"`
	Registry           *string  `json:"registry"`
	ExplicitNameInToml *string  `json:"explicit_name_in_toml"`
}

// Limits of a publish request's JSON.
const (
	maxDeps     = 2048
	maxFeatures = 4096
	maxField    = 64 << 10 // a feature name, requirement, target, or URL
)

// check validates a publish request's JSON, returning an error that
// says what is wrong.
func (m *publishMeta) check() error {
	if !ValidCrateName(m.Name) {
		return errors.New("invalid crate name " + quote(m.Name) +
			": use 1 to 64 ASCII letters, digits, \"-\", and \"_\", starting with a letter")
	}
	if _, ok := parseVersion(m.Vers); !ok {
		return errors.New("invalid version " + quote(m.Vers) + ": it must be a semantic version, such as 1.0.0")
	}
	if len(m.Deps) > maxDeps {
		return errors.New("the crate has too many dependencies")
	}
	for _, d := range m.Deps {
		name := d.Name
		if d.ExplicitNameInToml != nil {
			name = *d.ExplicitNameInToml
		}
		switch {
		case !validIndexName(d.Name) || !validIndexName(name):
			return errors.New("invalid dependency name " + quote(name))
		case d.VersionReq == "" || len(d.VersionReq) > maxField:
			return errors.New("dependency " + d.Name + " has no valid version requirement")
		case d.Kind != "" && d.Kind != "normal" && d.Kind != "dev" && d.Kind != "build":
			return errors.New("dependency " + d.Name + " has an invalid kind " + quote(d.Kind))
		case d.Target != nil && len(*d.Target) > maxField, d.Registry != nil && len(*d.Registry) > maxField:
			return errors.New("dependency " + d.Name + " has a field that is too long")
		case len(d.Features) > maxFeatures:
			return errors.New("dependency " + d.Name + " has too many features")
		}
	}
	if len(m.Features) > maxFeatures {
		return errors.New("the crate has too many features")
	}
	for f, vals := range m.Features {
		if f == "" || len(f) > maxField || len(vals) > maxFeatures {
			return errors.New("invalid feature " + quote(f))
		}
	}
	if m.Links != nil && len(*m.Links) > maxField || m.RustVersion != nil && len(*m.RustVersion) > maxField {
		return errors.New("a field of the publish request is too long")
	}
	return nil
}

// line builds the index line of a published version, whose .crate file
// has sha256 digest cksum, as the Cargo reference specifies: features
// that use the "dep:" or "?/" syntax go in features2, with v 2, so older
// Cargo versions skip the version rather than misread it.
func (m *publishMeta) line(cksum string, published time.Time) *indexLine {
	l := &indexLine{Name: m.Name, Vers: m.Vers, Deps: []indexDep{}, Cksum: cksum, Features: map[string][]string{},
		Links: m.Links, Pubtime: published.UTC().Format(time.RFC3339)}
	if m.RustVersion != nil {
		l.RustVersion = *m.RustVersion
	}
	for _, d := range m.Deps {
		dep := indexDep{Name: d.Name, Req: d.VersionReq, Features: d.Features, Optional: d.Optional,
			DefaultFeatures: d.DefaultFeatures, Target: d.Target, Kind: d.Kind, Registry: d.Registry}
		if dep.Features == nil {
			dep.Features = []string{}
		}
		if dep.Kind == "" {
			dep.Kind = "normal"
		}
		if d.ExplicitNameInToml != nil {
			pkg := d.Name
			dep.Name, dep.Package = *d.ExplicitNameInToml, &pkg
		}
		l.Deps = append(l.Deps, dep)
	}
	for f, vals := range m.Features {
		if vals == nil {
			vals = []string{}
		}
		if slices.ContainsFunc(vals, func(v string) bool { return strings.HasPrefix(v, "dep:") || strings.Contains(v, "?/") }) {
			if l.Features2 == nil {
				l.Features2 = map[string][]string{}
			}
			l.Features2[f] = vals
			continue
		}
		l.Features[f] = vals
	}
	if l.Features2 != nil {
		l.V = 2
	}
	return l
}

// encode returns the line as JSON, without a trailing newline.
func (l *indexLine) encode() []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(l)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func decodeLine(b []byte) (*indexLine, error) {
	var l indexLine
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// entry is a line of an index file as flint reads it to merge index files
// and resolve downloads: its bytes, as served, and the fields flint uses.
type entry struct {
	raw   []byte
	name  string
	vers  string
	key   string // the version without build metadata
	cksum string // lowercase hex sha256 of the .crate file, if valid
	// src names the member repository that supplied the line, in a
	// virtual repository.
	src string
	// rec, for a hosted version, is its record.
	rec *versionRecord
}

// errBadIndex means an upstream index file could not be read.
var errBadIndex = errors.New("the upstream index file is not a valid sparse index file")

// parseIndex reads an index file: one JSON object per line, each naming
// the crate and a version. Lines of other crates, whose names do not
// lowercase to name, are left out, so an index file cannot speak for
// another crate. A line flint cannot read fails the whole file.
func parseIndex(b []byte, name string) ([]*entry, error) {
	var out []*entry
	for len(b) > 0 {
		var ln []byte
		ln, b, _ = bytes.Cut(b, []byte("\n"))
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		var l struct {
			Name  string `json:"name"`
			Vers  string `json:"vers"`
			Cksum string `json:"cksum"`
		}
		if err := json.Unmarshal(ln, &l); err != nil || l.Name == "" || l.Vers == "" {
			return nil, errBadIndex
		}
		if strings.ToLower(l.Name) != name {
			continue
		}
		e := &entry{raw: ln, name: l.Name, vers: l.Vers, key: canonicalVersion(l.Vers)}
		if c := strings.ToLower(l.Cksum); validSHA256(c) {
			e.cksum = c
		}
		out = append(out, e)
	}
	return out, nil
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// renderIndex writes entries as an index file, sorted by version.
func renderIndex(es []*entry) []byte {
	slices.SortStableFunc(es, func(a, b *entry) int { return compareVersions(a.vers, b.vers) })
	var b bytes.Buffer
	for _, e := range es {
		b.Write(e.raw)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// crates.io's index, by the URLs a dependency's registry field may name
// it with: Cargo names it by its git index URL, whichever protocol it
// reads it with.
var cratesIOIndexes = []string{"https://github.com/rust-lang/crates.io-index", "https://index.crates.io"}

// registryID returns the form in which index URLs are compared: without
// the "sparse+" or "registry+" scheme prefix, a trailing "/" or ".git",
// with the scheme and host lowercase.
func registryID(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "sparse+"), "registry+")
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s
	}
	p := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + p
}

// aliases returns the index URLs, as registryID forms them, that name the
// registry whose sparse index is at indexURL: its own, and for crates.io
// also its git index URL.
func aliases(indexURL string) []string {
	id := registryID(indexURL)
	if slices.Contains(cratesIOIndexes, id) {
		return cratesIOIndexes
	}
	return []string{id}
}

// localize rewrites the dependencies of l whose registry is one of
// registries, as registryID forms them, to the registry serving the line,
// and reports whether it changed any.
func (l *indexLine) localize(registries []string) bool {
	changed := false
	for i, d := range l.Deps {
		if d.Registry != nil && slices.Contains(registries, registryID(*d.Registry)) {
			l.Deps[i].Registry = nil
			changed = true
		}
	}
	return changed
}

// quote returns s in double quotes, shortened for messages.
func quote(s string) string {
	const max = 100
	if len(s) > max {
		s = s[:max] + "..."
	}
	b, _ := json.Marshal(s)
	return string(b)
}
