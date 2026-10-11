package maven

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// maven-metadata.xml, as Maven's resolver and Gradle read and write it.
// flint generates it for hosted repositories from its records, merges it
// for virtual repositories, and serves proxy repositories' upstream
// copies verbatim.

// metadataXML is a maven-metadata.xml document: artifact-level (groupId,
// artifactId, versioning with versions), version-level for a snapshot
// (groupId, artifactId, version, versioning with the snapshot and its
// files), or group-level (plugins). Elements are written in the order
// Maven writes them.
type metadataXML struct {
	XMLName      xml.Name       `xml:"metadata"`
	ModelVersion string         `xml:"modelVersion,attr,omitempty"`
	GroupID      string         `xml:"groupId,omitempty"`
	ArtifactID   string         `xml:"artifactId,omitempty"`
	Version      string         `xml:"version,omitempty"`
	Versioning   *versioningXML `xml:"versioning,omitempty"`
	Plugins      *pluginsXML    `xml:"plugins,omitempty"`
}

type versioningXML struct {
	Latest           string               `xml:"latest,omitempty"`
	Release          string               `xml:"release,omitempty"`
	Snapshot         *snapshotXML         `xml:"snapshot,omitempty"`
	Versions         *versionsXML         `xml:"versions,omitempty"`
	LastUpdated      string               `xml:"lastUpdated,omitempty"`
	SnapshotVersions *snapshotVersionsXML `xml:"snapshotVersions,omitempty"`
}

type versionsXML struct {
	Version []string `xml:"version"`
}

type snapshotXML struct {
	Timestamp   string `xml:"timestamp,omitempty"`
	BuildNumber int    `xml:"buildNumber,omitempty"`
	LocalCopy   bool   `xml:"localCopy,omitempty"`
}

type snapshotVersionsXML struct {
	SnapshotVersion []snapshotVersionXML `xml:"snapshotVersion"`
}

type snapshotVersionXML struct {
	Classifier string `xml:"classifier,omitempty"`
	Extension  string `xml:"extension"`
	Value      string `xml:"value"`
	Updated    string `xml:"updated"`
}

type pluginsXML struct {
	Plugin []pluginXML `xml:"plugin"`
}

type pluginXML struct {
	Name       string `xml:"name,omitempty"`
	Prefix     string `xml:"prefix"`
	ArtifactID string `xml:"artifactId"`
}

// lastUpdatedLayout is the format of lastUpdated and updated: UTC
// yyyyMMddHHmmss.
const lastUpdatedLayout = "20060102150405"

// formatUpdated formats a time as lastUpdated.
func formatUpdated(t time.Time) string { return t.UTC().Format(lastUpdatedLayout) }

// encodeMetadata writes a document.
func encodeMetadata(m *metadataXML) []byte {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	enc := xml.NewEncoder(&b)
	enc.Indent("", "  ")
	if err := enc.Encode(m); err != nil {
		// The document holds only strings flint validated or read from
		// XML, which always encode.
		panic(fmt.Sprintf("maven: encoding metadata: %v", err))
	}
	b.WriteByte('\n')
	return b.Bytes()
}

// maxMetadata bounds a maven-metadata.xml document read from an upload or
// an upstream.
const maxMetadata = 16 << 20

// errBadMetadata means a document is not a maven-metadata.xml document.
var errBadMetadata = errors.New("not a valid maven-metadata.xml document")

// parseMetadata reads a maven-metadata.xml document.
func parseMetadata(b []byte) (*metadataXML, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.CharsetReader = charsetReader
	var m metadataXML
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", errBadMetadata, err)
	}
	trim := func(s *string) { *s = strings.TrimSpace(*s) }
	trim(&m.GroupID)
	trim(&m.ArtifactID)
	trim(&m.Version)
	if v := m.Versioning; v != nil {
		trim(&v.Latest)
		trim(&v.Release)
		trim(&v.LastUpdated)
		if v.Versions != nil {
			for i := range v.Versions.Version {
				trim(&v.Versions.Version[i])
			}
		}
	}
	if p := m.Plugins; p != nil {
		for i := range p.Plugin {
			trim(&p.Plugin[i].Name)
			trim(&p.Plugin[i].Prefix)
			trim(&p.Plugin[i].ArtifactID)
		}
	}
	return &m, nil
}

// charsetReader reads documents in the single-byte encodings old
// metadata declares, besides UTF-8, which encoding/xml reads itself.
func charsetReader(label string, r io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "iso-8859-1", "latin1", "latin-1", "us-ascii", "ascii", "windows-1252", "cp1252":
		return &latin1Reader{r: bufio.NewReader(r)}, nil
	}
	return nil, fmt.Errorf("unsupported encoding %q", label)
}

// latin1Reader converts ISO 8859-1 to UTF-8.
type latin1Reader struct {
	r   *bufio.Reader
	buf []byte
}

func (l *latin1Reader) Read(p []byte) (int, error) {
	for len(l.buf) == 0 {
		c, err := l.r.ReadByte()
		if err != nil {
			return 0, err
		}
		l.buf = utf8.AppendRune(l.buf[:0], rune(c))
	}
	n := copy(p, l.buf)
	l.buf = l.buf[n:]
	return n, nil
}

// versionEntry is a version an artifact-level document lists.
type versionEntry struct {
	Version string
	Updated time.Time // zero if unknown
}

// artifactMetadata generates an artifact's artifact-level document from
// its versions: listed in Maven's order, with latest the greatest and
// release the greatest that is not a snapshot.
func artifactMetadata(group, artifact string, versions []versionEntry, lastUpdated time.Time) *metadataXML {
	vs := make([]string, 0, len(versions))
	for _, v := range versions {
		vs = append(vs, v.Version)
		lastUpdated = laterOf(lastUpdated, v.Updated)
	}
	sortVersions(vs)
	vx := &versioningXML{Versions: &versionsXML{Version: vs}}
	if len(vs) > 0 {
		vx.Latest = vs[len(vs)-1]
	}
	for i := len(vs) - 1; i >= 0; i-- {
		if !IsSnapshot(vs[i]) {
			vx.Release = vs[i]
			break
		}
	}
	if !lastUpdated.IsZero() {
		vx.LastUpdated = formatUpdated(lastUpdated)
	}
	return &metadataXML{GroupID: group, ArtifactID: artifact, Versioning: vx}
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// snapshotFile is a timestamped file of a snapshot version.
type snapshotFile struct {
	c       *coords
	updated time.Time
}

// snapshotMetadata generates a snapshot version's version-level document
// from its timestamped files: the latest snapshot, and for each
// classifier and extension the latest file's version.
func snapshotMetadata(group, artifact, version string, files []snapshotFile) *metadataXML {
	newer := func(a, b *coords) bool { // a is later than b
		if a.Timestamp != b.Timestamp {
			return a.Timestamp > b.Timestamp
		}
		return a.Build > b.Build
	}
	var latest *coords
	var updated time.Time
	type ce struct{ classifier, extension string }
	byKind := map[ce]snapshotFile{}
	for _, f := range files {
		if latest == nil || newer(f.c, latest) {
			latest = f.c
		}
		updated = laterOf(updated, f.updated)
		k := ce{f.c.Classifier, f.c.Extension}
		if cur, ok := byKind[k]; !ok || newer(f.c, cur.c) {
			byKind[k] = f
		}
	}
	vx := &versioningXML{}
	if latest != nil {
		vx.Snapshot = &snapshotXML{Timestamp: latest.Timestamp, BuildNumber: latest.Build}
	}
	if !updated.IsZero() {
		vx.LastUpdated = formatUpdated(updated)
	}
	keys := make([]ce, 0, len(byKind))
	for k := range byKind {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b ce) int {
		if c := strings.Compare(a.extension, b.extension); c != 0 {
			return c
		}
		return strings.Compare(a.classifier, b.classifier)
	})
	if len(keys) > 0 {
		vx.SnapshotVersions = &snapshotVersionsXML{}
		for _, k := range keys {
			f := byKind[k]
			vx.SnapshotVersions.SnapshotVersion = append(vx.SnapshotVersions.SnapshotVersion, snapshotVersionXML{
				Classifier: k.classifier, Extension: k.extension, Value: f.c.value(), Updated: formatUpdated(f.updated)})
		}
	}
	return &metadataXML{ModelVersion: "1.1.0", GroupID: group, ArtifactID: artifact, Version: version, Versioning: vx}
}

// plugin is a plugin entry of group-level metadata.
type plugin struct {
	ArtifactID, Prefix, Name string
}

// pluginsMetadata returns the plugins element listing plugins, sorted by
// artifactId, or nil if there are none.
func pluginsMetadata(ps []plugin) *pluginsXML {
	if len(ps) == 0 {
		return nil
	}
	ps = slices.Clone(ps)
	slices.SortFunc(ps, func(a, b plugin) int { return strings.Compare(a.ArtifactID, b.ArtifactID) })
	out := &pluginsXML{}
	for _, p := range ps {
		out.Plugin = append(out.Plugin, pluginXML{Name: p.Name, Prefix: p.Prefix, ArtifactID: p.ArtifactID})
	}
	return out
}

// metadataVersions returns the versions an artifact-level document lists,
// and when it was last updated, zero if it does not say.
func metadataVersions(m *metadataXML) ([]string, time.Time) {
	if m == nil || m.Versioning == nil || m.Versioning.Versions == nil {
		return nil, time.Time{}
	}
	var out []string
	for _, v := range m.Versioning.Versions.Version {
		if v != "" {
			out = append(out, v)
		}
	}
	t, _ := time.Parse(lastUpdatedLayout, m.Versioning.LastUpdated)
	return out, t
}

// metadataPlugins returns the plugins a group-level document lists.
func metadataPlugins(m *metadataXML) []plugin {
	if m == nil || m.Plugins == nil {
		return nil
	}
	var out []plugin
	for _, p := range m.Plugins.Plugin {
		if validName(p.ArtifactID) && p.Prefix != "" {
			out = append(out, plugin{ArtifactID: p.ArtifactID, Prefix: p.Prefix, Name: p.Name})
		}
	}
	return out
}
