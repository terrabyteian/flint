package maven

import (
	"strconv"
	"strings"
)

// The Maven 2 repository layout. An artifact file is at
//
//	<groupId as path>/<artifactId>/<version>/<artifactId>-<version>[-<classifier>].<extension>
//
// such as com/acme/lib/1.0/lib-1.0-sources.jar. A snapshot version's files
// are deployed under unique timestamped names, in which the timestamp and
// build number replace "SNAPSHOT": lib-1.0-20261011.120000-3.jar in
// directory 1.0-SNAPSHOT. maven-metadata.xml sits in an artifact's
// directory (its versions), in a snapshot version's directory (its
// timestamped files), and in a group's directory (its plugins' prefixes).
// Every file has checksum sidecars, the file's name with ".md5", ".sha1",
// ".sha256", or ".sha512" appended.

// metadataName is the name of the metadata files.
const metadataName = "maven-metadata.xml"

// Checksum algorithms of sidecars, by extension.
const (
	algMD5    = "md5"
	algSHA1   = "sha1"
	algSHA256 = "sha256"
	algSHA512 = "sha512"
)

// sidecarAlgs are the sidecar algorithms, strongest first.
var sidecarAlgs = []string{algSHA512, algSHA256, algSHA1, algMD5}

// Path kinds.
const (
	kindOther    = iota // not in the layout, or a directory
	kindFile            // an artifact file
	kindMetadata        // a maven-metadata.xml file
	kindSidecar         // a checksum sidecar of a file or metadata file
)

// mpath is a parsed request path within a repository.
type mpath struct {
	path string // the path, without a leading "/"
	kind int
	// For kindSidecar: the algorithm and the parsed path of the file it
	// is a checksum of, of kindFile, kindMetadata, or kindOther.
	alg    string
	target *mpath
	// For kindMetadata: the directory's segments.
	dir []string
	// For kindFile: the file's coordinates.
	c *coords
}

// coords are the coordinates of an artifact file.
type coords struct {
	Group, Artifact string
	// Version is the version as its directory names it, such as
	// 1.0-SNAPSHOT.
	Version string
	// For a timestamped snapshot file, Timestamp (yyyyMMdd.HHmmss) and
	// Build (at least 1); NonUnique is set for a snapshot file named
	// with the "SNAPSHOT" version itself, which only Maven 2 deployed.
	Timestamp string
	Build     int
	NonUnique bool
	// Classifier, if any, and Extension, such as "jar" or "jar.asc".
	Classifier, Extension string
}

// name is the package name of the coordinates: groupId:artifactId.
func (c *coords) name() string { return c.Group + ":" + c.Artifact }

// value is the file's version as its name spells it: the version, or for
// a timestamped snapshot file the version with the timestamp and build
// number, such as 1.0-20261011.120000-3.
func (c *coords) value() string {
	if c.Timestamp == "" {
		return c.Version
	}
	return snapshotBase(c.Version) + c.Timestamp + "-" + strconv.Itoa(c.Build)
}

// snapshotBase is a snapshot version without "SNAPSHOT": "1.0-" for
// 1.0-SNAPSHOT.
func snapshotBase(version string) string { return version[:len(version)-len(snapshotSuffix)] }

// Path limits.
const (
	maxPath    = 1024
	maxSegment = 255
)

// validSegment reports whether s may be a path segment: 1 to 255
// printable ASCII characters, not "." or "..", and none of the
// characters that are special in URLs, file systems, or metadata keys.
func validSegment(s string) bool {
	if s == "" || len(s) > maxSegment || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c > '~' || strings.IndexByte(`/\%?#:"<>|*`, c) >= 0 {
			return false
		}
	}
	return true
}

// validName reports whether s may be a groupId segment or an artifactId:
// letters, digits, ".", "_", and "-", as Maven requires.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// parsePath parses a request path within a repository. ok is false for a
// path that is not a valid path at all; a valid path outside the layout,
// including a directory, is kindOther.
func parsePath(p string) (m *mpath, ok bool) {
	m = &mpath{path: p}
	switch {
	case p == "":
		return m, true // the repository's root directory
	case len(p) > maxPath:
		return nil, false
	}
	if strings.HasSuffix(p, "/") {
		for _, s := range strings.Split(strings.TrimSuffix(p, "/"), "/") {
			if !validSegment(s) {
				return nil, false
			}
		}
		return m, true
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if !validSegment(s) {
			return nil, false
		}
	}
	base := segs[len(segs)-1]
	for _, alg := range sidecarAlgs {
		if t, ok := strings.CutSuffix(base, "."+alg); ok && t != "" {
			target, _ := parsePath(p[:len(p)-len(alg)-1])
			if target.kind == kindSidecar {
				return m, true // a checksum of a checksum is not in the layout
			}
			m.kind, m.alg, m.target = kindSidecar, alg, target
			return m, true
		}
	}
	if base == metadataName {
		if len(segs) >= 2 {
			m.kind, m.dir = kindMetadata, segs[:len(segs)-1]
		}
		return m, true
	}
	if c := parseCoords(segs); c != nil {
		m.kind, m.c = kindFile, c
	}
	return m, true
}

// parseCoords parses the segments of an artifact file's path, or returns
// nil if they are not one.
func parseCoords(segs []string) *coords {
	if len(segs) < 4 {
		return nil
	}
	n := len(segs)
	c := &coords{Artifact: segs[n-3], Version: segs[n-2]}
	for _, g := range segs[:n-3] {
		if !validName(g) || strings.Contains(g, ".") {
			return nil
		}
	}
	if !validName(c.Artifact) {
		return nil
	}
	c.Group = strings.Join(segs[:n-3], ".")
	rest, ok := strings.CutPrefix(segs[n-1], c.Artifact+"-")
	if !ok {
		return nil
	}
	switch after, ok := strings.CutPrefix(rest, c.Version); {
	case ok && IsSnapshot(c.Version):
		c.NonUnique = true
		rest = after
	case ok:
		rest = after
	case IsSnapshot(c.Version):
		after, ok := strings.CutPrefix(rest, snapshotBase(c.Version))
		if !ok {
			return nil
		}
		ts, build, after, ok := cutTimestamp(after)
		if !ok {
			return nil
		}
		c.Timestamp, c.Build, rest = ts, build, after
	default:
		return nil
	}
	switch {
	case strings.HasPrefix(rest, "."):
		c.Extension = rest[1:]
	case strings.HasPrefix(rest, "-"):
		var ok bool
		c.Classifier, c.Extension, ok = strings.Cut(rest[1:], ".")
		if !ok || c.Classifier == "" {
			return nil
		}
	default:
		return nil
	}
	if c.Extension == "" || strings.HasPrefix(c.Extension, ".") || strings.HasSuffix(c.Extension, ".") {
		return nil
	}
	return c
}

// cutTimestamp cuts a snapshot timestamp and build number,
// "yyyyMMdd.HHmmss-<build>", from the start of s.
func cutTimestamp(s string) (ts string, build int, rest string, ok bool) {
	const tsLen = len("20060102.150405")
	if len(s) < tsLen+2 || s[8] != '.' || s[tsLen] != '-' {
		return "", 0, "", false
	}
	for i := 0; i < tsLen; i++ {
		if i != 8 && (s[i] < '0' || s[i] > '9') {
			return "", 0, "", false
		}
	}
	end := tsLen + 1
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	digits := s[tsLen+1 : end]
	if digits == "" || len(digits) > 9 || digits[0] == '0' {
		return "", 0, "", false
	}
	build, _ = strconv.Atoi(digits)
	return s[:tsLen], build, s[end:], true
}
