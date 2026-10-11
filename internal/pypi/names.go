package pypi

import (
	"strings"
)

// Normalize returns the PEP 503 normalized form of a project name:
// lowercase, with each run of "-", "_", and "." replaced by one "-".
func Normalize(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	sep := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '-' || c == '_' || c == '.':
			sep = true
			continue
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		}
		if sep {
			b.WriteByte('-')
			sep = false
		}
		b.WriteByte(c)
	}
	if sep {
		b.WriteByte('-')
	}
	return b.String()
}

// maxNameLen bounds project names.
const maxNameLen = 200

// ValidProjectName reports whether s is a valid project name (PEP 508):
// ASCII letters and digits, with ".", "_", and "-" allowed except at
// either end.
func ValidProjectName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || i == len(s)-1 || c != '.' && c != '_' && c != '-') {
			return false
		}
	}
	return true
}

// normalizedName reports whether s is a project name in normalized form,
// as project URLs and metadata keys use it.
func normalizedName(s string) bool {
	return ValidProjectName(s) && Normalize(s) == s
}

// maxFilenameLen bounds distribution file names.
const maxFilenameLen = 255

// validFilename reports whether s may name a distribution file: a single
// path component of printable ASCII without characters that need
// escaping in HTML or are unsafe in paths.
func validFilename(s string) bool {
	if s == "" || len(s) > maxFilenameLen || s == "." || s == ".." || strings.HasPrefix(s, ".") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`/\"'<>&?#%`, c) >= 0 {
			return false
		}
	}
	return true
}

// Package types, as PyPI's JSON API names them.
const (
	typeWheel = "bdist_wheel"
	typeSdist = "sdist"
	typeEgg   = "bdist_egg"
	typeOther = "bdist_dumb"
)

// sdistExts are the archive extensions of source distributions, longest
// first so ".tar.gz" wins over ".gz".
var sdistExts = []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.Z", ".tgz", ".tbz", ".zip", ".tar"}

// distInfo is what a distribution's file name says about it.
type distInfo struct {
	PackageType   string // typeWheel, typeSdist, typeEgg, or typeOther
	Name          string // the project name as written in the file name
	Version       string // "" if the file name does not say
	PythonVersion string // the wheel's or egg's Python tag, or "source"
}

// parseFilename reads the project name, version, and type from a
// distribution file name. project, the normalized project name, splits
// source distribution names, in which both the name and the version may
// contain "-". It reports false if the name does not belong to project.
func parseFilename(filename, project string) (distInfo, bool) {
	switch {
	case strings.HasSuffix(filename, ".whl"):
		// {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
		parts := strings.Split(strings.TrimSuffix(filename, ".whl"), "-")
		if len(parts) != 5 && len(parts) != 6 {
			return distInfo{}, false
		}
		if len(parts) == 6 && (parts[2] == "" || parts[2][0] < '0' || parts[2][0] > '9') {
			return distInfo{}, false // a build tag starts with a digit
		}
		for _, p := range parts {
			if p == "" {
				return distInfo{}, false
			}
		}
		d := distInfo{PackageType: typeWheel, Name: parts[0], Version: parts[1], PythonVersion: parts[len(parts)-3]}
		return d, Normalize(d.Name) == project
	case strings.HasSuffix(filename, ".egg"):
		// {name}-{version}(-py{X.Y}(-{platform})?)?.egg
		parts := strings.Split(strings.TrimSuffix(filename, ".egg"), "-")
		if len(parts) < 2 {
			return distInfo{}, false
		}
		d := distInfo{PackageType: typeEgg, Name: parts[0], Version: parts[1]}
		if len(parts) > 2 {
			d.PythonVersion = parts[2]
		}
		return d, Normalize(d.Name) == project
	}
	for _, ext := range sdistExts {
		if stem, ok := strings.CutSuffix(filename, ext); ok {
			name, version, ok := splitNameVersion(stem, project)
			return distInfo{PackageType: typeSdist, Name: name, Version: version, PythonVersion: "source"}, ok
		}
	}
	// Some other kind of file, such as a Windows installer: keep it
	// listed, with the version its name most likely carries.
	stem := filename
	if i := strings.LastIndexByte(stem, '.'); i > 0 {
		stem = stem[:i]
	}
	name, version, ok := splitNameVersion(stem, project)
	return distInfo{PackageType: typeOther, Name: name, Version: version}, ok
}

// splitNameVersion splits "{name}-{version}" at the first "-" whose prefix
// normalizes to project.
func splitNameVersion(stem, project string) (name, version string, ok bool) {
	for i := 0; i < len(stem); i++ {
		if stem[i] == '-' && Normalize(stem[:i]) == project {
			return stem[:i], stem[i+1:], i+1 < len(stem)
		}
	}
	return "", "", false
}
