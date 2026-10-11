package cargo

import (
	"strconv"
	"strings"
)

// maxNameLen bounds a crate name, as crates.io does.
const maxNameLen = 64

// ValidCrateName reports whether s is a crate name flint accepts for
// publishing, by crates.io's rules: 1 to 64 ASCII letters, digits, "-",
// and "_", starting with a letter.
func ValidCrateName(s string) bool {
	if s == "" || len(s) > maxNameLen || !isLetter(s[0]) {
		return false
	}
	return nameChars(s)
}

// validIndexName reports whether s may name a crate in an index path or
// a download URL: 1 to 64 ASCII letters, digits, "-", and "_". It is
// looser than ValidCrateName because upstream registries and dependency
// names may not follow crates.io's rule about the first character.
func validIndexName(s string) bool {
	return s != "" && len(s) <= maxNameLen && nameChars(s)
}

func nameChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isLetter(c) && !(c >= '0' && c <= '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// Normalize returns the form in which crate names are compared: lowercase,
// with "-" and "_" equal, as crates.io compares them, so "Foo-Bar" and
// "foo_bar" are one crate. It keeps "*" as it is, for virtual repository
// member filters.
func Normalize(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "-", "_")
}

// indexPath returns the path of a crate's file in a sparse index, relative
// to the index root, for the crate's name as it is: "1/<name>",
// "2/<name>", "3/<c>/<name>", or "<ab>/<cd>/<name>". Cargo requests the
// lowercase form, which lowerName gives.
func indexPath(name string) string {
	return prefixOf(name) + "/" + name
}

// prefixOf returns the directory part of a crate's index path, as the
// {prefix} marker of a download URL template expands to.
func prefixOf(name string) string {
	switch len(name) {
	case 1:
		return "1"
	case 2:
		return "2"
	case 3:
		return "3/" + name[:1]
	}
	return name[:2] + "/" + name[2:4]
}

// parseIndexPath returns the crate name an index request path names,
// lowercase, or false if the path is not a crate's index path.
func parseIndexPath(p string) (string, bool) {
	p = strings.ToLower(p)
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return "", false
	}
	name := p[i+1:]
	if !validIndexName(name) || p[:i] != prefixOf(name) {
		return "", false
	}
	return name, true
}

// version is a parsed semantic version (SemVer 2.0.0), as Cargo requires
// every crate version to be.
type version struct {
	major, minor, patch uint64
	pre                 []string // dot-separated pre-release identifiers
	build               string   // build metadata, which never affects precedence
}

// parseVersion parses a semantic version, such as "1.2.3-rc.1+abc".
func parseVersion(s string) (version, bool) {
	var v version
	if len(s) > 256 {
		return v, false
	}
	core, build, hasBuild := strings.Cut(s, "+")
	if hasBuild {
		if !validIdents(build, false) {
			return v, false
		}
		v.build = build
	}
	core, pre, hasPre := strings.Cut(core, "-")
	if hasPre {
		if !validIdents(pre, true) {
			return v, false
		}
		v.pre = strings.Split(pre, ".")
	}
	nums := strings.Split(core, ".")
	if len(nums) != 3 {
		return v, false
	}
	var out [3]uint64
	for i, n := range nums {
		if !numeric(n) || len(n) > 1 && n[0] == '0' {
			return v, false
		}
		x, err := strconv.ParseUint(n, 10, 64)
		if err != nil {
			return v, false
		}
		out[i] = x
	}
	v.major, v.minor, v.patch = out[0], out[1], out[2]
	return v, true
}

// validIdents reports whether s is a dot-separated list of non-empty
// identifiers of ASCII letters, digits, and "-"; in a pre-release, a
// numeric identifier must not have a leading zero.
func validIdents(s string, pre bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for i := 0; i < len(id); i++ {
			if c := id[i]; !isLetter(c) && !(c >= '0' && c <= '9') && c != '-' {
				return false
			}
		}
		if pre && numeric(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

func numeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// key returns the version without build metadata: versions that differ
// only in build metadata are one version, as on crates.io.
func (v version) key() string {
	s := strconv.FormatUint(v.major, 10) + "." + strconv.FormatUint(v.minor, 10) + "." + strconv.FormatUint(v.patch, 10)
	if len(v.pre) > 0 {
		s += "-" + strings.Join(v.pre, ".")
	}
	return s
}

// canonicalVersion returns the key of version s, or s itself if it is not a
// semantic version.
func canonicalVersion(s string) string {
	if v, ok := parseVersion(s); ok {
		return v.key()
	}
	return s
}

// compare orders versions by SemVer precedence.
func (v version) compare(o version) int {
	for _, d := range [][2]uint64{{v.major, o.major}, {v.minor, o.minor}, {v.patch, o.patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(v.pre) == 0 && len(o.pre) == 0:
		return 0
	case len(v.pre) == 0:
		return 1
	case len(o.pre) == 0:
		return -1
	}
	for i := 0; i < len(v.pre) && i < len(o.pre); i++ {
		a, b := v.pre[i], o.pre[i]
		an, bn := numeric(a), numeric(b)
		switch {
		case an && bn:
			if len(a) != len(b) {
				if len(a) < len(b) {
					return -1
				}
				return 1
			}
			if c := strings.Compare(a, b); c != 0 {
				return c
			}
		case an:
			return -1
		case bn:
			return 1
		default:
			if c := strings.Compare(a, b); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(v.pre) < len(o.pre):
		return -1
	case len(v.pre) > len(o.pre):
		return 1
	}
	return 0
}

// compareVersions orders version strings by SemVer precedence, with
// strings that are not semantic versions first, in byte order.
func compareVersions(a, b string) int {
	va, oka := parseVersion(a)
	vb, okb := parseVersion(b)
	switch {
	case oka && okb:
		if c := va.compare(vb); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	case oka:
		return 1
	case okb:
		return -1
	}
	return strings.Compare(a, b)
}
