package npm

import (
	"fmt"
	"strconv"
	"strings"
)

// maxNameLen bounds a package name, its scope included, as npm does.
const maxNameLen = 214

// ValidName reports whether name is a package name flint serves: an
// unscoped name, or "@scope/name". Each part is 1 or more characters that
// need no escaping in a URL, not starting with "." or "_". Uppercase
// letters and the characters ~'!()* are allowed, as they are in packages
// published before npm forbade them, which proxy repositories serve; a
// publish must also pass ValidNewName.
func ValidName(name string) bool {
	if name == "" || len(name) > maxNameLen {
		return false
	}
	scope, pkg, scoped := splitScope(name)
	if scoped && !validPart(scope, false) {
		return false
	}
	return validPart(pkg, false) && name != "-" && name != "node_modules" && name != "favicon.ico"
}

// ValidNewName reports whether name may be published: a ValidName in
// lowercase, without the characters ~'!()*, as npm requires of new
// packages.
func ValidNewName(name string) bool {
	if !ValidName(name) {
		return false
	}
	scope, pkg, scoped := splitScope(name)
	return (!scoped || validPart(scope, true)) && validPart(pkg, true)
}

// invalidName describes why name cannot be published.
func invalidName(name string) string {
	return fmt.Sprintf("invalid package name %q: use at most %d lowercase letters, digits, \"-\", \".\", and \"_\", "+
		"not starting with \".\" or \"_\", with an optional @scope/", abbrev(name), maxNameLen)
}

// splitScope splits "@scope/name" into scope and name, without "@". For
// an unscoped name, scoped is false and pkg is the name.
func splitScope(name string) (scope, pkg string, scoped bool) {
	rest, ok := strings.CutPrefix(name, "@")
	if !ok {
		return "", name, false
	}
	scope, pkg, ok = strings.Cut(rest, "/")
	if !ok {
		return "", "", true // "@x" alone: no part is valid
	}
	return scope, pkg, true
}

// validPart reports whether s is a valid scope or unscoped name part.
func validPart(s string, strict bool) bool {
	if s == "" || s[0] == '.' || s[0] == '_' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		case strict:
			return false
		case c >= 'A' && c <= 'Z', c == '~', c == '\'', c == '!', c == '(', c == ')', c == '*':
		default:
			return false
		}
	}
	return true
}

// unscoped returns a package name without its scope, as npm names
// tarballs: "name" for "@scope/name".
func unscoped(name string) string {
	if _, pkg, scoped := splitScope(name); scoped {
		return pkg
	}
	return name
}

// tarballName returns the file name of a version's tarball, as npm names
// it in tarball URLs: "<name without scope>-<version>.tgz".
func tarballName(name, version string) string {
	return unscoped(name) + "-" + version + ".tgz"
}

// tarballVersion returns the version that file, a tarball file name,
// names for package name: "<name without scope>-<version>.tgz", or with
// the scope, as npm names a publish's attachment. ok is false if file is
// not a tarball of the package.
func tarballVersion(name, file string) (version string, ok bool) {
	stem, ok := strings.CutSuffix(file, ".tgz")
	if !ok {
		return "", false
	}
	for _, prefix := range []string{unscoped(name) + "-", name + "-"} {
		if v, ok := strings.CutPrefix(stem, prefix); ok {
			if _, valid := parseVersion(v); valid {
				return v, true
			}
		}
	}
	return "", false
}

// maxTagLen bounds a dist-tag.
const maxTagLen = 128

// validTag reports whether s can be a dist-tag: a letter followed by
// letters, digits, ".", "_", and "-", that is not also a version or a
// version range such as "v1" or "x", which npm would read as one.
func validTag(s string) bool {
	if s == "" || len(s) > maxTagLen {
		return false
	}
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	if (c == 'v' || c == 'V') && len(s) > 1 && s[1] >= '0' && s[1] <= '9' {
		return false // v1, v1.2.x
	}
	return !rangeLike(s)
}

// rangeLike reports whether s is made of "x", "X", digits, and dots
// alone, such as "x" or "x.x", which npm reads as a version range.
func rangeLike(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != 'x' && c != 'X' && c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// maxVersionLen bounds a version string.
const maxVersionLen = 256

// version is a parsed semantic version (SemVer 2.0.0).
type version struct {
	major, minor, patch uint64
	pre                 []string // pre-release identifiers, or nil
}

// parseVersion parses a SemVer 2.0.0 version without build metadata,
// which npm strips before it publishes: "1.2.3" or "1.2.3-beta.1".
func parseVersion(s string) (version, bool) {
	var v version
	if s == "" || len(s) > maxVersionLen {
		return v, false
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, false
	}
	nums := [3]*uint64{&v.major, &v.minor, &v.patch}
	for i, p := range parts {
		n, ok := numericID(p)
		if !ok {
			return v, false
		}
		*nums[i] = n
	}
	if hasPre {
		v.pre = strings.Split(pre, ".")
		for _, id := range v.pre {
			if id == "" {
				return v, false
			}
			for j := 0; j < len(id); j++ {
				c := id[j]
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
					return v, false
				}
			}
			if isDigits(id) && len(id) > 1 && id[0] == '0' {
				return v, false // a numeric identifier has no leading zero
			}
		}
	}
	return v, true
}

// numericID parses a numeric version part: digits without a leading
// zero.
func numericID(s string) (uint64, bool) {
	if s == "" || !isDigits(s) || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// compare orders versions by SemVer precedence: -1, 0, or 1.
func (v version) compare(o version) int {
	for _, p := range [][2]uint64{{v.major, o.major}, {v.minor, o.minor}, {v.patch, o.patch}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(v.pre) == 0 && len(o.pre) == 0:
		return 0
	case len(v.pre) == 0:
		return 1 // a release follows its pre-releases
	case len(o.pre) == 0:
		return -1
	}
	for i := 0; i < len(v.pre) && i < len(o.pre); i++ {
		if c := compareID(v.pre[i], o.pre[i]); c != 0 {
			return c
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

// compareID orders pre-release identifiers: numeric ones numerically and
// before alphanumeric ones, which compare as strings.
func compareID(a, b string) int {
	an, bn := isDigits(a), isDigits(b)
	switch {
	case an && bn:
		if len(a) != len(b) {
			if len(a) < len(b) {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

// compareVersions orders version strings by SemVer precedence, with
// strings that do not parse first, in string order.
func compareVersions(a, b string) int {
	va, oka := parseVersion(a)
	vb, okb := parseVersion(b)
	switch {
	case oka && okb:
		if c := va.compare(vb); c != 0 {
			return c
		}
	case oka:
		return 1
	case okb:
		return -1
	}
	return strings.Compare(a, b)
}
