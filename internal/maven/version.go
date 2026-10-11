package maven

import (
	"slices"
	"strings"
)

// Maven's version order, which maven-metadata.xml lists versions in and
// which decides its latest and release versions. A version is split into
// items at ".", at "-", and where digits and letters meet; "-" and a
// transition start a nested list. Numbers compare numerically, and
// qualifiers in the order
//
//	alpha < beta < milestone < rc = cr < snapshot < "" = ga = final = release < sp
//
// with unknown qualifiers after sp, in lexical order, and "a1", "b1", and
// "m1" read as alpha-1, beta-1, and milestone-1. Trailing zeros and
// release qualifiers are dropped, so 1, 1.0, and 1-ga are one version.
// Letters compare case-insensitively.

// item kinds.
const (
	itemInt = iota
	itemString
	itemList
)

// item is a parsed version item: a number (its decimal digits, without
// leading zeros), a qualifier, or a nested list.
type item struct {
	kind int
	s    string  // itemInt: digits; itemString: the qualifier
	list []*item // itemList
}

// qualifiers are the known qualifiers, in order; "" is a release.
var qualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// qualifierAliases are other spellings of known qualifiers.
var qualifierAliases = map[string]string{"ga": "", "final": "", "release": "", "cr": "rc"}

func intItem(digits string) *item {
	digits = strings.TrimLeft(digits, "0")
	return &item{kind: itemInt, s: digits}
}

func stringItem(s string, followedByDigit bool) *item {
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	if a, ok := qualifierAliases[s]; ok {
		s = a
	}
	return &item{kind: itemString, s: s}
}

// isNull reports whether the item equals the absence of an item: zero,
// a release qualifier, or an empty list.
func (it *item) isNull() bool {
	switch it.kind {
	case itemInt:
		return it.s == ""
	case itemString:
		return it.s == ""
	}
	return len(it.list) == 0
}

// qualifierRank orders qualifiers: the index of a known one, and after
// every known one, an unknown one by its name.
func qualifierRank(q string) string {
	if i := slices.Index(qualifiers, q); i >= 0 {
		return string(rune('0' + i))
	}
	return string(rune('0'+len(qualifiers))) + "-" + q
}

// releaseRank is the rank of the release qualifier "".
var releaseRank = qualifierRank("")

// compareDigits compares two numbers written without leading zeros.
func compareDigits(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// compare compares it with other, which is nil for an absent item.
func (it *item) compare(other *item) int {
	switch it.kind {
	case itemInt:
		if other == nil {
			if it.s == "" {
				return 0
			}
			return 1
		}
		switch other.kind {
		case itemInt:
			return compareDigits(it.s, other.s)
		default: // 1.1 > 1-sp, 1.1 > 1-1
			return 1
		}
	case itemString:
		if other == nil {
			return strings.Compare(qualifierRank(it.s), releaseRank)
		}
		switch other.kind {
		case itemString:
			return strings.Compare(qualifierRank(it.s), qualifierRank(other.s))
		default: // 1.any < 1.1, 1.any < 1-1
			return -1
		}
	}
	if other == nil {
		if len(it.list) == 0 {
			return 0
		}
		return it.list[0].compare(nil)
	}
	switch other.kind {
	case itemInt: // 1-1 < 1.0.x
		return -1
	case itemString: // 1-1 > 1-sp
		return 1
	}
	for i := 0; i < len(it.list) || i < len(other.list); i++ {
		var l, r *item
		if i < len(it.list) {
			l = it.list[i]
		}
		if i < len(other.list) {
			r = other.list[i]
		}
		var c int
		switch {
		case l == nil && r == nil:
		case l == nil:
			c = -r.compare(l)
		default:
			c = l.compare(r)
		}
		if c != 0 {
			return c
		}
	}
	return 0
}

// normalize drops the trailing null items of a list, up to the last
// nested list.
func (it *item) normalize() {
	for i := len(it.list) - 1; i >= 0; i-- {
		if it.list[i].isNull() {
			it.list = slices.Delete(it.list, i, i+1)
		} else if it.list[i].kind != itemList {
			break
		}
	}
}

// parseVersion parses a version into its list of items.
func parseVersion(v string) *item {
	v = strings.ToLower(v)
	root := &item{kind: itemList}
	list := root
	stack := []*item{root}
	isDigit := false
	start := 0
	parseItem := func(digit bool, s string) *item {
		if digit {
			return intItem(s)
		}
		return stringItem(s, false)
	}
	push := func() {
		l := &item{kind: itemList}
		list.list = append(list.list, l)
		list = l
		stack = append(stack, l)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.':
			if i == start {
				list.list = append(list.list, intItem(""))
			} else {
				list.list = append(list.list, parseItem(isDigit, v[start:i]))
			}
			start = i + 1
		case c == '-':
			if i == start {
				list.list = append(list.list, intItem(""))
			} else {
				list.list = append(list.list, parseItem(isDigit, v[start:i]))
			}
			start = i + 1
			push()
		case c >= '0' && c <= '9':
			if !isDigit && i > start {
				list.list = append(list.list, stringItem(v[start:i], true))
				start = i
				push()
			}
			isDigit = true
		default:
			if isDigit && i > start {
				list.list = append(list.list, parseItem(true, v[start:i]))
				start = i
				push()
			}
			isDigit = false
		}
	}
	if len(v) > start {
		list.list = append(list.list, parseItem(isDigit, v[start:]))
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].normalize()
	}
	return root
}

// CompareVersions compares two versions in Maven's order, returning -1,
// 0, or 1.
func CompareVersions(a, b string) int {
	return parseVersion(a).compare(parseVersion(b))
}

// sortVersions sorts versions in Maven's order, keeping versions that
// compare equal in their given order.
func sortVersions(vs []string) {
	parsed := make(map[string]*item, len(vs))
	for _, v := range vs {
		parsed[v] = parseVersion(v)
	}
	slices.SortStableFunc(vs, func(a, b string) int { return parsed[a].compare(parsed[b]) })
}

// snapshotSuffix ends every snapshot version.
const snapshotSuffix = "SNAPSHOT"

// IsSnapshot reports whether version is a snapshot version: one ending
// in "SNAPSHOT", in any case, such as 1.0-SNAPSHOT.
func IsSnapshot(version string) bool {
	n := len(version) - len(snapshotSuffix)
	return n >= 0 && strings.EqualFold(version[n:], snapshotSuffix)
}
