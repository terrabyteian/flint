package pypi

import (
	"cmp"
	"slices"
	"strings"
)

// version is a parsed PEP 440 version.
type version struct {
	epoch   string   // digits, without leading zeros; "" for 0
	release []string // digits, without leading zeros
	pre     string   // "a", "b", "rc", or "" for none
	preN    string
	post    bool
	postN   string
	dev     bool
	devN    string
	local   []string // lowercase segments, numeric ones without leading zeros
}

// parseVersion parses a version in any form PEP 440 accepts, such as
// "v1.0-RC1.post2.dev3+Ubuntu-1".
func parseVersion(s string) (*version, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "v")
	v := &version{}
	p := parser{s: s}
	// Epoch and release.
	n, ok := p.digits()
	if !ok {
		return nil, false
	}
	if p.eat("!") {
		if v.epoch = trimZeros(n); v.epoch == "0" {
			v.epoch = ""
		}
		if n, ok = p.digits(); !ok {
			return nil, false
		}
	}
	v.release = append(v.release, trimZeros(n))
	for p.peek('.') && p.digitAt(1) {
		p.i++
		n, _ = p.digits()
		v.release = append(v.release, trimZeros(n))
	}
	// Pre-release.
	save := p.i
	p.sep()
	if l, ok := p.word("alpha", "beta", "preview", "pre", "rc", "a", "b", "c"); ok {
		switch l {
		case "alpha", "a":
			v.pre = "a"
		case "beta", "b":
			v.pre = "b"
		default:
			v.pre = "rc"
		}
		v.preN = p.optNumber()
	} else {
		p.i = save
	}
	// Post-release: "-N", or "post", "rev", or "r" with an optional number.
	save = p.i
	if p.eat("-") && p.digitAt(0) {
		n, _ = p.digits()
		v.post, v.postN = true, trimZeros(n)
	} else {
		p.i = save
		p.sep()
		if _, ok := p.word("post", "rev", "r"); ok {
			v.post, v.postN = true, p.optNumber()
		} else {
			p.i = save
		}
	}
	// Development release.
	save = p.i
	p.sep()
	if _, ok := p.word("dev"); ok {
		v.dev, v.devN = true, p.optNumber()
	} else {
		p.i = save
	}
	// Local version label.
	if p.eat("+") {
		for {
			seg := p.alnum()
			if seg == "" {
				return nil, false
			}
			if isDigits(seg) {
				seg = trimZeros(seg)
			}
			v.local = append(v.local, seg)
			if !p.eatAny("-_.") {
				break
			}
		}
	}
	if p.i != len(p.s) {
		return nil, false
	}
	return v, true
}

// String returns the canonical form of v, as PEP 440 normalizes it.
func (v *version) String() string {
	var b strings.Builder
	if v.epoch != "" {
		b.WriteString(v.epoch + "!")
	}
	b.WriteString(strings.Join(v.release, "."))
	if v.pre != "" {
		b.WriteString(v.pre + v.preN)
	}
	if v.post {
		b.WriteString(".post" + v.postN)
	}
	if v.dev {
		b.WriteString(".dev" + v.devN)
	}
	if len(v.local) > 0 {
		b.WriteString("+" + strings.Join(v.local, "."))
	}
	return b.String()
}

// canonicalVersion returns s in the form that compares equal for equal
// versions: normalized, and without the release's trailing zeros, so
// "1.0" and "1" match. A string that is not a PEP 440 version is
// returned lowercased.
func canonicalVersion(s string) string {
	v, ok := parseVersion(s)
	if !ok {
		return strings.ToLower(strings.TrimSpace(s))
	}
	c := *v
	c.release = trimRelease(v.release)
	return c.String()
}

// prerelease reports whether v is a pre-release or development release.
func (v *version) prerelease() bool { return v.pre != "" || v.dev }

// compareVersions orders versions as PEP 440 does. Strings that are not
// valid versions sort before every valid one, among themselves as
// strings.
func compareVersions(a, b string) int {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return -1
	case !okB:
		return 1
	}
	return va.compare(vb)
}

func (v *version) compare(o *version) int {
	if c := cmpNum(v.epoch, o.epoch); c != 0 {
		return c
	}
	ra, rb := trimRelease(v.release), trimRelease(o.release)
	for i := 0; i < max(len(ra), len(rb)); i++ {
		x, y := "0", "0"
		if i < len(ra) {
			x = ra[i]
		}
		if i < len(rb) {
			y = rb[i]
		}
		if c := cmpNum(x, y); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(v.preRank(), o.preRank()); c != 0 {
		return c
	}
	if v.pre != "" && o.pre != "" {
		if c := cmpNum(v.preN, o.preN); c != 0 {
			return c
		}
	}
	if v.post != o.post {
		if v.post {
			return 1
		}
		return -1
	}
	if c := cmpNum(v.postN, o.postN); c != 0 {
		return c
	}
	if v.dev != o.dev {
		if v.dev {
			return -1
		}
		return 1
	}
	if c := cmpNum(v.devN, o.devN); c != 0 {
		return c
	}
	return compareLocal(v.local, o.local)
}

// preRank orders the pre-release part: a development release of a final
// release comes before its pre-releases, which come before the final
// release.
func (v *version) preRank() int {
	switch {
	case v.pre == "" && !v.post && v.dev:
		return 0
	case v.pre == "a":
		return 1
	case v.pre == "b":
		return 2
	case v.pre == "rc":
		return 3
	}
	return 4
}

// compareLocal orders local version labels: none sorts first; numeric
// segments sort after alphanumeric ones and compare as numbers.
func compareLocal(a, b []string) int {
	for i := 0; i < min(len(a), len(b)); i++ {
		na, nb := isDigits(a[i]), isDigits(b[i])
		var c int
		switch {
		case na && nb:
			c = cmpNum(a[i], b[i])
		case na:
			c = 1
		case nb:
			c = -1
		default:
			c = strings.Compare(a[i], b[i])
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

// sortVersions sorts versions in PEP 440 order, oldest first.
func sortVersions(vs []string) {
	slices.SortStableFunc(vs, compareVersions)
}

// cmpNum compares strings of digits without leading zeros ("" is 0).
func cmpNum(a, b string) int {
	if a == "" {
		a = "0"
	}
	if b == "" {
		b = "0"
	}
	if len(a) != len(b) {
		return cmp.Compare(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func trimZeros(n string) string {
	n = strings.TrimLeft(n, "0")
	if n == "" {
		return "0"
	}
	return n
}

// trimRelease drops the release's trailing zeros, keeping one part.
func trimRelease(r []string) []string {
	n := len(r)
	for n > 1 && r[n-1] == "0" {
		n--
	}
	return r[:n]
}

func isDigits(s string) bool {
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

// parser scans a lowercased version string.
type parser struct {
	s string
	i int
}

func (p *parser) peek(c byte) bool { return p.i < len(p.s) && p.s[p.i] == c }

func (p *parser) digitAt(off int) bool {
	j := p.i + off
	return j < len(p.s) && p.s[j] >= '0' && p.s[j] <= '9'
}

func (p *parser) eat(s string) bool {
	if strings.HasPrefix(p.s[p.i:], s) {
		p.i += len(s)
		return true
	}
	return false
}

func (p *parser) eatAny(set string) bool {
	if p.i < len(p.s) && strings.IndexByte(set, p.s[p.i]) >= 0 {
		p.i++
		return true
	}
	return false
}

// sep skips one optional separator.
func (p *parser) sep() { p.eatAny("-_.") }

func (p *parser) digits() (string, bool) {
	j := p.i
	for p.digitAt(0) {
		p.i++
	}
	// Bound the length so numbers stay comparable as strings without
	// trouble; real versions are far shorter.
	return p.s[j:p.i], p.i > j && p.i-j <= 64
}

// word consumes the first of words that the input continues with.
func (p *parser) word(words ...string) (string, bool) {
	for _, w := range words {
		if p.eat(w) {
			return w, true
		}
	}
	return "", false
}

// optNumber reads an optional separator and number, "0" if absent.
func (p *parser) optNumber() string {
	save := p.i
	p.sep()
	if n, ok := p.digits(); ok {
		return trimZeros(n)
	}
	p.i = save
	return "0"
}

func (p *parser) alnum() string {
	j := p.i
	for p.i < len(p.s) && (p.s[p.i] >= 'a' && p.s[p.i] <= 'z' || p.s[p.i] >= '0' && p.s[p.i] <= '9') {
		p.i++
	}
	return p.s[j:p.i]
}
