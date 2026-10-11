package cargo

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCrateNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"serde", true}, {"Serde_JSON", true}, {"a", true}, {"a-b_c9", true}, {strings.Repeat("a", 64), true},
		{"", false}, {"9lives", false}, {"_x", false}, {"-x", false}, {"a.b", false}, {"a b", false},
		{strings.Repeat("a", 65), false}, {"é", false},
	} {
		if got := ValidCrateName(tc.name); got != tc.valid {
			t.Errorf("ValidCrateName(%q) = %v", tc.name, got)
		}
	}
	if Normalize("Foo-Bar_baz") != "foo_bar_baz" || Normalize("acme-*") != "acme_*" {
		t.Error("Normalize")
	}
	for _, tc := range []struct{ name, path string }{
		{"a", "1/a"}, {"ab", "2/ab"}, {"abc", "3/a/abc"}, {"abcd", "ab/cd/abcd"}, {"serde_json", "se/rd/serde_json"},
	} {
		if got := indexPath(tc.name); got != tc.path {
			t.Errorf("indexPath(%q) = %q, want %q", tc.name, got, tc.path)
		}
		if got, ok := parseIndexPath(tc.path); !ok || got != tc.name {
			t.Errorf("parseIndexPath(%q) = %q, %v", tc.path, got, ok)
		}
	}
	if got, ok := parseIndexPath("Se/Rd/Serde"); !ok || got != "serde" {
		t.Errorf("parseIndexPath of a mixed-case path = %q, %v", got, ok)
	}
	for _, p := range []string{"", "1", "1/ab", "2/a", "3/b/abc", "ab/ce/abcd", "ab/cd/ef/abcd", "ab/cd/ab.d", "4/abcd"} {
		if _, ok := parseIndexPath(p); ok {
			t.Errorf("parseIndexPath(%q) accepted it", p)
		}
	}
}

func TestVersions(t *testing.T) {
	for _, s := range []string{"0.0.0", "1.2.3", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0.3.7", "1.0.0-x.7.z.92",
		"1.0.0+20130313144700", "1.0.0-beta+exp.sha.5114f85", "10.20.30", "1.0.0-a-b--c"} {
		if _, ok := parseVersion(s); !ok {
			t.Errorf("%q is a valid version", s)
		}
	}
	for _, s := range []string{"", "1", "1.0", "1.0.0.0", "01.0.0", "1.02.0", "1.0.0-", "1.0.0-01", "1.0.0+", "1.0.0-a..b",
		"v1.0.0", "1.0.0-é", " 1.0.0", "1.0.0+a+b", "99999999999999999999.0.0"} {
		if _, ok := parseVersion(s); ok {
			t.Errorf("%q is not a valid version", s)
		}
	}
	// SemVer's precedence example.
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0"}
	shuffled := slices.Clone(order)
	slices.Reverse(shuffled)
	slices.SortFunc(shuffled, compareVersions)
	if !slices.Equal(shuffled, order) {
		t.Errorf("sorted %v", shuffled)
	}
	if canonicalVersion("1.0.0-rc.1+build") != "1.0.0-rc.1" || canonicalVersion("x") != "x" {
		t.Error("canonicalVersion")
	}
	if compareVersions("1.0.0+a", "1.0.0+b") >= 0 || compareVersions("bad", "0.0.1") >= 0 {
		t.Error("compareVersions orders build metadata and invalid versions")
	}
}

func TestPublishLine(t *testing.T) {
	m := &publishMeta{Name: "a", Vers: "1.0.0", Features: map[string][]string{"x": nil, "y": {"a?/b"}}}
	l := m.line("00", time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC))
	if string(l.encode()) != `{"name":"a","vers":"1.0.0","deps":[],"cksum":"00","features":{"x":[]},"yanked":false,"v":2,`+
		`"features2":{"y":["a?/b"]},"pubtime":"2026-01-02T03:04:05Z"}` {
		t.Errorf("line %s", l.encode())
	}
	m.Features = nil
	if s := string(m.line("00", time.Time{}).encode()); strings.Contains(s, `"v"`) || !strings.Contains(s, `"features":{}`) {
		t.Errorf("line without features %s", s)
	}
}
