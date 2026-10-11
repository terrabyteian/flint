package pypi

import (
	"slices"
	"testing"
)

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"friendly-bard":     "friendly-bard",
		"Friendly-Bard":     "friendly-bard",
		"FRIENDLY-BARD":     "friendly-bard",
		"friendly.bard":     "friendly-bard",
		"friendly_bard":     "friendly-bard",
		"friendly--bard":    "friendly-bard",
		"FrIeNdLy-._.-bArD": "friendly-bard",
		"zope.interface":    "zope-interface",
		"a":                 "a",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidProjectName(t *testing.T) {
	for _, s := range []string{"a", "A1", "zope.interface", "my_pkg-2", "x" + string(make([]byte, 0))} {
		if !ValidProjectName(s) {
			t.Errorf("%q is not valid", s)
		}
	}
	for _, s := range []string{"", "-a", "a-", ".a", "a b", "ä", "a/b", "a\x00"} {
		if ValidProjectName(s) {
			t.Errorf("%q is valid", s)
		}
	}
	if !normalizedName("zope-interface") || normalizedName("zope.interface") || normalizedName("Zope") {
		t.Error("normalizedName is wrong")
	}
}

func TestValidFilename(t *testing.T) {
	for _, s := range []string{"a-1.0.tar.gz", "torch-2.4.0+cpu-cp312-cp312-linux_x86_64.whl", "a-1!2.0-py3-none-any.whl"} {
		if !validFilename(s) {
			t.Errorf("%q is not valid", s)
		}
	}
	for _, s := range []string{"", ".", "..", ".hidden", "a/b.whl", `a\b.whl`, "a b.whl", "a<b>.whl", "a\"b", "a?b", "a#b", "a%2f.whl", "ä.whl"} {
		if validFilename(s) {
			t.Errorf("%q is valid", s)
		}
	}
}

func TestParseFilename(t *testing.T) {
	for _, tt := range []struct {
		filename, project string
		want              distInfo
		ok                bool
	}{
		{"requests-2.32.3-py3-none-any.whl", "requests", distInfo{typeWheel, "requests", "2.32.3", "py3"}, true},
		{"zope.interface-7.0-cp312-cp312-macosx_11_0_arm64.whl", "zope-interface", distInfo{typeWheel, "zope.interface", "7.0", "cp312"}, true},
		{"my_pkg-1.0-1-py3-none-any.whl", "my-pkg", distInfo{typeWheel, "my_pkg", "1.0", "py3"}, true},
		{"my_pkg-1.0-x-py3-none-any.whl", "my-pkg", distInfo{}, false},
		{"other-1.0-py3-none-any.whl", "my-pkg", distInfo{typeWheel, "other", "1.0", "py3"}, false},
		{"bad.whl", "bad", distInfo{}, false},
		{"my-pkg-1.0.tar.gz", "my-pkg", distInfo{typeSdist, "my-pkg", "1.0", "source"}, true},
		{"My.Pkg-1.0-1.zip", "my-pkg", distInfo{typeSdist, "My.Pkg", "1.0-1", "source"}, true},
		{"my_pkg-1.0.tar.bz2", "my-pkg", distInfo{typeSdist, "my_pkg", "1.0", "source"}, true},
		{"my-pkg.tar.gz", "my-pkg", distInfo{typeSdist, "", "", "source"}, false},
		{"my-pkg-.tar.gz", "my-pkg", distInfo{typeSdist, "my-pkg", "", "source"}, false},
		{"setuptools-0.6c11-py2.7.egg", "setuptools", distInfo{typeEgg, "setuptools", "0.6c11", "py2.7"}, true},
		{"pywin32-306.win-amd64-py3.12.exe", "pywin32", distInfo{typeOther, "pywin32", "306.win-amd64-py3.12", ""}, true},
	} {
		got, ok := parseFilename(tt.filename, tt.project)
		if ok != tt.ok || (tt.want != distInfo{} && got != tt.want) {
			t.Errorf("parseFilename(%q, %q) = %+v, %v; want %+v, %v", tt.filename, tt.project, got, ok, tt.want, tt.ok)
		}
	}
}

func TestVersions(t *testing.T) {
	for in, want := range map[string]string{
		"1.0":              "1.0",
		"v1.0":             "1.0",
		" 1.0 ":            "1.0",
		"01.002.0003":      "1.2.3",
		"1!2.0":            "1!2.0",
		"0!1.0":            "1.0",
		"1.0a1":            "1.0a1",
		"1.0-ALPHA.1":      "1.0a1",
		"1.0beta":          "1.0b0",
		"1.0c1":            "1.0rc1",
		"1.0pre2":          "1.0rc2",
		"1.0preview-3":     "1.0rc3",
		"1.0-1":            "1.0.post1",
		"1.0.post":         "1.0.post0",
		"1.0rev4":          "1.0.post4",
		"1.0_r5":           "1.0.post5",
		"1.0.dev":          "1.0.dev0",
		"1.0-dev_6":        "1.0.dev6",
		"1.0a1.post2.dev3": "1.0a1.post2.dev3",
		"1.0+Ubuntu-1":     "1.0+ubuntu.1",
		"2.4.0+cpu":        "2.4.0+cpu",
	} {
		v, ok := parseVersion(in)
		if !ok {
			t.Errorf("parseVersion(%q) failed", in)
			continue
		}
		if got := v.String(); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "a", "1.", "1..0", "1.0+", "1.0+a..b", "1.0-", "1.0 x", "1.0.0.dev1dev2", "1.0 a1", "1!"} {
		if v, ok := parseVersion(in); ok {
			t.Errorf("parseVersion(%q) = %q, want failure", in, v)
		}
	}
	if canonicalVersion("1.0.0") != "1" || canonicalVersion("1.0") != canonicalVersion("1") || canonicalVersion("1.0.post0") != "1.post0" {
		t.Errorf("canonicalVersion: %q %q %q", canonicalVersion("1.0.0"), canonicalVersion("1.0"), canonicalVersion("1.0.post0"))
	}
	if canonicalVersion("Weird-Thing") != "weird-thing" {
		t.Errorf("canonicalVersion of a legacy version: %q", canonicalVersion("Weird-Thing"))
	}
}

func TestVersionOrder(t *testing.T) {
	// In PEP 440 order, from the spec's examples and packaging's tests.
	ordered := []string{
		"not-a-version",
		"1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2",
		"1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456", "1.0rc1", "1.0", "1.0+abc.5", "1.0+abc.7",
		"1.0+5", "1.0.post456.dev34", "1.0.post456", "1.0.15", "1.1.dev1", "1.2", "1.10", "2.0", "1!0.1",
	}
	got := slices.Clone(ordered)
	slices.Reverse(got)
	sortVersions(got)
	if !slices.Equal(got, ordered) {
		t.Errorf("sorted:\n%q\nwant\n%q", got, ordered)
	}
	for _, eq := range [][2]string{{"1.0", "1"}, {"1.0.0", "1.0"}, {"1.0a", "1.0a0"}, {"1.0+A", "1.0+a"}, {"1.0+01", "1.0+1"}} {
		if c := compareVersions(eq[0], eq[1]); c != 0 {
			t.Errorf("compareVersions(%q, %q) = %d, want 0", eq[0], eq[1], c)
		}
	}
	for s, pre := range map[string]bool{"1.0": false, "1.0a1": true, "1.0.dev1": true, "1.0.post1": false, "1.0rc1.post1": true} {
		if v, _ := parseVersion(s); v.prerelease() != pre {
			t.Errorf("%q prerelease = %v", s, !pre)
		}
	}
}
