package maven

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
)

func TestCompareVersions(t *testing.T) {
	// Each row is in ascending order; "=" joins versions that compare
	// equal. The rows follow Maven's version order specification.
	for _, row := range [][]string{
		{"1", "1.1"},
		{"1-snapshot", "1", "1-sp"},
		{"1-foo2", "1-foo10"},
		{"1.ga=1-ga=1-0=1.0=1=1.0.0=1-final=1-release"},
		{"1-ga", "1-sp"},
		{"1-ga.1", "1-sp.1"},
		{"1-a1=1-alpha-1=1-ALPHA-1", "1-b1=1-beta-1", "1-m1=1-milestone-1", "1-rc1=1-cr1=1-rc-1", "1-SNAPSHOT", "1", "1-sp1"},
		{"1.0-alpha", "1.0-beta", "1.0-milestone", "1.0-rc", "1.0-snapshot", "1.0", "1.0-sp", "1.0-foo", "1.0-zzz", "1.0.1"},
		{"1.9", "1.10", "1.10.1", "2", "10"},
		{"33.0.0-android", "33.0.0-jre", "33.1.0-jre"},
		{"1.0.0.0.1", "1.1"},
		{"1.9", "1.12345678901234567890", "1.12345678901234567891"},
		{"1-1", "1.1"},
		{"r03", "r05", "r10"},
		{"1.0", "1.0-20261011.120000-1", "1.0-20261011.120000-2"},
	} {
		var groups [][]string
		for _, g := range row {
			groups = append(groups, strings.Split(g, "="))
		}
		for i, g := range groups {
			for _, a := range g {
				for _, b := range g {
					if c := CompareVersions(a, b); c != 0 {
						t.Errorf("CompareVersions(%q, %q) = %d, want 0", a, b, c)
					}
				}
				for _, later := range groups[i+1:] {
					for _, b := range later {
						if c := CompareVersions(a, b); c != -1 {
							t.Errorf("CompareVersions(%q, %q) = %d, want -1", a, b, c)
						}
						if c := CompareVersions(b, a); c != 1 {
							t.Errorf("CompareVersions(%q, %q) = %d, want 1", b, a, c)
						}
					}
				}
			}
		}
	}
	vs := []string{"2.0", "1.0-SNAPSHOT", "1.10", "1.9", "1.0", "1.0-rc1"}
	sortVersions(vs)
	if want := []string{"1.0-rc1", "1.0-SNAPSHOT", "1.0", "1.9", "1.10", "2.0"}; !slices.Equal(vs, want) {
		t.Errorf("sortVersions = %q, want %q", vs, want)
	}
	for v, want := range map[string]bool{"1.0-SNAPSHOT": true, "SNAPSHOT": true, "1.0-snapshot": true, "1.0": false, "1.0-SNAPSHOTS": false} {
		if got := IsSnapshot(v); got != want {
			t.Errorf("IsSnapshot(%q) = %v", v, got)
		}
	}
}

func TestParsePath(t *testing.T) {
	type want struct {
		kind                  int
		group, artifact, ver  string
		ts                    string
		build                 int
		nonUnique             bool
		classifier, extension string
	}
	for _, tc := range []struct {
		path string
		want want
	}{
		{"com/acme/lib/1.0/lib-1.0.jar", want{kind: kindFile, group: "com.acme", artifact: "lib", ver: "1.0", extension: "jar"}},
		{"com/acme/lib/1.0/lib-1.0-sources.jar", want{kind: kindFile, group: "com.acme", artifact: "lib", ver: "1.0", classifier: "sources", extension: "jar"}},
		{"com/acme/lib/1.0/lib-1.0.tar.gz", want{kind: kindFile, group: "com.acme", artifact: "lib", ver: "1.0", extension: "tar.gz"}},
		{"com/acme/lib/1.0/lib-1.0.jar.asc", want{kind: kindFile, group: "com.acme", artifact: "lib", ver: "1.0", extension: "jar.asc"}},
		{"acme/lib/1.0/lib-1.0.module", want{kind: kindFile, group: "acme", artifact: "lib", ver: "1.0", extension: "module"}},
		{"com/acme/lib/1.0-SNAPSHOT/lib-1.0-20261011.120000-3.jar",
			want{kind: kindFile, group: "com.acme", artifact: "lib", ver: "1.0-SNAPSHOT", ts: "20261011.120000", build: 3, extension: "jar"}},
		{"com/acme/lib/1.0-SNAPSHOT/lib-1.0-20261011.120000-12-tests.jar",
			want{kind: kindFile, group: "com.acme", artifact: "lib", ver: "1.0-SNAPSHOT", ts: "20261011.120000", build: 12, classifier: "tests", extension: "jar"}},
		{"com/acme/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar",
			want{kind: kindFile, group: "com.acme", artifact: "lib", ver: "1.0-SNAPSHOT", nonUnique: true, extension: "jar"}},
		{"com/acme/lib/maven-metadata.xml", want{kind: kindMetadata}},
		{"com/acme/lib/1.0/lib-1.0.jar.sha1", want{kind: kindSidecar}},
		{"com/acme/lib/maven-metadata.xml.sha512", want{kind: kindSidecar}},
		{"com/acme/lib/", want{kind: kindOther}},
		{"archetype-catalog.xml", want{kind: kindOther}},
		{"maven-metadata.xml", want{kind: kindOther}},
		{"com/acme/lib/1.0/other-1.0.jar", want{kind: kindOther}},
		{"com/acme/lib/1.0/lib-1.1.jar", want{kind: kindOther}},
		{"com/acme/lib/1.0/lib-1.0", want{kind: kindOther}},
		{"com/acme/lib/1.0/lib-1.0-.jar", want{kind: kindOther}},
		{"com/acme/lib/1.0-SNAPSHOT/lib-1.0-2026.jar", want{kind: kindOther}},
		{"com/acme/lib/1.0-SNAPSHOT/lib-1.0-20261011.120000-0.jar", want{kind: kindOther}},
		{"com/acme/lib/1.0/lib-1.0.jar.sha1.md5", want{kind: kindOther}},
		{"com.acme/lib/1.0/lib-1.0.jar", want{kind: kindOther}},
	} {
		mp, ok := parsePath(tc.path)
		if !ok {
			t.Errorf("parsePath(%q) failed", tc.path)
			continue
		}
		got := want{kind: mp.kind}
		if c := mp.c; c != nil {
			got = want{kind: mp.kind, group: c.Group, artifact: c.Artifact, ver: c.Version, ts: c.Timestamp, build: c.Build,
				nonUnique: c.NonUnique, classifier: c.Classifier, extension: c.Extension}
		}
		if got != tc.want {
			t.Errorf("parsePath(%q) = %+v, want %+v", tc.path, got, tc.want)
		}
	}
	for _, p := range []string{"a//b", "../a", "a/./b", "a/b%2f", "a b/c", "a/\x00/b", "a/b:c", strings.Repeat("a/", 600)} {
		if _, ok := parsePath(p); ok {
			t.Errorf("parsePath(%q) accepted an invalid path", p)
		}
	}
	mp, _ := parsePath("com/acme/lib/1.0/lib-1.0.jar.sha256")
	if mp.alg != algSHA256 || mp.target.kind != kindFile || mp.target.c.Artifact != "lib" {
		t.Errorf("sidecar = %+v, target %+v", mp, mp.target)
	}
	mp, _ = parsePath("com/acme/lib/1.0-SNAPSHOT/lib-1.0-20261011.120000-3-tests.jar")
	if v := mp.c.value(); v != "1.0-20261011.120000-3" {
		t.Errorf("value = %q", v)
	}
}

func TestMetadataDocuments(t *testing.T) {
	t0 := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	m := artifactMetadata("com.acme", "lib", []versionEntry{{"1.10", t0}, {"2.0-SNAPSHOT", t0.Add(time.Hour)}, {"1.9", t0}}, time.Time{})
	b := encodeMetadata(m)
	got, err := parseMetadata(b)
	if err != nil {
		t.Fatal(err)
	}
	vs, updated := metadataVersions(got)
	if !slices.Equal(vs, []string{"1.9", "1.10", "2.0-SNAPSHOT"}) || got.Versioning.Latest != "2.0-SNAPSHOT" ||
		got.Versioning.Release != "1.10" || !updated.Equal(t0.Add(time.Hour)) || got.GroupID != "com.acme" {
		t.Errorf("artifact metadata:\n%s", b)
	}

	c := func(p string) *coords { mp, _ := parsePath(p); return mp.c }
	files := []snapshotFile{
		{c("com/acme/lib/1.0-SNAPSHOT/lib-1.0-20261011.120000-1.jar"), t0},
		{c("com/acme/lib/1.0-SNAPSHOT/lib-1.0-20261011.120000-1.pom"), t0},
		{c("com/acme/lib/1.0-SNAPSHOT/lib-1.0-20261011.130000-2.jar"), t0.Add(time.Hour)},
		{c("com/acme/lib/1.0-SNAPSHOT/lib-1.0-20261011.120000-1-sources.jar"), t0},
	}
	b = encodeMetadata(snapshotMetadata("com.acme", "lib", "1.0-SNAPSHOT", files))
	for _, s := range []string{"<timestamp>20261011.130000</timestamp>", "<buildNumber>2</buildNumber>",
		"<lastUpdated>20261011130000</lastUpdated>", "<version>1.0-SNAPSHOT</version>",
		"<extension>jar</extension>\n        <value>1.0-20261011.130000-2</value>",
		"<extension>pom</extension>\n        <value>1.0-20261011.120000-1</value>",
		"<classifier>sources</classifier>\n        <extension>jar</extension>\n        <value>1.0-20261011.120000-1</value>"} {
		if !bytes.Contains(b, []byte(s)) {
			t.Errorf("snapshot metadata lacks %q:\n%s", s, b)
		}
	}

	group := `<?xml version="1.0" encoding="ISO-8859-1"?>
<metadata xmlns="http://maven.apache.org/METADATA/1.1.0">
  <plugins>
    <plugin><name>Caf` + "\xe9" + ` Plugin</name><prefix>cafe</prefix><artifactId>cafe-maven-plugin</artifactId></plugin>
    <plugin><prefix>bad</prefix><artifactId>bad/id</artifactId></plugin>
  </plugins>
</metadata>`
	gm, err := parseMetadata([]byte(group))
	if err != nil {
		t.Fatal(err)
	}
	if ps := metadataPlugins(gm); len(ps) != 1 || ps[0] != (plugin{"cafe-maven-plugin", "cafe", "Café Plugin"}) {
		t.Errorf("plugins = %+v", ps)
	}
	for _, bad := range []string{"", "not xml", "<project/>", `<?xml version="1.0" encoding="EBCDIC"?><metadata/>`} {
		if _, err := parseMetadata([]byte(bad)); err == nil {
			t.Errorf("parseMetadata(%q) succeeded", bad)
		}
	}
}

func TestRecordsRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	f := &fileRecord{Kind: kindLive, Digest: digestOf("x"), Size: 1, MD5: []byte{1}, SHA1: []byte{2}, SHA512: []byte{3}, Uploaded: t0}
	if got, err := decodeFile(f.encode()); err != nil || got.Digest != f.Digest || !got.Uploaded.Equal(t0) || !bytes.Equal(got.SHA1, f.SHA1) {
		t.Errorf("file record = %+v, %v", got, err)
	}
	tomb := &fileRecord{Kind: kindTombstone, Deleted: t0}
	if got, err := decodeFile(tomb.encode()); err != nil || got.Kind != kindTombstone || !got.Deleted.Equal(t0) || !got.Digest.IsZero() {
		t.Errorf("tombstone = %+v, %v", got, err)
	}
	v := &versionRecord{Created: t0, Updated: t0, Snapshot: true, Timestamp: "20261011.120000", Build: 3, Files: 2}
	if got, err := decodeVersion(v.encode()); err != nil || *got != *v {
		t.Errorf("version record = %+v, %v", got, err)
	}
	p := &pluginRecord{Prefix: "acme", Name: "Acme"}
	if got, err := decodePlugin(p.encode()); err != nil || *got != *p {
		t.Errorf("plugin record = %+v, %v", got, err)
	}
	for _, b := range [][]byte{nil, {0}, {recordFormat}, {recordFormat, 9}, {recordFormat, kindLive, 0}, append(f.encode(), 0)} {
		if _, err := decodeFile(b); err == nil {
			t.Errorf("decodeFile(%x) succeeded", b)
		}
	}
}

// digestOf is the blob digest of s.
func digestOf(s string) blob.Digest { return blob.FromBytes([]byte(s)) }
