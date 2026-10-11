package maven

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// upstreamMetadata is an artifact-level document listing versions.
func upstreamMetadata(group, id string, versions ...string) []byte {
	var vs strings.Builder
	for _, v := range versions {
		fmt.Fprintf(&vs, "<version>%s</version>", v)
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><metadata><groupId>%s</groupId><artifactId>%s</artifactId>`+
		`<versioning><latest>%s</latest><versions>%s</versions><lastUpdated>20261001120000</lastUpdated></versioning></metadata>`,
		group, id, versions[len(versions)-1], vs.String()))
}

func versionsOf(t *testing.T, doc string) (vs []string, latest, release string) {
	t.Helper()
	m, err := parseMetadata([]byte(doc))
	if err != nil {
		t.Fatalf("%v:\n%s", err, doc)
	}
	vs, _ = metadataVersions(m)
	if m.Versioning != nil {
		latest, release = m.Versioning.Latest, m.Versioning.Release
	}
	return vs, latest, release
}

func TestVirtualMergesVersions(t *testing.T) {
	e := newEnv(t)
	e.up.put("/maven2/org/demo/lib/maven-metadata.xml", upstreamMetadata("org.demo", "lib", "1.0", "1.1", "3.0-SNAPSHOT"))
	for _, v := range []string{"1.0", "1.1"} {
		e.up.put("/maven2/"+artifact("org.demo", "lib", v, "lib-"+v+".jar"), []byte("upstream "+v))
	}
	e.deploy("releases", artifact("org.demo", "lib", "1.1", "lib-1.1.jar"), []byte("hosted 1.1"))
	e.deploy("releases", artifact("org.demo", "lib", "2.0", "lib-2.0.jar"), []byte("hosted 2.0"))

	// Without dependency-confusion protection, the versions merge, and
	// latest and release are computed from the merged list.
	md := e.get("/maven/open/org/demo/lib/maven-metadata.xml", http.StatusOK)
	vs, latest, release := versionsOf(t, md.body)
	if !slices.Equal(vs, []string{"1.0", "1.1", "2.0", "3.0-SNAPSHOT"}) || latest != "3.0-SNAPSHOT" || release != "2.0" {
		t.Errorf("merged versions %q, latest %q, release %q", vs, latest, release)
	}
	e.want("GET", "/maven/open/org/demo/lib/maven-metadata.xml.sha1", nil, http.StatusOK, hexSum(algSHA1, []byte(md.body)))
	// A version both have comes from the first member.
	e.want("GET", "/maven/open/"+artifact("org.demo", "lib", "1.1", "lib-1.1.jar"), nil, http.StatusOK, "hosted 1.1")
	e.want("GET", "/maven/open/"+artifact("org.demo", "lib", "1.1", "lib-1.1.jar.sha1"), nil, http.StatusOK, hexSum(algSHA1, []byte("hosted 1.1")))
	e.want("GET", "/maven/open/"+artifact("org.demo", "lib", "1.0", "lib-1.0.jar"), nil, http.StatusOK, "upstream 1.0")
	// The hosted member lists 1.1, so it alone serves its files.
	e.up.put("/maven2/"+artifact("org.demo", "lib", "1.1", "lib-1.1-sources.jar"), []byte("upstream sources"))
	e.get("/maven/open/"+artifact("org.demo", "lib", "1.1", "lib-1.1-sources.jar"), http.StatusNotFound)

	// With protection, the hosted member owns org.demo:lib, so the proxy
	// is never asked about it.
	e.up.took()
	md = e.get("/maven/all/org/demo/lib/maven-metadata.xml", http.StatusOK)
	if vs, _, _ := versionsOf(t, md.body); !slices.Equal(vs, []string{"1.1", "2.0"}) {
		t.Errorf("protected versions %q", vs)
	}
	e.get("/maven/all/"+artifact("org.demo", "lib", "1.0", "lib-1.0.jar"), http.StatusNotFound)
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("the proxy was asked about an artifact a hosted member owns: %q", got)
	}
	// Once every file is deleted the hosted member still owns it.
	e.want("DELETE", "/maven/releases/org/demo/lib/1.1/", nil, http.StatusNoContent, "")
	e.want("DELETE", "/maven/releases/org/demo/lib/2.0/", nil, http.StatusNoContent, "")
	e.get("/maven/all/org/demo/lib/maven-metadata.xml", http.StatusNotFound)
	e.get("/maven/all/"+artifact("org.demo", "lib", "1.0", "lib-1.0.jar"), http.StatusNotFound)
}

func TestVirtualFilters(t *testing.T) {
	e := newEnv(t)
	// "all" excludes com.acme.* from the proxy: an internal group not
	// deployed yet can never be served from upstream.
	e.up.put("/maven2/com/acme/evil/maven-metadata.xml", upstreamMetadata("com.acme", "evil", "9.9"))
	e.up.put("/maven2/"+artifact("com.acme", "evil", "9.9", "evil-9.9.jar"), []byte("evil"))
	e.up.put("/maven2/"+artifact("org.ok", "lib", "1.0", "lib-1.0.jar"), []byte("ok"))
	e.get("/maven/all/com/acme/evil/maven-metadata.xml", http.StatusNotFound)
	e.get("/maven/all/"+artifact("com.acme", "evil", "9.9", "evil-9.9.jar"), http.StatusNotFound)
	e.want("GET", "/maven/all/"+artifact("org.ok", "lib", "1.0", "lib-1.0.jar"), nil, http.StatusOK, "ok")
	if got := e.up.took(); !slices.Equal(got, []string{"GET /maven2/" + artifact("org.ok", "lib", "1.0", "lib-1.0.jar")}) {
		t.Errorf("upstream requests %q", got)
	}

	// Publishing through a virtual repository is refused for a name its
	// publishTo member's filters do not admit.
	e.put("/maven/scoped/"+artifact("com.acme", "lib", "1.0", "lib-1.0.jar"), []byte("ok"), http.StatusCreated)
	e.get("/maven/mixed/"+artifact("com.acme", "lib", "1.0", "lib-1.0.jar"), http.StatusOK)
	r := e.put("/maven/scoped/"+artifact("org.other", "lib", "1.0", "lib-1.0.jar"), []byte("no"), http.StatusForbidden)
	if !strings.Contains(r.body, "include filter") {
		t.Errorf("403 body %q", r.body)
	}
	e.put("/maven/scoped/org/other/plugins/maven-metadata.xml",
		[]byte(`<metadata><plugins><plugin><prefix>x</prefix><artifactId>x-maven-plugin</artifactId></plugin></plugins></metadata>`),
		http.StatusForbidden)
}

func TestVirtualSkipsFailingMembers(t *testing.T) {
	e := newEnv(t)
	path := artifact("org.demo", "lib", "1.0", "lib-1.0.jar")
	e.plain.put("/repo/"+path, []byte("from plain"))
	e.plain.put("/repo/org/demo/lib/maven-metadata.xml", upstreamMetadata("org.demo", "lib", "1.0"))
	e.up.set(func(u *fakeRepo) { u.down = true })
	e.want("GET", "/maven/both/"+path, nil, http.StatusOK, "from plain")
	md := e.get("/maven/both/org/demo/lib/maven-metadata.xml", http.StatusOK)
	if vs, _, _ := versionsOf(t, md.body); !slices.Equal(vs, []string{"1.0"}) {
		t.Errorf("versions %q", vs)
	}
	if got := e.metric(`flint_virtual_member_skips_total{repository="both",member="central"}`); got != "2" {
		t.Errorf("skips = %q, want 2", got)
	}
	// When every member fails, the failure is answered.
	e.plain.set(func(u *fakeRepo) { u.down = true })
	other := artifact("org.demo", "other", "1.0", "other-1.0.jar")
	if r := e.do("GET", "/maven/both/"+other, nil); r.code != http.StatusServiceUnavailable && r.code != http.StatusBadGateway {
		t.Errorf("all members down: %d %q", r.code, r.body)
	}
	if r := e.do("GET", "/maven/both/org/demo/other/maven-metadata.xml", nil); r.code != http.StatusServiceUnavailable && r.code != http.StatusBadGateway {
		t.Errorf("all members down: %d %q", r.code, r.body)
	}
	// Cached content keeps being served.
	e.want("GET", "/maven/both/"+path, nil, http.StatusOK, "from plain")
}

func TestVirtualSnapshotsAndPlugins(t *testing.T) {
	e := newEnv(t)
	dir := "com/acme/lib/1.0-SNAPSHOT/"
	e.deploy("snapshots", dir+"lib-1.0-20261011.120000-1.jar", []byte("snapshot"))
	e.deploy("snapshots", dir+"lib-1.0-20261011.120000-1.pom", []byte("<project/>"))
	md := e.get("/maven/all/"+dir+"maven-metadata.xml", http.StatusOK)
	if !strings.Contains(md.body, "<buildNumber>1</buildNumber>") {
		t.Errorf("snapshot metadata:\n%s", md.body)
	}
	e.want("GET", "/maven/all/"+dir+"maven-metadata.xml.md5", nil, http.StatusOK, hexSum(algMD5, []byte(md.body)))
	e.want("GET", "/maven/all/"+dir+"lib-1.0-20261011.120000-1.jar", nil, http.StatusOK, "snapshot")
	if vs, latest, release := versionsOf(t, e.get("/maven/all/com/acme/lib/maven-metadata.xml", http.StatusOK).body); !slices.Equal(vs, []string{"1.0-SNAPSHOT"}) ||
		latest != "1.0-SNAPSHOT" || release != "" {
		t.Errorf("versions %q, latest %q, release %q", vs, latest, release)
	}
	// A snapshot only the proxy has comes from it.
	updir := "org/demo/lib/2.0-SNAPSHOT/"
	upmd := []byte(`<metadata><groupId>org.demo</groupId><artifactId>lib</artifactId><version>2.0-SNAPSHOT</version>` +
		`<versioning><snapshot><timestamp>20261011.120000</timestamp><buildNumber>7</buildNumber></snapshot></versioning></metadata>`)
	e.up.put("/maven2/"+updir+"maven-metadata.xml", upmd)
	e.want("GET", "/maven/all/"+updir+"maven-metadata.xml", nil, http.StatusOK, string(upmd))
	e.get("/maven/all/org/demo/lib/3.0-SNAPSHOT/maven-metadata.xml", http.StatusNotFound)

	// Plugin prefixes merge by artifactId, the first member's winning,
	// each admitted by its own name.
	e.put("/maven/releases/org/demo/plugins/maven-metadata.xml",
		[]byte(`<metadata><plugins><plugin><prefix>hosted</prefix><artifactId>a-maven-plugin</artifactId></plugin></plugins></metadata>`),
		http.StatusCreated)
	e.up.put("/maven2/org/demo/plugins/maven-metadata.xml",
		[]byte(`<metadata><plugins><plugin><prefix>upstream</prefix><artifactId>a-maven-plugin</artifactId></plugin>`+
			`<plugin><prefix>b</prefix><artifactId>b-maven-plugin</artifactId></plugin></plugins></metadata>`))
	gm, err := parseMetadata([]byte(e.get("/maven/open/org/demo/plugins/maven-metadata.xml", http.StatusOK).body))
	if err != nil {
		t.Fatal(err)
	}
	if ps := metadataPlugins(gm); len(ps) != 2 || ps[0].Prefix != "hosted" || ps[1].Prefix != "b" {
		t.Errorf("merged plugins %+v", ps)
	}
	e.up.put("/maven2/com/acme/plugins/maven-metadata.xml",
		[]byte(`<metadata><plugins><plugin><prefix>evil</prefix><artifactId>evil-maven-plugin</artifactId></plugin></plugins></metadata>`))
	e.get("/maven/all/com/acme/plugins/maven-metadata.xml", http.StatusNotFound)
}

// TestVirtualGroupPlugins checks that a member whose filters admit a
// group's artifacts, but not the group's own name, serves the group's
// plugin prefixes, ahead of a later member's entry for the same prefix.
func TestVirtualGroupPlugins(t *testing.T) {
	e := newEnv(t)
	// "scoped" consults mixed for com.acme.* only, which does not match
	// com.acme itself.
	e.put("/maven/mixed/com/acme/maven-metadata.xml",
		[]byte(`<metadata><plugins><plugin><prefix>acme</prefix><artifactId>acme-maven-plugin</artifactId></plugin></plugins></metadata>`),
		http.StatusCreated)
	e.up.put("/maven2/com/acme/maven-metadata.xml",
		[]byte(`<metadata><plugins><plugin><prefix>acme</prefix><artifactId>evil-maven-plugin</artifactId></plugin></plugins></metadata>`))
	gm, err := parseMetadata([]byte(e.get("/maven/scoped/com/acme/maven-metadata.xml", http.StatusOK).body))
	if err != nil {
		t.Fatal(err)
	}
	if ps := metadataPlugins(gm); len(ps) != 2 || ps[0].ArtifactID != "acme-maven-plugin" || ps[1].ArtifactID != "evil-maven-plugin" {
		t.Errorf("plugins %+v; want the hosted member's first", ps)
	}

	// A proxy whose filters exclude the group's artifacts is not asked
	// for its prefixes.
	e.up.put("/maven2/com/acme/tools/maven-metadata.xml",
		[]byte(`<metadata><plugins><plugin><prefix>tools</prefix><artifactId>tools-maven-plugin</artifactId></plugin></plugins></metadata>`))
	e.up.took()
	e.get("/maven/all/com/acme/tools/maven-metadata.xml", http.StatusNotFound)
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("a proxy whose filters exclude the group was asked: %q", got)
	}
}
