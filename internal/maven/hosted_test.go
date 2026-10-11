package maven

import (
	"bytes"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHostedDeployAndResolve(t *testing.T) {
	e := newEnv(t)
	jar, pom := []byte("jar bytes 1.0"), []byte("<project>1.0</project>")
	e.deploy("releases", artifact("com.acme", "lib", "1.0", "lib-1.0.jar"), jar)
	e.deploy("releases", artifact("com.acme", "lib", "1.0", "lib-1.0.pom"), pom)
	e.deploy("releases", artifact("com.acme", "lib", "1.0", "lib-1.0-sources.jar"), []byte("sources"))
	e.deploy("releases", artifact("com.acme", "lib", "1.10", "lib-1.10.jar"), []byte("jar bytes 1.10"))
	e.advance(time.Hour)
	e.deploy("releases", artifact("com.acme", "lib", "1.9", "lib-1.9.jar"), []byte("jar bytes 1.9"))
	// Clients upload their own merged metadata, which flint discards.
	e.put("/maven/releases/com/acme/lib/maven-metadata.xml",
		[]byte(`<metadata><groupId>com.acme</groupId><artifactId>lib</artifactId><versioning><versions><version>9.9</version></versions></versioning></metadata>`),
		http.StatusCreated)
	e.put("/maven/releases/com/acme/lib/maven-metadata.xml.sha1", []byte("0000000000000000000000000000000000000000"), http.StatusCreated)

	r := e.want("GET", "/maven/releases/"+artifact("com.acme", "lib", "1.0", "lib-1.0.jar"), nil, http.StatusOK, string(jar))
	for alg, hd := range map[string]string{algMD5: "X-Checksum-Md5", algSHA1: "X-Checksum-Sha1", algSHA256: "X-Checksum-Sha256", algSHA512: "X-Checksum-Sha512"} {
		if got := r.header.Get(hd); got != hexSum(alg, jar) {
			t.Errorf("%s = %q, want %q", hd, got, hexSum(alg, jar))
		}
		e.want("GET", "/maven/releases/"+artifact("com.acme", "lib", "1.0", "lib-1.0.jar."+alg), nil, http.StatusOK, hexSum(alg, jar))
	}
	if ct := r.header.Get("Content-Type"); ct != "application/java-archive" {
		t.Errorf("jar Content-Type = %q", ct)
	}
	if r := e.get("/maven/releases/"+artifact("com.acme", "lib", "1.0", "lib-1.0.pom"), http.StatusOK); r.header.Get("Content-Type") != ctXML {
		t.Errorf("pom Content-Type = %q", r.header.Get("Content-Type"))
	}
	if r := e.do("HEAD", "/maven/releases/"+artifact("com.acme", "lib", "1.0", "lib-1.0.jar"), nil); r.code != http.StatusOK ||
		r.header.Get("Content-Length") != fmt.Sprint(len(jar)) || r.body != "" {
		t.Errorf("HEAD = %d %q %q", r.code, r.header.Get("Content-Length"), r.body)
	}

	md := e.get("/maven/releases/com/acme/lib/maven-metadata.xml", http.StatusOK)
	m, err := parseMetadata([]byte(md.body))
	if err != nil {
		t.Fatal(err)
	}
	vs, updated := metadataVersions(m)
	if !slices.Equal(vs, []string{"1.0", "1.9", "1.10"}) || m.Versioning.Latest != "1.10" || m.Versioning.Release != "1.10" ||
		!updated.Equal(e.now()) || m.GroupID != "com.acme" || m.ArtifactID != "lib" {
		t.Errorf("metadata:\n%s", md.body)
	}
	if md.header.Get("X-Checksum-Sha1") != hexSum(algSHA1, []byte(md.body)) {
		t.Error("the metadata's checksum header does not match it")
	}
	for _, alg := range sidecarAlgs {
		e.want("GET", "/maven/releases/com/acme/lib/maven-metadata.xml."+alg, nil, http.StatusOK, hexSum(alg, []byte(md.body)))
	}
	for _, p := range []string{"com/acme/other/maven-metadata.xml", artifact("com.acme", "lib", "2.0", "lib-2.0.jar"),
		artifact("com.acme", "lib", "2.0", "lib-2.0.jar.sha1"), "com/acme/lib/", "archetype-catalog.xml"} {
		e.get("/maven/releases/"+p, http.StatusNotFound)
	}
	if got := e.metric(`flint_maven_deploys_total{repository="releases"}`); got != "5" {
		t.Errorf("deploys = %s, want 5", got)
	}
}

func TestHostedImmutable(t *testing.T) {
	e := newEnv(t)
	p := "/maven/releases/" + artifact("com.acme", "lib", "1.0", "lib-1.0.jar")
	e.put(p, []byte("one"), http.StatusCreated)
	// A retried upload of the same bytes succeeds without a change.
	e.put(p, []byte("one"), http.StatusOK)
	if r := e.put(p, []byte("two"), http.StatusConflict); !strings.Contains(r.body, "different content") {
		t.Errorf("409 body %q", r.body)
	}
	e.want("GET", p, nil, http.StatusOK, "one")
	e.put("/maven/releases/"+artifact("com.acme", "lib", "1.0", "lib-1.0.pom"), []byte("<project/>"), http.StatusCreated)

	e.want("DELETE", p, nil, http.StatusNoContent, "")
	e.get(p, http.StatusNotFound)
	e.get(p+".sha1", http.StatusNotFound)
	e.want("DELETE", p, nil, http.StatusNotFound, "")
	// A deleted name is never usable again, not even with its bytes.
	if r := e.put(p, []byte("one"), http.StatusConflict); !strings.Contains(r.body, "deleted") {
		t.Errorf("409 body %q", r.body)
	}
	// The version is listed while a file of it is live.
	md := e.get("/maven/releases/com/acme/lib/maven-metadata.xml", http.StatusOK)
	if !strings.Contains(md.body, "<version>1.0</version>") {
		t.Errorf("metadata:\n%s", md.body)
	}
	e.want("DELETE", "/maven/releases/"+artifact("com.acme", "lib", "1.0", "lib-1.0.pom"), nil, http.StatusNoContent, "")
	e.get("/maven/releases/com/acme/lib/maven-metadata.xml", http.StatusNotFound)
	v := e.meta.View()
	defer v.Release()
	if !owns(v, "releases", "com.acme:lib") {
		t.Error("deleting every file gave up ownership of the artifact")
	}
}

// TestHostedConcurrentDeploys checks that of concurrent uploads of one
// name, those with identical content all succeed and of those with
// different content exactly one does.
func TestHostedConcurrentDeploys(t *testing.T) {
	e := newEnv(t)
	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			body := "same content"
			if i >= n/2 {
				body = fmt.Sprintf("other content %d", i)
			}
			codes[i] = e.do("PUT", "/maven/releases/"+artifact("com.acme", "race", "1.0", "race-1.0.jar"), []byte(body)).code
		})
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		switch c {
		case http.StatusCreated:
			ok++
		case http.StatusOK, http.StatusConflict:
		default:
			t.Errorf("status %d", c)
		}
	}
	if ok != 1 {
		t.Errorf("%d uploads created the file, want 1: %v", ok, codes)
	}
	v := e.meta.View()
	defer v.Release()
	vr, err := hostedVersion(v, "releases", "com.acme", "race", "1.0")
	if err != nil || vr == nil || vr.Files != 1 {
		t.Errorf("version record %+v, %v; want one live file", vr, err)
	}
}

func TestVersionPolicy(t *testing.T) {
	e := newEnv(t)
	rel := artifact("com.acme", "lib", "1.0", "lib-1.0.jar")
	snap := artifact("com.acme", "lib", "1.1-SNAPSHOT", "lib-1.1-20261011.120000-1.jar")
	nonUnique := artifact("com.acme", "lib", "1.1-SNAPSHOT", "lib-1.1-SNAPSHOT.jar")
	for _, tc := range []struct {
		repo, path string
		want       int
	}{
		{"releases", rel, http.StatusCreated},
		{"releases", snap, http.StatusBadRequest},
		{"snapshots", rel, http.StatusBadRequest},
		{"snapshots", snap, http.StatusCreated},
		{"snapshots", nonUnique, http.StatusBadRequest},
		{"mixed", rel, http.StatusCreated},
		{"mixed", snap, http.StatusCreated},
		{"mixed", nonUnique, http.StatusBadRequest},
		{"releases", "com/acme/lib/1.0/other.jar", http.StatusBadRequest},
		{"releases", "archetype-catalog.xml", http.StatusBadRequest},
		{"releases", "com/acme/lib/1.0/", http.StatusBadRequest},
		{"releases", "com/acme/lib/1.0/lib-1.0.jar%3Ax", http.StatusBadRequest},
	} {
		if r := e.do("PUT", "/maven/"+tc.repo+"/"+tc.path, []byte("x")); r.code != tc.want {
			t.Errorf("PUT %s to %s = %d %q, want %d", tc.path, tc.repo, r.code, r.body, tc.want)
		}
	}
}

func TestHostedSnapshots(t *testing.T) {
	e := newEnv(t)
	dir := "com/acme/lib/1.0-SNAPSHOT/"
	e.deploy("snapshots", dir+"lib-1.0-20261011.120000-1.jar", []byte("build 1"))
	e.deploy("snapshots", dir+"lib-1.0-20261011.120000-1.pom", []byte("<project>1</project>"))
	e.advance(time.Hour)
	e.deploy("snapshots", dir+"lib-1.0-20261011.130000-2.jar", []byte("build 2"))
	e.deploy("snapshots", dir+"lib-1.0-20261011.130000-2.pom", []byte("<project>2</project>"))
	e.deploy("snapshots", dir+"lib-1.0-20261011.130000-2-sources.jar", []byte("sources 2"))
	e.put("/maven/snapshots/"+dir+"maven-metadata.xml", []byte("<metadata><version>1.0-SNAPSHOT</version></metadata>"), http.StatusCreated)

	md := e.get("/maven/snapshots/"+dir+"maven-metadata.xml", http.StatusOK)
	m, err := parseMetadata([]byte(md.body))
	if err != nil {
		t.Fatal(err)
	}
	if s := m.Versioning.Snapshot; s == nil || s.Timestamp != "20261011.130000" || s.BuildNumber != 2 || m.Version != "1.0-SNAPSHOT" {
		t.Errorf("snapshot metadata:\n%s", md.body)
	}
	var values []string
	for _, sv := range m.Versioning.SnapshotVersions.SnapshotVersion {
		values = append(values, sv.Classifier+":"+sv.Extension+"="+sv.Value)
	}
	if want := []string{"sources:jar=1.0-20261011.130000-2", ":jar=1.0-20261011.130000-2", ":pom=1.0-20261011.130000-2"}; !sameSet(values, want) {
		t.Errorf("snapshotVersions = %q, want %q", values, want)
	}
	am := e.get("/maven/snapshots/com/acme/lib/maven-metadata.xml", http.StatusOK)
	if !strings.Contains(am.body, "<latest>1.0-SNAPSHOT</latest>") || strings.Contains(am.body, "<release>") {
		t.Errorf("artifact metadata:\n%s", am.body)
	}
	e.want("GET", "/maven/snapshots/"+dir+"lib-1.0-20261011.120000-1.jar", nil, http.StatusOK, "build 1")
	// Deleting the snapshot version's directory deletes every file in it.
	e.want("DELETE", "/maven/snapshots/"+dir, nil, http.StatusNoContent, "")
	e.get("/maven/snapshots/"+dir+"maven-metadata.xml", http.StatusNotFound)
	e.get("/maven/snapshots/com/acme/lib/maven-metadata.xml", http.StatusNotFound)
	e.want("DELETE", "/maven/snapshots/"+dir, nil, http.StatusNotFound, "")
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func TestHostedChecksumUploads(t *testing.T) {
	e := newEnv(t)
	p := "/maven/releases/" + artifact("com.acme", "lib", "1.0", "lib-1.0.jar")
	e.put(p, []byte("jar"), http.StatusCreated)
	for _, tc := range []struct {
		alg, body string
		want      int
	}{
		{algSHA1, hexSum(algSHA1, []byte("jar")), http.StatusCreated},
		{algSHA1, strings.ToUpper(hexSum(algSHA1, []byte("jar"))) + "  lib-1.0.jar\n", http.StatusCreated},
		{algSHA256, hexSum(algSHA256, []byte("jar")), http.StatusCreated},
		{algSHA512, hexSum(algSHA512, []byte("jar")), http.StatusCreated},
		{algMD5, hexSum(algMD5, []byte("jar")), http.StatusCreated},
		{algSHA1, hexSum(algSHA1, []byte("other")), http.StatusBadRequest},
		{algSHA1, "not a checksum", http.StatusBadRequest},
		{algSHA256, hexSum(algSHA1, []byte("jar")), http.StatusBadRequest},
		{algSHA1, strings.Repeat("a", 2000), http.StatusBadRequest},
	} {
		if r := e.do("PUT", p+"."+tc.alg, []byte(tc.body)); r.code != tc.want {
			t.Errorf("PUT .%s %.40q = %d %q, want %d", tc.alg, tc.body, r.code, r.body, tc.want)
		}
	}
	// A sidecar of a file not deployed is accepted and discarded.
	e.put("/maven/releases/"+artifact("com.acme", "lib", "2.0", "lib-2.0.jar.sha1"), []byte(hexSum(algSHA1, nil)), http.StatusCreated)
	e.get("/maven/releases/"+artifact("com.acme", "lib", "2.0", "lib-2.0.jar.sha1"), http.StatusNotFound)
}

func TestHostedPlugins(t *testing.T) {
	e := newEnv(t)
	group := func(plugins ...string) []byte {
		var b bytes.Buffer
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><metadata><plugins>`)
		for _, p := range plugins {
			fmt.Fprintf(&b, `<plugin><name>%s plugin</name><prefix>%s</prefix><artifactId>%s-maven-plugin</artifactId></plugin>`, p, p, p)
		}
		b.WriteString(`</plugins></metadata>`)
		return b.Bytes()
	}
	e.put("/maven/releases/com/acme/plugins/maven-metadata.xml", group("deploy"), http.StatusCreated)
	e.put("/maven/releases/com/acme/plugins/maven-metadata.xml", group("lint"), http.StatusCreated)
	e.deploy("releases", artifact("com.acme.plugins", "lint-maven-plugin", "1.0", "lint-maven-plugin-1.0.jar"), []byte("plugin"))
	md := e.get("/maven/releases/com/acme/plugins/maven-metadata.xml", http.StatusOK)
	m, err := parseMetadata([]byte(md.body))
	if err != nil {
		t.Fatal(err)
	}
	ps := metadataPlugins(m)
	if len(ps) != 2 || ps[0].Prefix != "deploy" || ps[1].ArtifactID != "lint-maven-plugin" || ps[1].Name != "lint plugin" {
		t.Errorf("plugins = %+v\n%s", ps, md.body)
	}
	// com/acme/plugins also names artifact com.acme:plugins, which has no
	// versions, so the document is the group's alone.
	if m.Versioning != nil {
		t.Errorf("group metadata has versioning:\n%s", md.body)
	}
	e.put("/maven/releases/com/acme/plugins/maven-metadata.xml", []byte("garbage"), http.StatusBadRequest)
}

func TestAuthorization(t *testing.T) {
	e := newEnv(t)
	file := artifact("com.acme", "lib", "1.0", "lib-1.0.jar")
	e.put("/maven/releases/"+file, []byte("jar"), http.StatusCreated)
	e.get("/maven/releases/"+file, http.StatusOK)
	e.want("DELETE", "/maven/mixed/"+file, nil, http.StatusNotFound, "")
	e.get("/maven/all/"+file, http.StatusOK)
	e.put("/maven/all/"+artifact("com.acme", "lib", "1.1", "lib-1.1.jar"), []byte("jar 1.1"), http.StatusCreated)
	if got, want := e.auth.reset(), []string{"releases:push", "releases:pull", "mixed:delete", "all>releases:pull", "all>releases:push"}; !slices.Equal(got, want) {
		t.Errorf("authorization checks = %q, want %q", got, want)
	}
	e.get("/maven/releases/"+artifact("com.acme", "lib", "1.1", "lib-1.1.jar"), http.StatusOK)

	// Refusals carry the Basic challenge Maven and Gradle wait for.
	e.auth.deny = true
	r := e.get("/maven/releases/"+file, http.StatusUnauthorized)
	if r.header.Get("WWW-Authenticate") != `Basic realm="flint"` {
		t.Errorf("challenge %q", r.header.Get("WWW-Authenticate"))
	}
	e.auth.deny = false

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"PUT", "/maven/central/" + file, http.StatusMethodNotAllowed},
		{"DELETE", "/maven/central/" + file, http.StatusMethodNotAllowed},
		{"PUT", "/maven/open/" + file, http.StatusMethodNotAllowed},
		{"DELETE", "/maven/open/" + file, http.StatusMethodNotAllowed},
		{"POST", "/maven/releases/" + file, http.StatusMethodNotAllowed},
		{"GET", "/maven/nope/" + file, http.StatusNotFound},
		{"GET", "/maven/pypi/" + file, http.StatusNotFound},
		{"GET", "/maven/releases", http.StatusNotFound},
		{"GET", "/maven/releases/", http.StatusNotFound},
		{"GET", "/maven/central/", http.StatusNotFound},
		{"GET", "/maven/all/", http.StatusNotFound},
		{"PUT", "/maven/releases/", http.StatusBadRequest},
		{"DELETE", "/maven/releases/", http.StatusBadRequest},
		{"PUT", "/maven/releases/a//b", http.StatusBadRequest},
	} {
		if r := e.do(tc.method, tc.path, []byte("x")); r.code != tc.want {
			t.Errorf("%s %s = %d %q, want %d", tc.method, tc.path, r.code, r.body, tc.want)
		}
	}
	// A virtual repository's publishTo member's filters refuse what they
	// do not admit; "all" publishes to releases, whose filters admit all.
	e.put("/maven/all/"+artifact("org.other", "x", "1.0", "x-1.0.jar"), []byte("x"), http.StatusCreated)
}
