package maven

import (
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/upstream"
)

func TestProxyCachesVerifiedFiles(t *testing.T) {
	e := newEnv(t)
	jar := bytes.Repeat([]byte("guava "), 10000)
	path := artifact("com.google.guava", "guava", "33.0.0-jre", "guava-33.0.0-jre.jar")
	e.up.put("/maven2/"+path, jar)
	e.want("GET", "/maven/central/"+path, nil, http.StatusOK, string(jar))
	e.settle()
	if got := e.up.took(); !slices.Equal(got, []string{"GET /maven2/" + path}) {
		t.Errorf("upstream requests %q; want the file alone, verified by its X-Checksum-SHA1", got)
	}
	rec, err := e.h.pc.Lookup(e.h.repos["central"].proxy.pr, path)
	if err != nil || rec == nil {
		t.Fatalf("not cached: %v", err)
	}

	// Cached: served without asking the upstream, with checksum headers
	// and sidecars from flint's own digests, also when it is down.
	e.up.set(func(u *fakeRepo) { u.down = true })
	r := e.want("GET", "/maven/central/"+path, nil, http.StatusOK, string(jar))
	if r.header.Get("X-Checksum-Sha1") != hexSum(algSHA1, jar) || r.header.Get("X-Checksum-Sha256") != hexSum(algSHA256, jar) {
		t.Errorf("checksum headers %v", r.header)
	}
	if r.header.Get("Content-Type") != "application/java-archive" {
		t.Errorf("Content-Type = %q", r.header.Get("Content-Type"))
	}
	for _, alg := range sidecarAlgs {
		e.want("GET", "/maven/central/"+path+"."+alg, nil, http.StatusOK, hexSum(alg, jar))
	}
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("cached content asked the upstream: %q", got)
	}
}

func TestProxyRefusesBadContent(t *testing.T) {
	e := newEnv(t)
	path := artifact("com.acme", "lib", "1.0", "lib-1.0.jar")
	data := bytes.Repeat([]byte("x"), 300000)
	e.up.put("/maven2/"+path, data)
	e.up.set(func(u *fakeRepo) { u.badSum = true })
	if r := e.do("GET", "/maven/central/"+path, nil); r.err == nil && r.code == http.StatusOK && len(r.body) == len(data) {
		t.Fatal("content that does not match its checksum was served whole")
	}
	e.settle()
	if rec, _ := e.h.pc.Lookup(e.h.repos["central"].proxy.pr, path); rec != nil {
		t.Error("content that does not match its checksum was cached")
	}
	e.up.set(func(u *fakeRepo) { u.badSum = false })
	e.want("GET", "/maven/central/"+path, nil, http.StatusOK, string(data))
}

// TestProxySidecars checks verification against an upstream that sends
// no checksum headers: the strongest sidecar it serves is fetched, the
// algorithm it last served first.
func TestProxySidecars(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"1.0", "1.1", "1.2", "1.3"} {
		e.plain.put("/repo/"+artifact("com.acme", "lib", v, "lib-"+v+".pom"), []byte("<project>"+v+"</project>"))
	}
	fetch := func(v string) []string {
		t.Helper()
		p := artifact("com.acme", "lib", v, "lib-"+v+".pom")
		e.want("GET", "/maven/plain/"+p, nil, http.StatusOK, "<project>"+v+"</project>")
		e.settle()
		var got []string
		for _, r := range e.plain.took() {
			got = append(got, strings.TrimPrefix(r, "GET /repo/"+p))
		}
		return got
	}
	if got := fetch("1.0"); !slices.Equal(got, []string{"", ".sha512"}) {
		t.Errorf("requests %q, want the file and its .sha512", got)
	}
	e.plain.set(func(u *fakeRepo) { u.noSidecar[algSHA512], u.noSidecar[algSHA256] = true, true })
	if got := fetch("1.1"); !slices.Equal(got, []string{"", ".sha512", ".sha256", ".sha1"}) {
		t.Errorf("requests %q, want the file, then each sidecar down to .sha1", got)
	}
	if got := fetch("1.2"); !slices.Equal(got, []string{"", ".sha1"}) {
		t.Errorf("requests %q, want the file and the sidecar served last time", got)
	}
	for _, v := range []string{"1.0", "1.1", "1.2"} {
		if rec, _ := e.h.pc.Lookup(e.h.repos["plain"].proxy.pr, artifact("com.acme", "lib", v, "lib-"+v+".pom")); rec == nil {
			t.Errorf("%s was not cached", v)
		}
	}

	// A file the upstream offers no checksum for is passed through, not
	// cached.
	e.plain.set(func(u *fakeRepo) { u.noSidecar[algSHA1], u.noSidecar[algMD5] = true, true })
	fetch("1.3")
	if rec, _ := e.h.pc.Lookup(e.h.repos["plain"].proxy.pr, artifact("com.acme", "lib", "1.3", "lib-1.3.pom")); rec != nil {
		t.Error("a file without a checksum was cached")
	}
	// A sidecar that does not match fails the fetch.
	e.plain.set(func(u *fakeRepo) { clear(u.noSidecar); u.badSum = true })
	e.plain.put("/repo/"+artifact("com.acme", "lib", "1.4", "lib-1.4.pom"), bytes.Repeat([]byte("p"), 200000))
	if r := e.do("GET", "/maven/plain/"+artifact("com.acme", "lib", "1.4", "lib-1.4.pom"), nil); r.err == nil && r.code == http.StatusOK {
		t.Error("a file whose sidecar does not match was served whole")
	}
}

func TestProxyMetadata(t *testing.T) {
	e := newEnv(t)
	md := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<metadata><groupId>com.acme</groupId><artifactId>lib</artifactId><versioning><latest>1.1</latest><release>1.1</release>
<versions><version>1.0</version><version>1.1</version></versions><lastUpdated>20261001120000</lastUpdated></versioning></metadata>`)
	e.up.put("/maven2/com/acme/lib/maven-metadata.xml", md)
	r := e.want("GET", "/maven/central/com/acme/lib/maven-metadata.xml", nil, http.StatusOK, string(md))
	if r.header.Get("X-Checksum-Sha1") != hexSum(algSHA1, md) {
		t.Errorf("checksum header %q", r.header.Get("X-Checksum-Sha1"))
	}
	for _, alg := range sidecarAlgs {
		e.want("GET", "/maven/central/com/acme/lib/maven-metadata.xml."+alg, nil, http.StatusOK, hexSum(alg, md))
	}
	if got := e.up.took(); len(got) != 1 {
		t.Errorf("upstream requests %q; want one within the window", got)
	}

	// After the window it is revalidated; a document flint cannot read
	// never replaces the cached one, and an upstream that is down has the
	// cached copy served.
	e.up.put("/maven2/com/acme/lib/maven-metadata.xml", []byte("<html>oops</html>"))
	e.advance(2 * testWindow)
	e.want("GET", "/maven/central/com/acme/lib/maven-metadata.xml", nil, http.StatusOK, string(md))
	e.up.set(func(u *fakeRepo) { u.down = true })
	e.advance(2 * testWindow)
	e.want("GET", "/maven/central/com/acme/lib/maven-metadata.xml", nil, http.StatusOK, string(md))
	e.up.set(func(u *fakeRepo) { u.down = false })
	updated := bytes.Replace(md, []byte("<version>1.1</version>"), []byte("<version>1.1</version><version>1.2</version>"), 1)
	e.up.put("/maven2/com/acme/lib/maven-metadata.xml", updated)
	e.advance(upstream.DefaultOfflineFor + 2*testWindow)
	e.want("GET", "/maven/central/com/acme/lib/maven-metadata.xml", nil, http.StatusOK, string(updated))

	// Not-found answers are remembered briefly.
	e.up.took()
	for range 3 {
		e.get("/maven/central/com/acme/missing/maven-metadata.xml", http.StatusNotFound)
		e.get("/maven/central/"+artifact("com.acme", "lib", "1.0", "lib-1.0-javadoc.jar"), http.StatusNotFound)
	}
	if got := e.up.took(); len(got) != 2 {
		t.Errorf("upstream requests %q; want one for each missing path", got)
	}
}

func TestProxyPassThrough(t *testing.T) {
	e := newEnv(t)
	nonUnique := artifact("com.acme", "lib", "1.0-SNAPSHOT", "lib-1.0-SNAPSHOT.jar")
	e.up.put("/maven2/"+nonUnique, []byte("v1"))
	e.up.put("/maven2/archetype-catalog.xml", []byte("<catalog/>"))
	e.want("GET", "/maven/central/"+nonUnique, nil, http.StatusOK, "v1")
	e.up.put("/maven2/"+nonUnique, []byte("v2"))
	e.want("GET", "/maven/central/"+nonUnique, nil, http.StatusOK, "v2")
	e.want("GET", "/maven/central/archetype-catalog.xml", nil, http.StatusOK, "<catalog/>")
	e.up.took()
	e.get("/maven/central/com/acme/lib/", http.StatusNotFound)
	e.get("/maven/central/", http.StatusNotFound)
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("a directory listing asked the upstream: %q", got)
	}
	// The sidecar of a file not cached is the upstream's.
	jar := artifact("com.acme", "lib", "1.0", "lib-1.0.jar")
	e.up.put("/maven2/"+jar, []byte("jar"))
	e.want("GET", "/maven/central/"+jar+".sha1", nil, http.StatusOK, hexSum(algSHA1, []byte("jar"))+"  lib-1.0.jar\n")
	e.settle()
	if rec, _ := e.h.pc.Lookup(e.h.repos["central"].proxy.pr, nonUnique); rec != nil {
		t.Error("a non-unique snapshot file was cached")
	}
}

func TestProxySizeLimit(t *testing.T) {
	e := newEnv(t)
	big, small := artifact("com.acme", "big", "1.0", "big-1.0.jar"), artifact("com.acme", "small", "1.0", "small-1.0.jar")
	e.up.put("/maven2/"+big, bytes.Repeat([]byte("b"), 4000))
	e.up.put("/maven2/"+small, []byte("small"))
	e.get("/maven/small/"+big, http.StatusOK)
	e.get("/maven/small/"+small, http.StatusOK)
	e.settle()
	if rec, _ := e.h.pc.Lookup(e.h.repos["small"].proxy.pr, big); rec != nil {
		t.Error("a file larger than the size limit was cached")
	}
	if rec, _ := e.h.pc.Lookup(e.h.repos["small"].proxy.pr, small); rec == nil {
		t.Error("a file within the size limit was not cached")
	}
}
