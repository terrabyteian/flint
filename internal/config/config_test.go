package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMinimalDefaults(t *testing.T) {
	c, err := Parse([]byte(`{"dataDir": "/data"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := &Config{
		Listen:          DefaultListen,
		DataDir:         "/data",
		ShutdownTimeout: Duration{Duration: DefaultShutdownTimeout, set: true},
		Log:             Log{Level: DefaultLogLevel},
		Auth:            Auth{LoginTokenTTL: Duration{Duration: DefaultLoginTokenTTL, set: true}},
		ProxyCache:      ProxyCache{MinFreeSpace: FreeSpace{Percent: 5, text: "5%"}},
		GC:              GC{GracePeriod: Duration{Duration: DefaultGCGracePeriod, set: true}},
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v, want %+v", c, want)
	}
}

// TestExampleConfig keeps docs/flint.example.json valid and its values
// decoded as documented.
func TestExampleConfig(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "docs", "flint.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.TLS == nil || c.TLS.CertFile != "/etc/flint/tls/tls.crt" || c.ShutdownTimeout.Duration != 25*time.Second ||
		c.Backup.Directory != "/var/backups/flint" {
		t.Errorf("unexpected config %+v", c)
	}
	wantProxies := []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("192.168.1.10/32")}
	if got := c.Proxies(); !reflect.DeepEqual(got, wantProxies) {
		t.Errorf("Proxies() = %v, want %v", got, wantProxies)
	}
	if len(c.Repositories) != 13 || !c.Repositories[1].ImmutableTags || !c.Repositories[1].HelmIndex || len(c.Auth.Permissions) != 3 {
		t.Errorf("unexpected repositories or permissions: %+v", c)
	}
	if p := c.Repositories[2].Proxy; p == nil || p.URL != "https://registry-1.docker.io" || p.RevalidateAfter.Duration != 5*time.Minute ||
		p.PasswordFile != "/etc/flint/upstream/dockerhub/password" || c.Repositories[3].Proxy.SizeLimit.Bytes != 200<<30 {
		t.Errorf("unexpected proxy settings: %+v", c.Repositories[2:])
	}
	if p := c.Repositories[5].Proxy; c.Repositories[4].Format != FormatPyPI || p == nil || PyPIIndexURL(p.URL) != "https://pypi.org/simple/" ||
		p.RevalidateAfter.Duration != 10*time.Minute {
		t.Errorf("unexpected PyPI repositories: %+v", c.Repositories[4:6])
	}
	if v := c.Repositories[6].Virtual; v == nil || !v.Protected() || len(v.Members) != 2 || !c.Repositories[6].AnonymousPull {
		t.Errorf("unexpected virtual repository: %+v", c.Repositories[6])
	}
	if g := c.Repositories[8].Generic; c.Repositories[7].Format != FormatGeneric || g == nil || !g.Immutable ||
		len(c.Repositories[8].Proxy.AllowHosts) != 2 {
		t.Errorf("unexpected generic repositories: %+v", c.Repositories[7:9])
	}
	if p := c.Repositories[10].Proxy; c.Repositories[9].Format != FormatCargo || p == nil || CargoIndexURL(p.URL) != "https://index.crates.io/" {
		t.Errorf("unexpected Cargo repositories: %+v", c.Repositories[9:11])
	}
	if v := c.Repositories[11].Virtual; v == nil || v.PublishTo != "cargo-local" || len(v.Members) != 2 || c.Repositories[11].AnonymousPull {
		t.Errorf("unexpected Cargo virtual repository: %+v", c.Repositories[11])
	}
	if r := c.Repositories[12]; r.Format != FormatNPM || r.Type != TypeHosted {
		t.Errorf("unexpected npm repository: %+v", r)
	}
	if b := c.Auth.BootstrapAdmin; b == nil || b.Username != "admin" || b.PasswordFile != "/etc/flint/admin/password" {
		t.Errorf("unexpected auth settings: %+v", c.Auth)
	}
	if c.GC.GracePeriod.Duration != 24*time.Hour || c.GC.Interval.Duration != 24*time.Hour {
		t.Errorf("unexpected gc settings: %+v", c.GC)
	}
}

func TestValidUserName(t *testing.T) {
	for _, s := range []string{"a", "alice", "ci-bot", "first.last", "a_b", "me@example.com", "0", strings.Repeat("a", 64)} {
		if !ValidUserName(s) {
			t.Errorf("ValidUserName(%q) = false", s)
		}
	}
	for _, s := range []string{"", "Alice", "__token__", "_a", ".a", "-a", "a:b", "a b", "a/b", "é", strings.Repeat("a", 65)} {
		if ValidUserName(s) {
			t.Errorf("ValidUserName(%q) = true", s)
		}
	}
}

// TestExampleDocumented keeps the example in docs/configuration.md
// identical to docs/flint.example.json.
func TestExampleDocumented(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "docs", "flint.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(doc), "```json\n")
	if block, _, _ = strings.Cut(block, "```"); !ok || block != string(example) {
		t.Errorf("the example in docs/configuration.md differs from docs/flint.example.json:\n%s", block)
	}
}

// TestRoundTrip checks that a decoded config encodes back to an equivalent
// file, so tooling can rewrite configs.
func TestRoundTrip(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "docs", "flint.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Parse(b)
	if err != nil {
		t.Fatalf("re-parsing %s: %v", b, err)
	}
	if !reflect.DeepEqual(c, c2) {
		t.Errorf("round trip changed the config:\n%+v\n%+v", c, c2)
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name, in string
		want     []string
	}{
		{"empty", ``, []string{"the file is empty"}},
		{"not an object", `[]`, []string{"must be a JSON object"}},
		{"syntax", "{\n  \"dataDir\": \"/d\",,\n}", []string{"invalid JSON at line 2"}},
		{"truncated", `{"dataDir": "/d"`, []string{"unexpected end of file"}},
		{"unknown top-level field", `{"dataDir": "/d", "listen_addr": ":1"}`, []string{`unknown field "listen_addr"`}},
		{"unknown nested field", `{"dataDir": "/d", "tls": {"certFile": "a", "keyFile": "b", "caFile": "c"}}`, []string{`unknown field "caFile"`}},
		{"unknown repository field", `{"dataDir": "/d", "repositories": [{"name": "a", "format": "oci", "type": "hosted", "imutableTags": true}]}`, []string{`unknown field "imutableTags"`}},
		{"wrong type", `{"dataDir": 5}`, []string{"dataDir: want a string, got number", "line 1"}},
		{"wrong nested type", `{"dataDir": "/d", "repositories": [{"name": "a", "immutableTags": "yes"}]}`, []string{"repositories[0].immutableTags: want true or false, got string"}},
		{"trailing data", `{"dataDir": "/d"} {}`, []string{"unexpected data after the top-level object"}},
		{"duration type", `{"dataDir": "/d", "shutdownTimeout": 30}`, []string{`shutdownTimeout: 30 is not a duration string`}},
		{"duration syntax", `{"dataDir": "/d", "shutdownTimeout": "30"}`, []string{`shutdownTimeout: "30" is not a duration`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.in))
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string // each must appear in the error; nil means valid
	}{
		{"missing dataDir", `{}`, []string{"dataDir: is required"}},
		{"relative dataDir", `{"dataDir": "data"}`, []string{`dataDir: "data" must be an absolute path`}},
		{"listen without port", `{"dataDir": "/d", "listen": "localhost"}`, []string{`listen: "localhost" is not a host:port`}},
		{"listen bad port", `{"dataDir": "/d", "listen": ":http"}`, []string{`listen: port "http" is not a number`}},
		{"listen port too big", `{"dataDir": "/d", "listen": ":70000"}`, []string{`listen: port "70000"`}},
		{"listen bad host", `{"dataDir": "/d", "listen": "a b:80"}`, []string{`listen: host "a b"`}},
		{"listen ipv6", `{"dataDir": "/d", "listen": "[::1]:5000"}`, nil},
		{"listen hostname", `{"dataDir": "/d", "listen": "localhost:0"}`, nil},
		{"tls missing key", `{"dataDir": "/d", "tls": {"certFile": "/c"}}`, []string{"tls.keyFile: is required"}},
		{"tls empty", `{"dataDir": "/d", "tls": {}}`, []string{"tls.certFile: is required", "tls.keyFile: is required"}},
		{"bad proxy", `{"dataDir": "/d", "trustedProxies": ["10.0.0.0/8", "10.0.0.300", "fe80::/129"]}`,
			[]string{`trustedProxies[1]: "10.0.0.300"`, `trustedProxies[2]: "fe80::/129"`}},
		{"zero shutdown", `{"dataDir": "/d", "shutdownTimeout": "0s"}`, []string{"shutdownTimeout: must be positive"}},
		{"negative shutdown", `{"dataDir": "/d", "shutdownTimeout": "-1s"}`, []string{"shutdownTimeout: must be positive"}},
		{"login token ttl", `{"dataDir": "/d", "auth": {"loginTokenTTL": "720h"}}`, nil},
		{"zero login token ttl", `{"dataDir": "/d", "auth": {"loginTokenTTL": "0s"}}`, []string{"auth.loginTokenTTL: must be positive"}},
		{"negative login token ttl", `{"dataDir": "/d", "auth": {"loginTokenTTL": "-1h"}}`, []string{"auth.loginTokenTTL: must be positive"}},
		{"login token ttl syntax", `{"dataDir": "/d", "auth": {"loginTokenTTL": "90d"}}`, []string{`auth.loginTokenTTL: "90d" is not a duration`}},
		{"bad level", `{"dataDir": "/d", "log": {"level": "verbose"}}`, []string{`log.level: "verbose" is not one of`}},
		{"repo bad name", `{"dataDir": "/d", "repositories": [{"name": "Docker", "format": "oci", "type": "hosted"}]}`,
			[]string{`repositories[0].name: "Docker" is not a valid repository name`}},
		{"repo slash", `{"dataDir": "/d", "repositories": [{"name": "a/b", "format": "oci", "type": "hosted"}]}`,
			[]string{`repositories[0].name: "a/b"`}},
		{"repo double separator", `{"dataDir": "/d", "repositories": [{"name": "a--b", "format": "oci", "type": "hosted"}]}`,
			[]string{`repositories[0].name: "a--b"`}},
		{"repo trailing separator", `{"dataDir": "/d", "repositories": [{"name": "a-", "format": "oci", "type": "hosted"}]}`,
			[]string{`repositories[0].name: "a-"`}},
		{"repo too long", `{"dataDir": "/d", "repositories": [{"name": "` + strings.Repeat("a", 65) + `", "format": "oci", "type": "hosted"}]}`,
			[]string{`repositories[0].name`}},
		{"repo duplicate", `{"dataDir": "/d", "repositories": [{"name": "a", "format": "oci", "type": "hosted"}, {"name": "a", "format": "oci", "type": "hosted"}]}`,
			[]string{`repositories[1].name: "a" is already declared by repositories[0]`}},
		{"repo missing format and type", `{"dataDir": "/d", "repositories": [{"name": "a"}]}`,
			[]string{"repositories[0].format: is required", "repositories[0].type: is required"}},
		{"repo unsupported", `{"dataDir": "/d", "repositories": [{"name": "a", "format": "maven", "type": "group"}]}`,
			[]string{`repositories[0].format: "maven" is not supported`, `repositories[0].type: "group" is not supported`}},
		{"npm proxy", `{"dataDir": "/d", "repositories": [{"name": "a", "format": "npm", "type": "proxy", "proxy": {"url": "https://registry.npmjs.org"}}]}`,
			[]string{`repositories[0].type: "proxy" is not supported for format npm; supported types: hosted`}},
		{"oci virtual", `{"dataDir": "/d", "repositories": [{"name": "h", "format": "oci", "type": "hosted"},
			{"name": "a", "format": "oci", "type": "virtual", "virtual": {"members": ["h"]}}]}`,
			[]string{`repositories[1].type: "virtual" is not supported for format oci`}},
		{"pypi good", `{"dataDir": "/d", "repositories": [
			{"name": "pypi-local", "format": "pypi", "type": "hosted"},
			{"name": "pypi", "format": "pypi", "type": "proxy", "anonymousPull": true,
			 "proxy": {"url": "https://pypi.org/simple/", "revalidateAfter": "10m", "sizeLimit": "100GiB"}},
			{"name": "torch", "format": "pypi", "type": "proxy", "proxy": {"url": "https://download.pytorch.org/whl/cpu"}},
			{"name": "pypi-all", "format": "pypi", "type": "virtual", "anonymousPull": true,
			 "virtual": {"members": ["pypi-local", "pypi", "torch"], "dependencyConfusionProtection": false}}]}`, nil},
		{"npm good", `{"dataDir": "/d", "repositories": [
			{"name": "npm-local", "format": "npm", "type": "hosted", "anonymousPull": true}]}`, nil},
		{"npm virtual", `{"dataDir": "/d", "repositories": [{"name": "h", "format": "npm", "type": "hosted"},
			{"name": "a", "format": "npm", "type": "virtual", "virtual": {"members": ["h"]}}]}`,
			[]string{`repositories[1].type: "virtual" is not supported for format npm`}},
		{"pypi virtual problems", `{"dataDir": "/d", "repositories": [
			{"name": "h", "format": "pypi", "type": "hosted", "immutableTags": true, "helmIndex": true, "virtual": {"members": []}},
			{"name": "o", "format": "oci", "type": "hosted"},
			{"name": "v", "format": "pypi", "type": "virtual", "virtual": {"members": ["h", "h", "o", "v", "x", "w"]}},
			{"name": "w", "format": "pypi", "type": "virtual", "virtual": {"members": []}},
			{"name": "n", "format": "pypi", "type": "virtual"}]}`,
			[]string{"repositories[0].immutableTags: is only allowed for a hosted OCI repository",
				"repositories[0].helmIndex: is only allowed for a hosted OCI repository",
				`repositories[0].virtual: is only allowed for type "virtual"`,
				`repositories[2].virtual.members[1]: "h" is named twice`,
				`repositories[2].virtual.members[2]: "o" is a oci repository, not pypi`,
				"repositories[2].virtual.members[3]: a virtual repository cannot be its own member",
				`repositories[2].virtual.members[4]: "x" is not a declared repository`,
				`repositories[2].virtual.members[5]: "w" is a virtual repository; members must be hosted or proxy repositories`,
				"repositories[3].virtual.members: must name at least one",
				`repositories[4].virtual: is required for type "virtual"`}},
		{"virtual filters and publishTo", `{"dataDir": "/d", "repositories": [
			{"name": "h", "format": "pypi", "type": "hosted"},
			{"name": "p", "format": "pypi", "type": "proxy", "proxy": {"url": "https://pypi.org/simple/"}},
			{"name": "v", "format": "pypi", "type": "virtual", "virtual": {"publishTo": "h", "members": [
				{"name": "h", "include": ["acme-*", "tool"]}, {"name": "p", "exclude": ["acme-*", "@scope/*", "com.acme:*"]}]}}]}`, nil},
		{"generic good", `{"dataDir": "/d", "repositories": [
			{"name": "files", "format": "generic", "type": "hosted"},
			{"name": "scratch", "format": "generic", "type": "hosted", "generic": {"allowOverwrite": true}},
			{"name": "releases", "format": "generic", "type": "proxy", "generic": {"immutable": true},
			 "proxy": {"url": "https://github.com/acme/tool/releases/download/", "sizeLimit": "10GiB",
			  "allowHosts": ["release-assets.githubusercontent.com"]}},
			{"name": "mirror", "format": "generic", "type": "proxy", "proxy": {"url": "https://downloads.example.com"}},
			{"name": "generic-all", "format": "generic", "type": "virtual", "generic": {},
			 "virtual": {"publishTo": "files", "members": ["files", {"name": "releases", "exclude": ["internal/*"]}, "mirror"]}}]}`, nil},
		{"generic problems", `{"dataDir": "/d", "repositories": [
			{"name": "h", "format": "generic", "type": "hosted", "generic": {"immutable": true}},
			{"name": "p", "format": "generic", "type": "proxy", "generic": {"allowOverwrite": true},
			 "proxy": {"url": "https://example.com/files/?x=1", "sizeLimit": "1GiB"}},
			{"name": "o", "format": "oci", "type": "hosted", "generic": {}},
			{"name": "v", "format": "generic", "type": "virtual", "generic": {"immutable": true}, "virtual": {"members": ["o"]}}]}`,
			[]string{"repositories[0].generic.immutable: is only allowed for a proxy repository",
				"repositories[1].generic.allowOverwrite: is only allowed for a hosted repository",
				`repositories[1].proxy.url: "https://example.com/files/?x=1" must not have a query or fragment`,
				"repositories[1].proxy.sizeLimit: needs generic.immutable",
				"repositories[2].generic: is only allowed for a repository of format generic",
				"repositories[3].generic.immutable: is only allowed for a proxy repository",
				`repositories[3].virtual.members[0]: "o" is a oci repository, not generic`}},
		{"generic unknown setting", `{"dataDir": "/d", "repositories": [
			{"name": "h", "format": "generic", "type": "hosted", "generic": {"allowOverwite": true}}]}`,
			[]string{`unknown field "allowOverwite"`}},
		{"virtual member problems", `{"dataDir": "/d", "repositories": [
			{"name": "h", "format": "pypi", "type": "hosted"},
			{"name": "p", "format": "pypi", "type": "proxy", "proxy": {"url": "https://pypi.org/simple/"}},
			{"name": "v", "format": "pypi", "type": "virtual", "virtual": {"publishTo": "p", "members": [
				{"name": "h", "include": ["", "a b", "ok"], "exclude": ["é"]}, {"name": "p", "inclde": ["x"]},
				{"include": ["x"]}, 7, {"name": "h", "exclude": "x"}, "p"]}},
			{"name": "w", "format": "pypi", "type": "virtual", "virtual": {"publishTo": "x", "members": ["h"]}}]}`,
			[]string{`repositories[2].virtual.members[0].include[0]: "" is not a package name or pattern`,
				`repositories[2].virtual.members[0].include[1]: "a b" is not a package name or pattern`,
				`repositories[2].virtual.members[0].exclude[0]: "é" is not a package name or pattern`,
				`repositories[2].virtual.members[1]: unknown field "inclde"`,
				"repositories[2].virtual.members[2].name: is required",
				"repositories[2].virtual.members[3]: want a repository name or an object with a name and filters, got 7",
				"repositories[2].virtual.members[4]: exclude: want an array, got string",
				`repositories[2].virtual.publishTo: "p" is a proxy repository; publishTo must name a hosted member`,
				`repositories[3].virtual.publishTo: "x" is not a member of the virtual repository`}},
		{"public URL", `{"dataDir": "/d", "publicURL": "https://flint.example.com/registry/"}`, nil},
		{"public URL problems", `{"dataDir": "/d", "publicURL": "flint.example.com"}`,
			[]string{`publicURL: "flint.example.com" must be an http or https URL`}},
		{"public URL query", `{"dataDir": "/d", "publicURL": "https://flint.example.com/?a=b"}`,
			[]string{`publicURL: "https://flint.example.com/?a=b" must not have a query or fragment`}},
		{"public URL credentials", `{"dataDir": "/d", "publicURL": "https://u:p@flint.example.com"}`,
			[]string{`publicURL: "https://u:p@flint.example.com" must not contain credentials`}},
		{"pypi proxy url", `{"dataDir": "/d", "repositories": [
			{"name": "a", "format": "pypi", "type": "proxy", "proxy": {"url": "https://pypi.org/simple?x=1"}},
			{"name": "b", "format": "pypi", "type": "proxy", "proxy": {"url": "pypi.org"}}]}`,
			[]string{`repositories[0].proxy.url: "https://pypi.org/simple?x=1" must not have a query`,
				`repositories[1].proxy.url: "pypi.org" must be an http or https URL`}},
		{"cargo good", `{"dataDir": "/d", "repositories": [
			{"name": "cargo-local", "format": "cargo", "type": "hosted"},
			{"name": "crates-io", "format": "cargo", "type": "proxy", "anonymousPull": true,
			 "proxy": {"url": "sparse+https://index.crates.io/", "sizeLimit": "100GiB"}},
			{"name": "inner", "format": "cargo", "type": "proxy", "proxy": {"url": "https://flint.example/cargo/crates/"}},
			{"name": "cargo-all", "format": "cargo", "type": "virtual",
			 "virtual": {"members": ["cargo-local", {"name": "crates-io", "exclude": ["acme-*"]}], "publishTo": "cargo-local"}}]}`, nil},
		{"cargo problems", `{"dataDir": "/d", "repositories": [
			{"name": "a", "format": "cargo", "type": "proxy", "proxy": {"url": "sparse+index.crates.io"}},
			{"name": "b", "format": "cargo", "type": "proxy", "proxy": {"url": "git+https://github.com/rust-lang/crates.io-index"}},
			{"name": "c", "format": "cargo", "type": "hosted", "immutableTags": true},
			{"name": "d", "format": "cargo", "type": "virtual", "virtual": {"members": ["a", "p"]}},
			{"name": "p", "format": "pypi", "type": "hosted"}]}`,
			[]string{`repositories[0].proxy.url: "sparse+index.crates.io" must be an http or https URL`,
				`repositories[1].proxy.url: "git+https://github.com/rust-lang/crates.io-index" must be an http or https URL`,
				`repositories[2].immutableTags: is only allowed for a hosted OCI repository`,
				`repositories[3].virtual.members[1]: "p" is a pypi repository, not cargo`}},
		{"proxy good", `{"dataDir": "/d", "proxyCache": {"minFreeSpace": "20GiB"}, "repositories": [{"name": "dockerhub", "format": "oci", "type": "proxy",
			"anonymousPull": true, "proxy": {"url": "https://registry-1.docker.io", "username": "me", "passwordFile": "/run/pw",
			"revalidateAfter": "1m", "sizeLimit": "500GiB"}}]}`, nil},
		{"proxy minimal", `{"dataDir": "/d", "repositories": [{"name": "ghcr", "format": "oci", "type": "proxy", "proxy": {"url": "http://localhost:5001/"}}]}`, nil},
		{"proxy missing", `{"dataDir": "/d", "repositories": [{"name": "p", "format": "oci", "type": "proxy", "immutableTags": true, "helmIndex": true}]}`,
			[]string{`repositories[0].proxy: is required for type "proxy"`, "repositories[0].immutableTags: is not allowed",
				"repositories[0].helmIndex: is not allowed for a proxy repository"}},
		{"helm index", `{"dataDir": "/d", "repositories": [{"name": "charts", "format": "oci", "type": "hosted", "helmIndex": true}]}`, nil},
		{"proxy on hosted", `{"dataDir": "/d", "repositories": [{"name": "h", "format": "oci", "type": "hosted", "proxy": {"url": "https://ghcr.io"}}]}`,
			[]string{`repositories[0].proxy: is only allowed for type "proxy"`}},
		{"proxy bad settings", `{"dataDir": "/d", "repositories": [{"name": "p", "format": "oci", "type": "proxy", "proxy": {
			"url": "ftp://x", "username": "a:b", "passwordFile": "pw", "revalidateAfter": "-1s", "sizeLimit": "lots"}}]}`,
			[]string{`repositories[0].proxy.url: "ftp://x" must be an http or https URL`, "repositories[0].proxy.username: must not contain",
				`repositories[0].proxy.passwordFile: "pw" must be an absolute path`, "repositories[0].proxy.revalidateAfter: must be positive",
				`repositories[0].proxy.sizeLimit: "lots" is not a size`}},
		{"proxy url checks", `{"dataDir": "/d", "repositories": [
			{"name": "a", "format": "oci", "type": "proxy", "proxy": {"url": ""}},
			{"name": "b", "format": "oci", "type": "proxy", "proxy": {"url": "https://u:p@ghcr.io"}},
			{"name": "c", "format": "oci", "type": "proxy", "proxy": {"url": "https://ghcr.io/v2/x"}},
			{"name": "d", "format": "oci", "type": "proxy", "proxy": {"url": "https://ghcr.io?x=1"}},
			{"name": "e", "format": "oci", "type": "proxy", "proxy": {"url": "https://"}}]}`,
			[]string{"repositories[0].proxy.url: is required", "repositories[1].proxy.url: \"https://u:p@ghcr.io\" must not contain credentials",
				"repositories[2].proxy.url: \"https://ghcr.io/v2/x\" must be the registry's base URL", "repositories[3].proxy.url: \"https://ghcr.io?x=1\" must not have a query",
				"repositories[4].proxy.url: \"https://\" has no host"}},
		{"proxy credentials incomplete", `{"dataDir": "/d", "repositories": [
			{"name": "a", "format": "oci", "type": "proxy", "proxy": {"url": "https://ghcr.io", "username": "me"}},
			{"name": "b", "format": "oci", "type": "proxy", "proxy": {"url": "https://ghcr.io", "passwordFile": "/pw"}}]}`,
			[]string{"repositories[0].proxy.passwordFile: is required with username", "repositories[1].proxy.username: is required with passwordFile"}},
		{"proxy zero size limit", `{"dataDir": "/d", "repositories": [{"name": "p", "format": "oci", "type": "proxy", "proxy": {"url": "https://ghcr.io", "sizeLimit": 0}}]}`,
			[]string{"repositories[0].proxy.sizeLimit: must be positive"}},
		{"proxy fetch limits", `{"dataDir": "/d", "repositories": [{"name": "p", "format": "pypi", "type": "proxy", "proxy": {
			"url": "https://pypi.example/simple/", "maxConcurrent": 16,
			"allowHosts": ["files.example", "cdn.example:8443", "*.blob.example", "10.0.0.7", "[fd00::1]:443", "fd00::2"]}}]}`, nil},
		{"proxy bad fetch limits", `{"dataDir": "/d", "repositories": [{"name": "p", "format": "oci", "type": "proxy", "proxy": {
			"url": "https://ghcr.io", "maxConcurrent": -1,
			"allowHosts": ["", "https://cdn.example", "cdn.example/path", "a.*.example", "*", "cdn.example:0", "cdn.example:x"]}}]}`,
			[]string{"repositories[0].proxy.maxConcurrent: must be positive",
				`repositories[0].proxy.allowHosts[0]: "" is not a host name`,
				`repositories[0].proxy.allowHosts[1]: "https://cdn.example" is not a host name`,
				`repositories[0].proxy.allowHosts[2]: "cdn.example/path" is not a host name`,
				`repositories[0].proxy.allowHosts[3]: "a.*.example" is not a host name or address; a wildcard is allowed only as a leading "*."`,
				`repositories[0].proxy.allowHosts[4]: "*" is not a host name or address`,
				`repositories[0].proxy.allowHosts[5]: "cdn.example:0" has an invalid port`,
				`repositories[0].proxy.allowHosts[6]: "cdn.example:x" has an invalid port`}},
		{"bad min free space", `{"dataDir": "/d", "proxyCache": {"minFreeSpace": "100%"}}`,
			[]string{`proxyCache.minFreeSpace: "100%" is not a percentage`}},
		{"bad min free size", `{"dataDir": "/d", "proxyCache": {"minFreeSpace": "some"}}`,
			[]string{`proxyCache.minFreeSpace: "some" is not a size: use a percentage such as "5%"`}},
		{"backup good", `{"dataDir": "/data", "backup": {"directory": "/data-backup"}}`, nil},
		{"backup relative", `{"dataDir": "/data", "backup": {"directory": "backup"}}`,
			[]string{`backup.directory: "backup" must be an absolute path`}},
		{"backup inside data", `{"dataDir": "/data", "backup": {"directory": "/data/backup"}}`,
			[]string{`backup.directory: "/data/backup" must be outside the data directory`}},
		{"backup is data", `{"dataDir": "/data", "backup": {"directory": "/data/"}}`,
			[]string{`backup.directory: "/data/" must be outside the data directory`}},
		{"backup contains data", `{"dataDir": "/srv/data", "backup": {"directory": "/srv"}}`,
			[]string{`backup.directory: "/srv" must be outside the data directory`}},
		{"gc good", `{"dataDir": "/d", "gc": {"gracePeriod": "48h", "interval": "24h"}}`, nil},
		{"gc grace period at the minimum", `{"dataDir": "/d", "gc": {"gracePeriod": "1h"}}`, nil},
		{"gc grace period too short", `{"dataDir": "/d", "gc": {"gracePeriod": "59m"}}`,
			[]string{"gc.gracePeriod: 59m0s is shorter than the minimum, 1h0m0s"}},
		{"gc zero grace period", `{"dataDir": "/d", "gc": {"gracePeriod": "0s"}}`,
			[]string{"gc.gracePeriod: 0s is shorter than the minimum"}},
		{"gc bad durations", `{"dataDir": "/d", "gc": {"gracePeriod": "a day", "interval": 5}}`,
			[]string{`gc.gracePeriod: "a day" is not a duration`, "gc.interval: 5 is not a duration string"}},
		{"gc negative interval", `{"dataDir": "/d", "gc": {"interval": "-1h"}}`, []string{"gc.interval: must be positive"}},
		{"audit retention good", `{"dataDir": "/d", "audit": {"retention": {"maxAge": "8760h", "maxSize": "10GiB"}}}`, nil},
		{"audit retention bad", `{"dataDir": "/d", "audit": {"retention": {"maxAge": "1y", "maxSize": "huge"}}}`,
			[]string{`audit.retention.maxAge: "1y" is not a duration`, `audit.retention.maxSize: "huge" is not a size`}},
		{"audit retention out of range", `{"dataDir": "/d", "audit": {"retention": {"maxAge": "-1h", "maxSize": 0}}}`,
			[]string{"audit.retention.maxAge: must not be negative", "audit.retention.maxSize: must be positive"}},
		{"audit unknown field", `{"dataDir": "/d", "audit": {"maxAge": "1h"}}`, []string{`unknown field "maxAge"`}},
		{"repo good", `{"dataDir": "/d", "repositories": [{"name": "my.repo_1-x", "format": "oci", "type": "hosted"}]}`, nil},
		{"permission empty", `{"dataDir": "/d", "auth": {"permissions": [{}]}}`,
			[]string{"auth.permissions[0].repositories: must name at least one", `auth.permissions[0].role: "" is not one of`,
				"auth.permissions[0]: must name at least one user or group"}},
		{"permission bad pattern", `{"dataDir": "/d", "auth": {"permissions": [{"repositories": ["Team/*"], "role": "read", "users": ["a"]}]}}`,
			[]string{`auth.permissions[0].repositories[0]: "Team/*"`}},
		{"permission bad subjects", `{"dataDir": "/d", "auth": {"permissions": [{"repositories": ["*"], "role": "read", "users": [" ", "Alice"], "groups": ["", "__token__"]}]}}`,
			[]string{`auth.permissions[0].users[0]: " " is not a valid name`, `auth.permissions[0].users[1]: "Alice"`,
				`auth.permissions[0].groups[0]: ""`, `auth.permissions[0].groups[1]: "__token__"`}},
		{"permission good", `{"dataDir": "/d", "auth": {"permissions": [{"repositories": ["team-*"], "role": "delete", "groups": ["g"]}]}}`, nil},
		{"bootstrap admin default name", `{"dataDir": "/d", "auth": {"bootstrapAdmin": {"passwordFile": "/run/secrets/pw"}}}`, nil},
		{"bootstrap admin incomplete", `{"dataDir": "/d", "auth": {"bootstrapAdmin": {"username": "Root"}}}`,
			[]string{`auth.bootstrapAdmin.username: "Root"`, "auth.bootstrapAdmin.passwordFile: is required"}},
		{"all problems reported", `{"listen": "x", "log": {"level": "loud"}}`,
			[]string{"listen:", "dataDir: is required", "log.level:"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.in))
			if tt.want == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

func TestProxyDefaults(t *testing.T) {
	c, err := Parse([]byte(`{"dataDir": "/d", "proxyCache": {"minFreeSpace": 1073741824}, "repositories": [
		{"name": "p", "format": "oci", "type": "proxy", "proxy": {"url": "https://ghcr.io", "sizeLimit": "1.5GiB"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Repositories[0].Proxy
	if p.RevalidateAfter.Duration != DefaultRevalidateAfter {
		t.Errorf("revalidateAfter = %v, want the default %v", p.RevalidateAfter, DefaultRevalidateAfter)
	}
	if p.SizeLimit.Bytes != 3<<29 {
		t.Errorf("sizeLimit = %d, want 1.5GiB", p.SizeLimit.Bytes)
	}
	if got := c.ProxyCache.MinFreeSpace.Of(1 << 40); got != 1<<30 {
		t.Errorf("minFreeSpace of 1TiB = %d, want 1GiB", got)
	}
	d, _ := Parse([]byte(`{"dataDir": "/d"}`))
	if got := d.ProxyCache.MinFreeSpace.Of(1000); got != 50 {
		t.Errorf("default minFreeSpace of 1000 bytes = %d, want 50", got)
	}
}

func TestAuditDefaults(t *testing.T) {
	c, err := Parse([]byte(`{"dataDir": "/d"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r := c.Audit.Retention; r.MaxAge.Duration != 0 || r.MaxSize.Bytes != 0 {
		t.Errorf("default audit retention = %+v, want none", r)
	}
	c, err = Parse([]byte(`{"dataDir": "/d", "audit": {"retention": {"maxAge": "720h", "maxSize": "1GiB"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if r := c.Audit.Retention; r.MaxAge.Duration != 720*time.Hour || r.MaxSize.Bytes != 1<<30 {
		t.Errorf("audit retention = %+v", r)
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		in   string
		want int64 // -1 means an error
	}{
		{"0", 0},
		{"1024", 1024},
		{"1KB", 1000},
		{"1kB", 1000},
		{"1KiB", 1024},
		{"1Ki", 1024},
		{"20GiB", 20 << 30},
		{"1.5 GiB", 3 << 29},
		{"2TB", 2e12},
		{"1Pi", 1 << 50},
		{"", -1},
		{"GiB", -1},
		{"1 gib", -1},
		{"-1GiB", -1},
		{"1..2GiB", -1},
		{"99999999PiB", -1},
	}
	for _, tt := range tests {
		got, err := ParseSize(tt.in)
		if tt.want < 0 {
			if err == nil {
				t.Errorf("ParseSize(%q) = %d, want an error", tt.in, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", tt.in, got, err, tt.want)
		}
	}
}

func TestParseProxy(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"10.1.2.3", "10.1.2.3/32"},
		{"10.1.2.3/8", "10.0.0.0/8"},
		{"::1", "::1/128"},
		{"fd00::1/8", "fd00::/8"},
		{"::ffff:10.1.2.3", "10.1.2.3/32"},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8"},
		{"fe80::1%eth0", "fe80::1/128"},
		{"nonsense", ""},
		{"10.0.0.0/33", ""},
		{"fe80::%eth0/64", ""},
	}
	for _, tt := range tests {
		p, err := ParseProxy(tt.in)
		if tt.want == "" {
			if err == nil {
				t.Errorf("ParseProxy(%q) = %v, want an error", tt.in, p)
			}
			continue
		}
		if err != nil || p.String() != tt.want {
			t.Errorf("ParseProxy(%q) = %v, %v; want %s", tt.in, p, err, tt.want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "missing.json") {
		t.Errorf("missing file: err = %v", err)
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"dataDir": "x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "dataDir") {
		t.Errorf("invalid file: err = %v, want it to name the file and field", err)
	}
}

func TestPyPIIndexURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://pypi.org":                     "https://pypi.org/simple/",
		"https://pypi.org/":                    "https://pypi.org/simple/",
		"https://pypi.org/simple":              "https://pypi.org/simple/",
		"https://pypi.org/simple/":             "https://pypi.org/simple/",
		"https://download.pytorch.org/whl/cpu": "https://download.pytorch.org/whl/cpu/",
		"http://flint:5000/pypi/pypi/simple/":  "http://flint:5000/pypi/pypi/simple/",
	} {
		if got := PyPIIndexURL(in); got != want {
			t.Errorf("PyPIIndexURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCargoIndexURL(t *testing.T) {
	for in, want := range map[string]string{
		"sparse+https://index.crates.io/":     "https://index.crates.io/",
		"https://index.crates.io":             "https://index.crates.io/",
		"sparse+http://flint:5000/cargo/c":    "http://flint:5000/cargo/c/",
		"https://flint.example/cargo/crates/": "https://flint.example/cargo/crates/",
	} {
		if got := CargoIndexURL(in); got != want {
			t.Errorf("CargoIndexURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPublicBase(t *testing.T) {
	for in, want := range map[string]string{
		"":                              "",
		"https://flint.example.com":     "https://flint.example.com",
		"https://flint.example.com/":    "https://flint.example.com",
		"https://example.com/registry/": "https://example.com/registry",
	} {
		if got := (&Config{PublicURL: in}).PublicBase(); got != want {
			t.Errorf("PublicBase with %q = %q, want %q", in, got, want)
		}
	}
}

// TestVirtualMemberJSON checks that a member decodes from a name or an
// object, and encodes back to a name when it has no filters.
func TestVirtualMemberJSON(t *testing.T) {
	var v Virtual
	in := `{"members": ["a", {"name": "b", "include": ["x-*"], "exclude": ["x-y"]}, {"name": "c"}]}`
	if err := json.Unmarshal([]byte(in), &v); err != nil {
		t.Fatal(err)
	}
	want := []VirtualMember{{Name: "a"}, {Name: "b", Include: []string{"x-*"}, Exclude: []string{"x-y"}}, {Name: "c"}}
	if !reflect.DeepEqual(v.Members, want) {
		t.Errorf("members %+v, want %+v", v.Members, want)
	}
	out, err := json.Marshal(v.Members)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != `["a",{"name":"b","include":["x-*"],"exclude":["x-y"]},"c"]` {
		t.Errorf("encoded members %s", got)
	}
}

// TestFormatSettings checks the rule for per-format settings objects: a
// repository may carry only its own format's, which that format checks.
func TestFormatSettings(t *testing.T) {
	saved := formats
	defer func() { formats = saved }()
	// The test format's settings object stands in on the proxy field.
	formats = append(slices.Clone(saved), formatSpec{name: "test", types: []string{TypeHosted},
		settings: func(r *Repository) any {
			if r.Proxy == nil {
				return nil
			}
			return r.Proxy
		},
		check: func(v *validator, path string, r *Repository) {
			if r.Proxy == nil {
				v.addf(path, "is required")
			}
		}})
	if got := Formats(); !slices.Equal(got, []string{"oci", "pypi", "generic", "cargo", "npm", "test"}) {
		t.Errorf("Formats() = %q", got)
	}
	_, err := Parse([]byte(`{"dataDir": "/d", "repositories": [
		{"name": "a", "format": "test", "type": "hosted"},
		{"name": "b", "format": "test", "type": "proxy"},
		{"name": "c", "format": "oci", "type": "proxy", "proxy": {"url": "https://ghcr.io"}}]}`))
	for _, w := range []string{"repositories[0].test: is required",
		`repositories[1].type: "proxy" is not supported for format test; supported types: hosted`,
		"repositories[2].test: is only allowed for a repository of format test"} {
		if err == nil || !strings.Contains(err.Error(), w) {
			t.Errorf("error %v does not contain %q", err, w)
		}
	}
}

func TestVirtualProtected(t *testing.T) {
	off := false
	on := true
	for _, tt := range []struct {
		v    Virtual
		want bool
	}{{Virtual{}, true}, {Virtual{DependencyConfusionProtection: &on}, true}, {Virtual{DependencyConfusionProtection: &off}, false}} {
		if got := tt.v.Protected(); got != tt.want {
			t.Errorf("Protected() with %v = %v", tt.v.DependencyConfusionProtection, got)
		}
	}
}
