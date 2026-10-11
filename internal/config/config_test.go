package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
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
		ShutdownTimeout: Duration{Duration: DefaultShutdownTimeout},
		Log:             Log{Level: DefaultLogLevel},
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
	if c.TLS == nil || c.TLS.CertFile != "/etc/flint/tls/tls.crt" || c.ShutdownTimeout.Duration != 25*time.Second {
		t.Errorf("unexpected config %+v", c)
	}
	wantProxies := []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("192.168.1.10/32")}
	if got := c.Proxies(); !reflect.DeepEqual(got, wantProxies) {
		t.Errorf("Proxies() = %v, want %v", got, wantProxies)
	}
	if len(c.Repositories) != 2 || !c.Repositories[1].ImmutableTags || len(c.Auth.Permissions) != 2 {
		t.Errorf("unexpected repositories or permissions: %+v", c)
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
		{"repo unsupported", `{"dataDir": "/d", "repositories": [{"name": "a", "format": "pypi", "type": "proxy"}]}`,
			[]string{`repositories[0].format: "pypi" is not supported`, `repositories[0].type: "proxy" is not supported`}},
		{"repo good", `{"dataDir": "/d", "repositories": [{"name": "my.repo_1-x", "format": "oci", "type": "hosted"}]}`, nil},
		{"permission empty", `{"dataDir": "/d", "auth": {"permissions": [{}]}}`,
			[]string{"auth.permissions[0].repositories: must name at least one", `auth.permissions[0].role: "" is not one of`,
				"auth.permissions[0]: must name at least one user or group"}},
		{"permission bad pattern", `{"dataDir": "/d", "auth": {"permissions": [{"repositories": ["Team/*"], "role": "read", "users": ["a"]}]}}`,
			[]string{`auth.permissions[0].repositories[0]: "Team/*"`}},
		{"permission blank subject", `{"dataDir": "/d", "auth": {"permissions": [{"repositories": ["*"], "role": "read", "users": [" "], "groups": [""]}]}}`,
			[]string{"auth.permissions[0].users[0]: is empty", "auth.permissions[0].groups[0]: is empty"}},
		{"permission good", `{"dataDir": "/d", "auth": {"permissions": [{"repositories": ["team-*"], "role": "delete", "groups": ["g"]}]}}`, nil},
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
