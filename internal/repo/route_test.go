package repo

import (
	"slices"
	"testing"

	"github.com/terrabyteian/flint/internal/config"
)

func TestPaths(t *testing.T) {
	for _, tt := range []struct{ format, name, want string }{
		{config.FormatOCI, "docker-local", "/v2/docker-local/"},
		{config.FormatPyPI, "pypi-local", "/pypi/pypi-local/"},
		{"npm", "npm-all", "/npm/npm-all/"},
	} {
		if got := Path(tt.format, tt.name); got != tt.want {
			t.Errorf("Path(%q, %q) = %q, want %q", tt.format, tt.name, got, tt.want)
		}
	}
}

func TestSplit(t *testing.T) {
	for _, tt := range []struct {
		format, path string
		name, rest   string
		slash, under bool
	}{
		{"pypi", "/pypi/local/simple/pkg/", "local", "simple/pkg/", true, true},
		{"pypi", "/pypi/local/", "local", "", true, true},
		{"pypi", "/pypi/local", "local", "", false, true},
		{"pypi", "/pypi/", "", "", false, true},
		{"pypi", "/npm/local/x", "", "", false, false},
		{"pypi", "/pypix/local/", "", "", false, false},
		{"oci", "/v2/docker-local/team/app/manifests/1", "docker-local", "team/app/manifests/1", true, true},
	} {
		name, rest, slash, ok := Split(tt.format, tt.path)
		if name != tt.name || rest != tt.rest || slash != tt.slash || ok != tt.under {
			t.Errorf("Split(%q, %q) = %q, %q, %v, %v", tt.format, tt.path, name, rest, slash, ok)
		}
	}
}

// TestFormatsAvoidReservedPaths checks that no format the configuration
// accepts is served under one of flint's own paths.
func TestFormatsAvoidReservedPaths(t *testing.T) {
	for _, f := range config.Formats() {
		if f == config.FormatOCI {
			continue
		}
		if slices.Contains(Reserved, f) {
			t.Errorf("format %s would be served under /%s/, which flint serves itself", f, f)
		}
		if got := Prefix(f); got != "/"+f+"/" {
			t.Errorf("Prefix(%q) = %q", f, got)
		}
	}
}
