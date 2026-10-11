package repo

import (
	"slices"
	"testing"

	"github.com/terrabyteian/flint/internal/config"
)

func repos(protect *bool) []config.Repository {
	return []config.Repository{
		{Name: "local", Format: config.FormatPyPI, Type: config.TypeHosted},
		{Name: "team", Format: config.FormatPyPI, Type: config.TypeHosted},
		{Name: "pypi", Format: config.FormatPyPI, Type: config.TypeProxy, Proxy: &config.Proxy{URL: "https://pypi.org/simple/"}},
		{Name: "all", Format: config.FormatPyPI, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: []string{"pypi", "local", "team"}, DependencyConfusionProtection: protect}},
		{Name: "oci", Format: config.FormatOCI, Type: config.TypeHosted},
	}
}

func names(ms []Member) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func TestSources(t *testing.T) {
	off := false
	for _, tt := range []struct {
		name    string
		protect *bool
		owners  []string
		want    []string
	}{
		{"unowned name: every member", nil, nil, []string{"pypi", "local", "team"}},
		{"owned name: hosted members only", nil, []string{"team"}, []string{"local", "team"}},
		{"owned by several", nil, []string{"local", "team"}, []string{"local", "team"}},
		{"protection off", &off, []string{"local"}, []string{"pypi", "local", "team"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			all := repos(tt.protect)
			v, err := NewVirtual(all[3], all)
			if err != nil {
				t.Fatal(err)
			}
			got := names(v.Sources(func(m string) bool { return slices.Contains(tt.owners, m) }))
			if !slices.Equal(got, tt.want) {
				t.Errorf("Sources = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewVirtual(t *testing.T) {
	all := repos(nil)
	v, err := NewVirtual(all[3], all)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Protect || v.Name != "all" {
		t.Errorf("NewVirtual = %+v", v)
	}
	want := []Member{{"pypi", false}, {"local", true}, {"team", true}}
	if !slices.Equal(v.Members, want) {
		t.Errorf("members %+v, want %+v", v.Members, want)
	}
	if got := v.Hosted(); !slices.Equal(got, []string{"local", "team"}) {
		t.Errorf("Hosted = %q", got)
	}
	if _, err := NewVirtual(all[0], all); err == nil {
		t.Error("NewVirtual accepted a hosted repository")
	}
	bad := all[3]
	bad.Virtual = &config.Virtual{Members: []string{"oci"}}
	if _, err := NewVirtual(bad, all); err == nil {
		t.Error("NewVirtual accepted a member of another format")
	}
	bad.Virtual = &config.Virtual{Members: []string{"missing"}}
	if _, err := NewVirtual(bad, all); err == nil {
		t.Error("NewVirtual accepted an undeclared member")
	}
}
