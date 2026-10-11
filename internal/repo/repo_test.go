package repo

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/metrics"
)

var quiet = slog.New(slog.DiscardHandler)

func repos(protect *bool) []config.Repository {
	return []config.Repository{
		{Name: "local", Format: config.FormatPyPI, Type: config.TypeHosted},
		{Name: "team", Format: config.FormatPyPI, Type: config.TypeHosted},
		{Name: "pypi", Format: config.FormatPyPI, Type: config.TypeProxy, Proxy: &config.Proxy{URL: "https://pypi.org/simple/"}},
		{Name: "all", Format: config.FormatPyPI, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("pypi", "local", "team"), DependencyConfusionProtection: protect}},
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

// lower is a stand-in for a format's name normalization.
func lower(s string) string { return strings.ToLower(s) }

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
			v, err := NewVirtual(all[3], all, VirtualOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got := names(v.Sources("pkg", func(m string) bool { return slices.Contains(tt.owners, m) }))
			if !slices.Equal(got, tt.want) {
				t.Errorf("Sources = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFilters checks that members are consulted only for the names their
// filters admit, compared after normalization, and that a hosted member
// the filters leave out does not own a name for the virtual repository.
func TestFilters(t *testing.T) {
	all := repos(nil)
	all[3].Virtual.Members = []config.VirtualMember{
		{Name: "local", Include: []string{"Acme-*", "tool"}},
		{Name: "team", Exclude: []string{"acme-secret"}},
		{Name: "pypi", Exclude: []string{"acme-*", "*-internal"}},
	}
	v, err := NewVirtual(all[3], all, VirtualOptions{Normalize: lower})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		owners []string
		want   []string
	}{
		{"numpy", nil, []string{"team", "pypi"}},
		{"ACME-Lib", nil, []string{"local", "team"}},
		{"acme-secret", nil, []string{"local"}},
		{"tool", nil, []string{"local", "team", "pypi"}},
		{"tool", []string{"team"}, []string{"local", "team"}},
		{"build-internal", nil, []string{"team"}},
		// local does not admit numpy, so its owning numpy counts for
		// nothing: the proxy is still asked.
		{"numpy", []string{"local"}, []string{"team", "pypi"}},
		{"numpy", []string{"team"}, []string{"team"}},
	} {
		got := names(v.Sources(tt.name, func(m string) bool { return slices.Contains(tt.owners, m) }))
		if !slices.Equal(got, tt.want) {
			t.Errorf("Sources(%q) with owners %q = %q, want %q", tt.name, tt.owners, got, tt.want)
		}
	}
	if !v.Admits(v.Members[0], "acme-x") || v.Admits(v.Members[0], "other") || v.Admits(v.Members[2], "Acme-X") {
		t.Error("Admits does not follow the filters")
	}
}

// TestSourcesAsksOnlyAdmittedHosted checks that ownership is asked only of
// admitted hosted members, never of proxies.
func TestSourcesAsksOnlyAdmittedHosted(t *testing.T) {
	all := repos(nil)
	all[3].Virtual.Members = []config.VirtualMember{{Name: "pypi"}, {Name: "local", Exclude: []string{"x"}}, {Name: "team"}}
	v, err := NewVirtual(all[3], all, VirtualOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	v.Sources("x", func(m string) bool { asked = append(asked, m); return false })
	if !slices.Equal(asked, []string{"team"}) {
		t.Errorf("ownership asked of %q, want team only", asked)
	}
}

func TestNewVirtual(t *testing.T) {
	all := repos(nil)
	all[3].Virtual.PublishTo = "team"
	v, err := NewVirtual(all[3], all, VirtualOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Protect || v.Name != "all" || v.PublishTo != "team" {
		t.Errorf("NewVirtual = %+v", v)
	}
	want := []Member{{Name: "pypi"}, {Name: "local", Hosted: true}, {Name: "team", Hosted: true}}
	if !slices.EqualFunc(v.Members, want, func(a, b Member) bool { return a.Name == b.Name && a.Hosted == b.Hosted }) {
		t.Errorf("members %+v, want %+v", v.Members, want)
	}
	if got := v.Hosted(); !slices.Equal(got, []string{"local", "team"}) {
		t.Errorf("Hosted = %q", got)
	}
	if _, err := NewVirtual(all[0], all, VirtualOptions{}); err == nil {
		t.Error("NewVirtual accepted a hosted repository")
	}
	bad := all[3]
	for _, vc := range []*config.Virtual{
		{Members: config.Members("oci")},
		{Members: config.Members("missing")},
		{Members: config.Members("local", "pypi"), PublishTo: "pypi"},
		{Members: config.Members("local"), PublishTo: "team"},
	} {
		bad.Virtual = vc
		if _, err := NewVirtual(bad, all, VirtualOptions{}); err == nil {
			t.Errorf("NewVirtual accepted %+v", vc)
		}
	}
}

// TestCheckPublish checks that a publish through the virtual repository
// is refused, naming the filter, when the publishTo member's filters do
// not admit the name.
func TestCheckPublish(t *testing.T) {
	all := repos(nil)
	all[3].Virtual.Members = []config.VirtualMember{
		{Name: "pypi"}, {Name: "local", Include: []string{"Acme-*"}, Exclude: []string{"acme-secret"}}, {Name: "team"},
	}
	all[3].Virtual.PublishTo = "local"
	v, err := NewVirtual(all[3], all, VirtualOptions{Normalize: lower})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.CheckPublish("ACME-Tool"); err != nil {
		t.Errorf("CheckPublish(ACME-Tool) = %v", err)
	}
	for name, filter := range map[string]string{"corp-tool": "acme-*", "acme-secret": "acme-secret"} {
		if err := v.CheckPublish(name); err == nil || !strings.Contains(err.Error(), "local") || !strings.Contains(err.Error(), filter) {
			t.Errorf("CheckPublish(%s) = %v, want a refusal naming local and %s", name, err, filter)
		}
	}
	all[3].Virtual.PublishTo = "team"
	if v, err = NewVirtual(all[3], all, VirtualOptions{Normalize: lower}); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckPublish("corp-tool"); err != nil {
		t.Errorf("CheckPublish through an unfiltered member = %v", err)
	}
	all[3].Virtual.PublishTo = ""
	if v, err = NewVirtual(all[3], all, VirtualOptions{Normalize: lower}); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckPublish("corp-tool"); err != nil {
		t.Errorf("CheckPublish without publishTo = %v", err)
	}
}

var errDown = errors.New("upstream unreachable")

// TestConsult checks that a member that fails is skipped, logged, and
// counted, that not-found members are left out silently, and that
// Consult fails only when no member answered.
func TestConsult(t *testing.T) {
	all := repos(nil)
	reg := metrics.NewRegistry()
	var logs bytes.Buffer
	v, err := NewVirtual(all[3], all, VirtualOptions{Metrics: NewMetrics(reg), Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	notFound := func(err error) bool { return errors.Is(err, errNotFound) }
	answers := func(m map[string]error) ([]Answer[string], error) {
		return Consult(context.Background(), v, v.Members, "pkg", func(_ context.Context, mb Member) (string, error) {
			if err := m[mb.Name]; err != nil {
				return "", err
			}
			return "page of " + mb.Name, nil
		}, notFound)
	}

	got, err := answers(map[string]error{"pypi": errDown, "local": errNotFound})
	if err != nil || len(got) != 1 || got[0].Member.Name != "team" || got[0].Value != "page of team" {
		t.Errorf("Consult = %+v, %v; want team's answer", got, err)
	}
	if !strings.Contains(logs.String(), "member=pypi") || !strings.Contains(logs.String(), "package=pkg") {
		t.Errorf("the skip is not logged: %s", logs.String())
	}
	var exp bytes.Buffer
	reg.WriteTo(&exp)
	if !strings.Contains(exp.String(), `flint_virtual_member_skips_total{repository="all",member="pypi"} 1`) {
		t.Errorf("the skip is not counted:\n%s", exp.String())
	}

	if _, err := answers(map[string]error{"pypi": errDown, "local": errNotFound, "team": errNotFound}); err != errDown {
		t.Errorf("Consult with no answer and a failure = %v, want the failure", err)
	}
	if got, err := answers(map[string]error{"pypi": errNotFound, "local": errNotFound, "team": errNotFound}); err != nil || got != nil {
		t.Errorf("Consult with no answer = %+v, %v; want neither", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Consult(ctx, v, v.Members, "pkg", func(ctx context.Context, _ Member) (int, error) { return 0, ctx.Err() }, notFound); err != context.Canceled {
		t.Errorf("Consult after the context ended = %v", err)
	}
}

var errNotFound = errors.New("not found")

func TestMerge(t *testing.T) {
	type file struct{ name, from string }
	got := Merge([][]file{
		{{"a-1.0", "first"}, {"a-2.0", "first"}},
		{{"a-2.0", "second"}, {"a-3.0", "second"}},
		nil,
		{{"a-1.0", "third"}, {"a-4.0", "third"}},
	}, func(f file) string { return f.name })
	want := []file{{"a-1.0", "first"}, {"a-2.0", "first"}, {"a-3.0", "second"}, {"a-4.0", "third"}}
	if !slices.Equal(got, want) {
		t.Errorf("Merge = %v, want %v", got, want)
	}
}

func TestMatch(t *testing.T) {
	for _, tt := range []struct {
		pattern, name string
		want          bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"@acme/*", "@acme/lib", true},
		{"@acme/*", "@acmecorp/lib", false},
		{"com.acme:*", "com.acme:core", true},
		{"com.acme*", "com.acme.tools:cli", true},
		{"*-internal", "x-internal", true},
		{"*-internal", "x-internals", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"exact", "exact", true},
		{"exact", "exac", false},
		{"", "", true},
		{"", "x", false},
	} {
		if got := Match(tt.pattern, tt.name); got != tt.want {
			t.Errorf("Match(%q, %q) = %v", tt.pattern, tt.name, got)
		}
	}
}
