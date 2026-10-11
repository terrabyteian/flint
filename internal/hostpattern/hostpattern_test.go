package hostpattern_test

import (
	"testing"

	"github.com/terrabyteian/flint/internal/hostpattern"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want hostpattern.Pattern
	}{
		{"files.example", hostpattern.Pattern{Host: "files.example"}},
		{"CDN.Example.:8443", hostpattern.Pattern{Host: "cdn.example", Port: "8443"}},
		{"cdn.example:0443", hostpattern.Pattern{Host: "cdn.example", Port: "443"}},
		{"*.blob.example", hostpattern.Pattern{Host: "blob.example", Wildcard: true}},
		{"10.0.0.7", hostpattern.Pattern{Host: "10.0.0.7"}},
		{"[fd00::1]:443", hostpattern.Pattern{Host: "fd00::1", Port: "443"}},
		{"fd00::2", hostpattern.Pattern{Host: "fd00::2"}},
		{"[fd00::3]", hostpattern.Pattern{Host: "fd00::3"}},
	} {
		got, err := hostpattern.Parse(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", tc.in, got, err, tc.want)
		}
	}
	for _, s := range []string{"", ".", "https://cdn.example", "cdn.example/path", "user@host", "a b", "a\tb",
		"a.*.example", "*", "*.", "cdn.example:", "cdn.example:0", "cdn.example:x", "host:99999"} {
		if p, err := hostpattern.Parse(s); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", s, p)
		}
	}
}

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, host, port string
		ok                  bool
	}{
		{"cdn.example", "cdn.example", "443", true},
		{"cdn.example", "cdn.example", "8080", true},
		{"cdn.example:443", "cdn.example", "443", true},
		{"cdn.example:443", "cdn.example", "80", false},
		{"cdn.example", "other.example", "443", false},
		{"*.example.com", "a.example.com", "443", true},
		{"*.example.com", "a.b.example.com", "443", true},
		{"*.example.com", "example.com", "443", false},
		{"*.example.com", "badexample.com", "443", false},
	} {
		p, err := hostpattern.Parse(tc.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Match(tc.host, tc.port); got != tc.ok {
			t.Errorf("%q matches %s:%s = %v, want %v", tc.pattern, tc.host, tc.port, got, tc.ok)
		}
	}
}
