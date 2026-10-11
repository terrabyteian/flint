package server

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestResolve(t *testing.T) {
	trusted := proxies{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	tests := []struct {
		name    string
		remote  string
		tls     bool
		host    string
		headers map[string][]string
		want    RequestInfo
	}{
		{
			name:   "direct client",
			remote: "203.0.113.5:4321", host: "flint.lan",
			want: RequestInfo{ClientIP: netip.MustParseAddr("203.0.113.5"), Scheme: "http", Host: "flint.lan"},
		},
		{
			name:   "direct tls",
			remote: "203.0.113.5:4321", host: "flint.lan", tls: true,
			want: RequestInfo{ClientIP: netip.MustParseAddr("203.0.113.5"), Scheme: "https", Host: "flint.lan"},
		},
		{
			name:   "untrusted peer's forwarded headers are ignored",
			remote: "203.0.113.5:4321", host: "flint.lan",
			headers: map[string][]string{
				"X-Forwarded-For":   {"198.51.100.1"},
				"X-Forwarded-Proto": {"https"},
				"X-Forwarded-Host":  {"evil.example"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("203.0.113.5"), Scheme: "http", Host: "flint.lan"},
		},
		{
			name:   "trusted proxy",
			remote: "10.1.1.1:80", host: "flint-svc:5000",
			headers: map[string][]string{
				"X-Forwarded-For":   {"198.51.100.1"},
				"X-Forwarded-Proto": {"HTTPS"},
				"X-Forwarded-Host":  {"registry.example.com"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("198.51.100.1"), Scheme: "https", Host: "registry.example.com"},
		},
		{
			name:   "spoofed leftmost entry is skipped",
			remote: "10.1.1.1:80",
			headers: map[string][]string{
				"X-Forwarded-For": {"1.2.3.4, 198.51.100.1, 10.2.2.2"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("198.51.100.1"), Scheme: "http"},
		},
		{
			name:   "multiple header lines are one list",
			remote: "10.1.1.1:80",
			headers: map[string][]string{
				"X-Forwarded-For": {"1.2.3.4", "198.51.100.1", "10.2.2.2"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("198.51.100.1"), Scheme: "http"},
		},
		{
			name:   "all trusted uses the leftmost",
			remote: "10.1.1.1:80",
			headers: map[string][]string{
				"X-Forwarded-For": {"10.3.3.3, 10.2.2.2"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("10.3.3.3"), Scheme: "http"},
		},
		{
			name:   "garbage stops at the last good hop",
			remote: "10.1.1.1:80",
			headers: map[string][]string{
				"X-Forwarded-For": {"198.51.100.1, not-an-ip, 10.2.2.2"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("10.2.2.2"), Scheme: "http"},
		},
		{
			name:   "no forwarded-for keeps the proxy address",
			remote: "10.1.1.1:80",
			want:   RequestInfo{ClientIP: netip.MustParseAddr("10.1.1.1"), Scheme: "http"},
		},
		{
			name:   "ports and brackets in forwarded-for",
			remote: "[fd00::1]:80",
			headers: map[string][]string{
				"X-Forwarded-For": {"[2001:db8::1]:5555, 198.51.100.1:1234"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("198.51.100.1"), Scheme: "http"},
		},
		{
			name:   "ipv6 client through ipv6 proxy",
			remote: "[fd00::1]:80",
			headers: map[string][]string{
				"X-Forwarded-For": {"[2001:db8::1]"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("2001:db8::1"), Scheme: "http"},
		},
		{
			name:   "ipv4-mapped peer matches an ipv4 prefix",
			remote: "[::ffff:10.1.1.1]:80",
			headers: map[string][]string{
				"X-Forwarded-For": {"::ffff:198.51.100.1"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("198.51.100.1"), Scheme: "http"},
		},
		{
			name:   "first proto and host values, bad values ignored",
			remote: "10.1.1.1:80", host: "inner", tls: true,
			headers: map[string][]string{
				"X-Forwarded-Proto": {"gopher, https"},
				"X-Forwarded-Host":  {"bad host, good"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("10.1.1.1"), Scheme: "https", Host: "inner"},
		},
		{
			name:   "proto downgrade by a trusted proxy",
			remote: "10.1.1.1:80", tls: true,
			headers: map[string][]string{
				"X-Forwarded-Proto": {"http, https"},
			},
			want: RequestInfo{ClientIP: netip.MustParseAddr("10.1.1.1"), Scheme: "http"},
		},
		{
			name:   "unparsable remote address",
			remote: "@", host: "h",
			want: RequestInfo{Scheme: "http", Host: "h"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			r.Host = tt.host
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for k, vs := range tt.headers {
				for _, v := range vs {
					r.Header.Add(k, v)
				}
			}
			if got := resolve(r, trusted); got != tt.want {
				t.Errorf("resolve = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResolveNoProxies(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.1.1:80"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := resolve(r, nil); got.ClientIP != netip.MustParseAddr("10.1.1.1") {
		t.Errorf("ClientIP = %v, want the peer when no proxy is trusted", got.ClientIP)
	}
}

// TestBaseURL checks that the configured public URL is the base of
// absolute URLs, and that without one the base is the scheme and host the
// client addressed, honoring trusted proxies, which Origin always is.
func TestBaseURL(t *testing.T) {
	for _, tt := range []struct {
		name, public, want, origin string
		forwarded                  bool
	}{
		{"request host", "", "http://flint.lan:5000", "http://flint.lan:5000", false},
		{"forwarded by a trusted proxy", "", "https://flint.example.com", "https://flint.example.com", true},
		{"public URL", "https://registry.example.org/", "https://registry.example.org", "https://flint.example.com", true},
		{"public URL with a path", "https://example.org/flint", "https://example.org/flint", "http://flint.lan:5000", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New(Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, PublicURL: tt.public,
				Logger: slog.New(slog.DiscardHandler)})
			if err != nil {
				t.Fatal(err)
			}
			s.HandleFunc("GET /x", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, BaseURL(r)+" "+Origin(r)) })
			r := httptest.NewRequest("GET", "http://flint.lan:5000/x", nil)
			r.RemoteAddr = "10.0.0.1:1234"
			if tt.forwarded {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "flint.example.com")
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if got, want := w.Body.String(), tt.want+" "+tt.origin; got != want {
				t.Errorf("BaseURL and Origin = %q, want %q", got, want)
			}
		})
	}
	// Outside a Server, as in a format's unit tests, the request decides.
	r := httptest.NewRequest("GET", "https://flint.lan/x", nil)
	r.TLS = &tls.ConnectionState{}
	if got := BaseURL(r); got != "https://flint.lan" {
		t.Errorf("BaseURL outside a server = %q", got)
	}
}
