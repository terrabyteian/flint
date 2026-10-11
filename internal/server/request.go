package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// RequestInfo describes a request as the client made it, after
// trusted-proxy resolution.
type RequestInfo struct {
	// ID identifies the request in logs and in the X-Request-Id response header.
	ID string
	// ClientIP is the client's address: the connection's peer, or, when
	// the peer is a trusted proxy, the nearest untrusted address in
	// X-Forwarded-For.
	ClientIP netip.Addr
	// Scheme is "https" or "http", as the client connected: from the
	// connection, or from X-Forwarded-Proto set by a trusted proxy.
	Scheme string
	// Host is the host the client addressed: the Host header, or
	// X-Forwarded-Host set by a trusted proxy.
	Host string
}

// requestState is the per-request state the server's middleware keeps in
// the request context. Handlers annotate it through SetRoute and LogAttrs.
type requestState struct {
	info RequestInfo

	mu    sync.Mutex
	route string // the metrics and log route label
	attrs []slog.Attr
	quiet bool // log at debug level, for probes and scrapes
}

type stateKey struct{}

func stateFrom(ctx context.Context) *requestState {
	st, _ := ctx.Value(stateKey{}).(*requestState)
	return st
}

// Info returns the request information for a request served by a Server,
// or the zero RequestInfo for a context that did not come from one.
func Info(ctx context.Context) RequestInfo {
	if st := stateFrom(ctx); st != nil {
		return st.info
	}
	return RequestInfo{}
}

// ClientAddr returns the client IP address of the request ctx belongs
// to, as trusted-proxy handling resolved it, or "" if it is unknown.
func ClientAddr(ctx context.Context) string {
	if ip := Info(ctx).ClientIP; ip.IsValid() {
		return ip.String()
	}
	return ""
}

// SetRoute names the route that served the request, for the route label
// of request metrics and the request log. It overrides the mux pattern,
// which is the default; a handler that routes internally, such as one
// mounted at /v2/, calls it with a fixed, low-cardinality name.
func SetRoute(ctx context.Context, route string) {
	if st := stateFrom(ctx); st != nil {
		st.mu.Lock()
		st.route = route
		st.mu.Unlock()
	}
}

// LogAttrs adds attributes to the request's log line, such as the
// authenticated user. Attributes must not contain secrets.
func LogAttrs(ctx context.Context, attrs ...slog.Attr) {
	if st := stateFrom(ctx); st != nil {
		st.mu.Lock()
		st.attrs = append(st.attrs, attrs...)
		st.mu.Unlock()
	}
}

func (st *requestState) setDefaultRoute(route string, quiet bool) {
	st.mu.Lock()
	st.quiet = quiet
	if st.route == "" {
		st.route = route
	}
	st.mu.Unlock()
}

func (st *requestState) snapshot() (route string, quiet bool, attrs []slog.Attr) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.route, st.quiet, st.attrs
}

// proxies is a set of trusted-proxy prefixes.
type proxies []netip.Prefix

func (p proxies) trusted(a netip.Addr) bool {
	for _, pfx := range p {
		if pfx.Contains(a) {
			return true
		}
	}
	return false
}

// resolve determines the client's address, scheme, and host. Forwarded
// headers are believed only when the connection's peer is a trusted
// proxy. X-Forwarded-For is read from right to left, skipping trusted
// proxies; the first untrusted address is the client. If every address is
// trusted, the leftmost is the client; an unparsable entry ends the walk
// at the last good address. X-Forwarded-Proto and X-Forwarded-Host use
// their first value, the one the outermost proxy set.
func resolve(r *http.Request, p proxies) RequestInfo {
	info := RequestInfo{Scheme: "http", Host: r.Host}
	if r.TLS != nil {
		info.Scheme = "https"
	}
	peer, ok := parseAddr(r.RemoteAddr)
	if !ok {
		return info
	}
	info.ClientIP = peer
	if !p.trusted(peer) {
		return info
	}

	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseAddr(strings.TrimSpace(hops[i]))
		if !ok {
			break
		}
		info.ClientIP = a
		if !p.trusted(a) {
			break
		}
	}

	if proto, ok := firstValue(r.Header, "X-Forwarded-Proto"); ok {
		switch strings.ToLower(proto) {
		case "http", "https":
			info.Scheme = strings.ToLower(proto)
		}
	}
	if host, ok := firstValue(r.Header, "X-Forwarded-Host"); ok && validHost(host) {
		info.Host = host
	}
	return info
}

// parseAddr parses an IP address with or without a port, such as a
// RemoteAddr or an X-Forwarded-For entry, dropping any zone and unmapping
// IPv4-mapped IPv6 addresses.
func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"))
	if err != nil {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return netip.Addr{}, false
		}
		a = ap.Addr()
	}
	return a.Unmap().WithZone(""), true
}

// firstValue returns the first comma-separated value of a header.
func firstValue(h http.Header, name string) (string, bool) {
	v := h.Get(name)
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	return v, v != ""
}

// validHost reports whether s is a plausible host[:port]: letters,
// digits, and the punctuation of DNS names, IPv6 literals, and ports.
func validHost(s string) bool {
	if len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_' || c == ':' || c == '[' || c == ']') {
			return false
		}
	}
	return true
}
