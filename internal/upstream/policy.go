package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
)

// ErrPolicy means the fetch policy refused a request: upstream metadata,
// a redirect, or a token challenge named a host the proxy repository may
// not fetch from, or a host that resolves to an internal address. It is
// not an answer about the content and not an outage: it is neither
// retried nor marks the upstream offline.
var ErrPolicy = errors.New("refused by the upstream fetch policy")

// Policy decides which hosts a Client fetches from besides its upstream's
// own, which it always may.
//
// Hosts the configuration names (the upstream URL's host and AllowHosts)
// may resolve to any address, so an upstream inside the network works.
// Every other host, which only upstream content, a redirect, or a token
// challenge can lead to, must resolve to a public address: flint refuses
// to connect to loopback, link-local, private, and unspecified addresses
// for it. The check runs on the resolved address when the connection is
// dialed, not on the host name, so a name that resolves differently by
// then cannot get around it. Metadata from an upstream therefore never
// steers flint at internal services.
type Policy struct {
	// AllowHosts are further hosts the administrator allows
	// (proxy.allowHosts). Each is a host name or IP address, optionally
	// with a port, or "*.example.com" for every subdomain of example.com.
	// They may resolve to internal addresses.
	AllowHosts []string
	// FormatHosts are the hosts the format allows for this upstream, such
	// as static.crates.io for crates.io or files.pythonhosted.org for
	// pypi.org, in the syntax of AllowHosts. They must resolve to public
	// addresses.
	FormatHosts []string
	// AnyHost allows every host, at public addresses only. The OCI
	// distribution protocol lets a registry redirect blob downloads to,
	// and name a token service on, any host.
	AnyHost bool
}

// policy is a Client's compiled Policy.
type policy struct {
	own     hostPattern   // the upstream's own host and port
	allow   []hostPattern // configured: any address
	formats []hostPattern // format defaults: public addresses only
	anyHost bool

	mu      sync.Mutex
	proxies map[string]bool // host:port of HTTP proxies the transport used
}

// hostPattern matches a host, with a port or any port, or every
// subdomain of a domain.
type hostPattern struct {
	host     string // lowercase, without brackets
	port     string // "" for any port
	wildcard bool   // host is a domain whose subdomains match
}

func (p hostPattern) match(host, port string) bool {
	if p.port != "" && p.port != port {
		return false
	}
	if p.wildcard {
		return strings.HasSuffix(host, "."+p.host)
	}
	return host == p.host
}

func parseHostPattern(s string) (hostPattern, error) {
	if s == "" || strings.ContainsAny(s, "/?#@ ") {
		return hostPattern{}, fmt.Errorf("%q is not a host name or address, optionally with a port", s)
	}
	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	} else if strings.Count(s, ":") > 1 { // a bare IPv6 address
		host = strings.Trim(s, "[]")
	}
	if port != "" {
		if _, err := netip.ParseAddrPort("0.0.0.0:" + port); err != nil {
			return hostPattern{}, fmt.Errorf("%q has an invalid port", s)
		}
	}
	p := hostPattern{host: strings.ToLower(strings.TrimSuffix(host, ".")), port: port}
	if rest, ok := strings.CutPrefix(p.host, "*."); ok {
		p.host, p.wildcard = rest, true
	}
	if p.host == "" || strings.Contains(p.host, "*") {
		return hostPattern{}, fmt.Errorf("%q is not a host name or address; a wildcard is allowed only as a leading \"*.\"", s)
	}
	return p, nil
}

// splitURLHost returns u's lowercase host name and its port, the
// scheme's default if it names none.
func splitURLHost(u *url.URL) (host, port string) {
	host = strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port = u.Port()
	if port == "" {
		port = "80"
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		}
	}
	return host, port
}

func compilePolicy(base *url.URL, pol Policy) (*policy, error) {
	host, port := splitURLHost(base)
	p := &policy{own: hostPattern{host: host, port: port}, anyHost: pol.AnyHost, proxies: map[string]bool{}}
	for _, s := range pol.AllowHosts {
		hp, err := parseHostPattern(s)
		if err != nil {
			return nil, fmt.Errorf("upstream: allowed host %w", err)
		}
		p.allow = append(p.allow, hp)
	}
	for _, s := range pol.FormatHosts {
		hp, err := parseHostPattern(s)
		if err != nil {
			return nil, fmt.Errorf("upstream: format host %w", err)
		}
		p.formats = append(p.formats, hp)
	}
	return p, nil
}

// configured reports whether the configuration names host and port: the
// upstream's own host or an allowed host. Such a host may resolve to an
// internal address.
func (p *policy) configured(host, port string) bool {
	if p.own.match(host, port) {
		return true
	}
	for _, hp := range p.allow {
		if hp.match(host, port) {
			return true
		}
	}
	return false
}

// check returns an error wrapping ErrPolicy unless the policy allows
// fetching u.
func (p *policy) check(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: %q is not an http or https URL", ErrPolicy, u.Redacted())
	}
	host, port := splitURLHost(u)
	if p.configured(host, port) {
		return nil
	}
	if a, err := netip.ParseAddr(host); err == nil && internal(a) {
		return fmt.Errorf("%w: %s is an internal address", ErrPolicy, u.Host)
	}
	if p.anyHost {
		return nil
	}
	for _, hp := range p.formats {
		if hp.match(host, port) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not the upstream's host or an allowed host; add it to proxy.allowHosts to allow it", ErrPolicy, u.Host)
}

// internal reports whether a is an address flint never connects to for a
// host only upstream content led to.
func internal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsUnspecified() || !a.IsValid()
}

// checkRedirect is the http.Client's CheckRedirect: a redirect is
// followed only to a host the policy allows.
func (p *policy) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return p.check(req.URL)
}

// proxyFunc returns the transport's Proxy function: the environment's
// proxy, which the policy then trusts like a configured host, since flint
// connects to it and not to the request's host.
func (p *policy) proxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		u, err := http.ProxyFromEnvironment(req)
		if u != nil {
			host, port := splitURLHost(u)
			p.mu.Lock()
			p.proxies[net.JoinHostPort(host, port)] = true
			p.mu.Unlock()
		}
		return u, err
	}
}

// dialContext dials addr, refusing internal addresses unless the
// configuration names addr's host or it is an HTTP proxy's.
func (p *policy) dialContext(base *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		p.mu.Lock()
		proxy := p.proxies[net.JoinHostPort(host, port)]
		p.mu.Unlock()
		if proxy || p.configured(host, port) {
			return base.DialContext(ctx, network, addr)
		}
		d := *base
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: cannot check address %s", ErrPolicy, address)
			}
			if internal(ap.Addr()) {
				return fmt.Errorf("%w: %s resolves to the internal address %s", ErrPolicy, host, ap.Addr())
			}
			return nil
		}
		return d.DialContext(ctx, network, addr)
	}
}
