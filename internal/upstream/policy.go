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

	"github.com/terrabyteian/flint/internal/hostpattern"
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
// to connect to loopback, link-local, private, shared (100.64.0.0/10),
// and unspecified (0.0.0.0/8) addresses for it, nor to IPv6 addresses
// that embed such an IPv4 address (NAT64 64:ff9b::/96 and 6to4
// 2002::/16). The check runs on the resolved address when the connection is
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
	own     hostpattern.Pattern   // the upstream's own host and port
	allow   []hostpattern.Pattern // configured: any address
	formats []hostpattern.Pattern // format defaults: public addresses only
	anyHost bool

	mu      sync.Mutex
	proxies map[string]bool // host:port of HTTP proxies the transport used
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
	p := &policy{own: hostpattern.Pattern{Host: host, Port: port}, anyHost: pol.AnyHost, proxies: map[string]bool{}}
	for _, s := range pol.AllowHosts {
		hp, err := hostpattern.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("upstream: allowed host %w", err)
		}
		p.allow = append(p.allow, hp)
	}
	for _, s := range pol.FormatHosts {
		hp, err := hostpattern.Parse(s)
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
	if p.own.Match(host, port) {
		return true
	}
	for _, hp := range p.allow {
		if hp.Match(host, port) {
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
		if hp.Match(host, port) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not the upstream's host or an allowed host; add it to proxy.allowHosts to allow it", ErrPolicy, u.Host)
}

// Address ranges internal beyond netip's classification, and IPv6
// ranges that embed an IPv4 address.
var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")     // RFC 791: this host on this network
	sharedSpace = netip.MustParsePrefix("100.64.0.0/10") // RFC 6598: carrier-grade NAT, some clouds' metadata services
	nat64       = netip.MustParsePrefix("64:ff9b::/96")  // RFC 6052: the IPv4 address in the last 32 bits
	sixToFour   = netip.MustParsePrefix("2002::/16")     // RFC 3056: the IPv4 address in bits 16 to 47
)

// internal reports whether a is an address flint never connects to for a
// host only upstream content led to: loopback, private, link-local,
// shared, or unspecified, or an IPv6 address embedding such an IPv4
// address.
func internal(a netip.Addr) bool {
	a = a.Unmap()
	switch b := a.As16(); {
	case nat64.Contains(a):
		a = netip.AddrFrom4([4]byte(b[12:16]))
	case sixToFour.Contains(a):
		a = netip.AddrFrom4([4]byte(b[2:6]))
	}
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsUnspecified() || !a.IsValid() ||
		thisNetwork.Contains(a) || sharedSpace.Contains(a)
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
