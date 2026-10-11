// Package hostpattern parses and matches the host patterns of a proxy
// repository's allowed hosts (proxy.allowHosts): a host name or IP
// address, optionally with a port, or "*." and a domain for every
// subdomain of the domain. Configuration validation and the upstream
// fetch policy share it, so what one accepts the other enforces alike.
package hostpattern

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Pattern matches a host, with a port or any port, or every subdomain of
// a domain.
type Pattern struct {
	// Host is lowercase, without brackets or a trailing dot.
	Host string
	// Port is the decimal port, or "" for any port.
	Port string
	// Wildcard means Host is a domain whose subdomains match, but not
	// the domain itself.
	Wildcard bool
}

// Parse parses a host pattern.
func Parse(s string) (Pattern, error) {
	if s == "" || strings.ContainsAny(s, "/?#@ \t") {
		return Pattern{}, fmt.Errorf("%q is not a host name or address, optionally with a port", s)
	}
	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Pattern{}, fmt.Errorf("%q has an invalid port", s)
		}
		host, port = h, strconv.Itoa(n)
	} else if strings.Count(s, ":") > 1 { // a bare IPv6 address
		host = strings.Trim(s, "[]")
	} else if strings.Contains(s, ":") {
		return Pattern{}, fmt.Errorf("%q has an invalid port", s)
	}
	p := Pattern{Host: strings.ToLower(strings.TrimSuffix(host, ".")), Port: port}
	if rest, ok := strings.CutPrefix(p.Host, "*."); ok {
		p.Host, p.Wildcard = rest, true
	}
	if p.Host == "" || strings.Contains(p.Host, "*") {
		return Pattern{}, fmt.Errorf("%q is not a host name or address; a wildcard is allowed only as a leading \"*.\"", s)
	}
	return p, nil
}

// Match reports whether the pattern matches a lowercase host, without
// brackets or a trailing dot, and its port.
func (p Pattern) Match(host, port string) bool {
	if p.Port != "" && p.Port != port {
		return false
	}
	if p.Wildcard {
		return strings.HasSuffix(host, "."+p.Host)
	}
	return host == p.Host
}
