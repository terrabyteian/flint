package config

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Defaults of the sign-in settings.
const (
	// DefaultSessionTTL is how long a sign-in session lasts.
	DefaultSessionTTL = 12 * time.Hour
	// DefaultOIDCUsernameClaim is the ID token claim an OIDC user's flint
	// name comes from.
	DefaultOIDCUsernameClaim = "email"
	// DefaultOIDCGroupsClaim is the ID token claim that lists an OIDC
	// user's groups at the provider.
	DefaultOIDCGroupsClaim = "groups"
)

// DefaultOIDCScopes are the scopes requested from an OIDC provider.
var DefaultOIDCScopes = []string{"openid", "email", "profile"}

// OIDCSigningAlgorithms are the ID token signature algorithms flint
// verifies, as JWS names them.
var OIDCSigningAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// OIDCProvider is an OpenID Connect provider users sign in through.
// Users who sign in are created on their first sign-in and identified by
// the provider's issuer and their subject, never by email.
type OIDCProvider struct {
	// Name identifies the provider in flint's URLs, as in
	// /auth/oidc/<name>/callback: 1 to 64 lowercase letters and digits,
	// with single ".", "_", or "-" separators.
	Name string `json:"name"`
	// DisplayName is shown on the sign-in page. Default: Name.
	DisplayName string `json:"displayName,omitempty"`
	// Issuer is the provider's issuer URL, exactly as its ID tokens and
	// its discovery document name it. It must be https, except on a
	// loopback address.
	Issuer string `json:"issuer"`
	// ClientID is flint's client ID at the provider.
	ClientID string `json:"clientId"`
	// ClientSecretFile, if set, holds the client secret: an absolute
	// path, read at every sign-in so a rotated secret takes effect. One
	// trailing newline is ignored. Without it, flint is a public client
	// and relies on PKCE alone.
	ClientSecretFile string `json:"clientSecretFile,omitempty"`
	// CAFile, if set, holds PEM certificates of the certificate
	// authorities that the provider's TLS certificates are checked
	// against, instead of the system's.
	CAFile string `json:"caFile,omitempty"`
	// Scopes are the scopes requested; they must include "openid".
	// Default: openid, email, and profile.
	Scopes []string `json:"scopes,omitempty"`
	// UsernameClaim is the ID token claim the user's flint name is made
	// from, lowercased, when the user first signs in. Default "email",
	// which counts only if the provider says it is verified.
	UsernameClaim string `json:"usernameClaim,omitempty"`
	// GroupsClaim is the ID token claim that lists the user's groups at
	// the provider: an array of strings, or one string. Default "groups".
	GroupsClaim string `json:"groupsClaim,omitempty"`
	// AllowedDomains, if set, admits only users whose verified email is
	// in one of these domains.
	AllowedDomains []string `json:"allowedDomains,omitempty"`
	// AllowedGroups, if set, admits only users in one of these groups at
	// the provider.
	AllowedGroups []string `json:"allowedGroups,omitempty"`
	// GroupMappings maps a group at the provider to the flint groups its
	// members belong to.
	GroupMappings map[string][]string `json:"groupMappings,omitempty"`
	// ImportGroups also makes the user a member of each of the user's
	// groups at the provider whose name, lowercased, is a valid flint
	// group name, by that name.
	ImportGroups bool `json:"importGroups,omitempty"`
	// AdminGroups, if set, makes the members of these groups at the
	// provider global administrators, and everyone else not, at every
	// sign-in. Without it, the admin flag is managed through the admin
	// API.
	AdminGroups []string `json:"adminGroups,omitempty"`
	// SigningAlgorithms, if set, are the only ID token signature
	// algorithms accepted. Default: those the provider's discovery
	// document lists, among the ones flint supports.
	SigningAlgorithms []string `json:"signingAlgorithms,omitempty"`
}

// Display returns the name the sign-in page shows for the provider.
func (p *OIDCProvider) Display() string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	return p.Name
}

func (c *Config) setOIDCDefaults() {
	for i := range c.Auth.OIDC {
		p := &c.Auth.OIDC[i]
		if p.Scopes == nil {
			p.Scopes = slices.Clone(DefaultOIDCScopes)
		}
		if p.UsernameClaim == "" {
			p.UsernameClaim = DefaultOIDCUsernameClaim
		}
		if p.GroupsClaim == "" {
			p.GroupsClaim = DefaultOIDCGroupsClaim
		}
	}
}

// validateSignIn checks the session and OIDC settings.
func (c *Config) validateSignIn(v *validator) {
	switch d := c.Auth.SessionTTL; {
	case d.invalid != "":
		v.addf("auth.sessionTTL", "%s", d.invalid)
	case d.Duration <= 0:
		v.addf("auth.sessionTTL", "must be positive")
	}
	names := map[string]int{}
	for i := range c.Auth.OIDC {
		p := &c.Auth.OIDC[i]
		path := fmt.Sprintf("auth.oidc[%d]", i)
		if !validRepoName(p.Name) {
			v.addf(path+".name", "%q is not a valid provider name: use 1 to 64 lowercase letters and digits, "+
				"with single \".\", \"_\", or \"-\" separators between them", p.Name)
		} else if j, dup := names[p.Name]; dup {
			v.addf(path+".name", "%q is already declared by auth.oidc[%d]", p.Name, j)
		} else {
			names[p.Name] = i
		}
		if len(p.DisplayName) > 128 || strings.ContainsFunc(p.DisplayName, isControl) {
			v.addf(path+".displayName", "must be at most 128 bytes, without control characters")
		}
		if p.Issuer == "" {
			v.addf(path+".issuer", "is required")
		} else if err := CheckIssuerURL(p.Issuer); err != nil {
			v.addf(path+".issuer", "%q %v", p.Issuer, err)
		}
		switch {
		case p.ClientID == "":
			v.addf(path+".clientId", "is required")
		case strings.ContainsFunc(p.ClientID, isControl):
			v.addf(path+".clientId", "must not contain control characters")
		}
		for _, f := range []struct{ field, value string }{{"clientSecretFile", p.ClientSecretFile}, {"caFile", p.CAFile}} {
			if f.value != "" && !filepath.IsAbs(f.value) {
				v.addf(path+"."+f.field, "%q must be an absolute path", f.value)
			}
		}
		if !slices.Contains(p.Scopes, "openid") {
			v.addf(path+".scopes", "must include \"openid\"")
		}
		for j, s := range p.Scopes {
			if !validScopeToken(s) {
				v.addf(fmt.Sprintf("%s.scopes[%d]", path, j), "%q is not a valid scope", s)
			}
		}
		for _, f := range []struct{ field, value string }{{"usernameClaim", p.UsernameClaim}, {"groupsClaim", p.GroupsClaim}} {
			if strings.TrimSpace(f.value) != f.value || strings.ContainsFunc(f.value, isControl) {
				v.addf(path+"."+f.field, "%q is not a claim name", f.value)
			}
		}
		for j, d := range p.AllowedDomains {
			if d != strings.ToLower(d) || !validHostname(d) {
				v.addf(fmt.Sprintf("%s.allowedDomains[%d]", path, j), "%q is not a lowercase domain name", d)
			}
		}
		checkIdPGroups(v, path+".allowedGroups", p.AllowedGroups)
		checkIdPGroups(v, path+".adminGroups", p.AdminGroups)
		for _, g := range slices.Sorted(maps.Keys(p.GroupMappings)) {
			targets := p.GroupMappings[g]
			gp := fmt.Sprintf("%s.groupMappings[%q]", path, g)
			if g == "" || strings.ContainsFunc(g, isControl) {
				v.addf(gp, "the provider's group name must be non-empty, without control characters")
			}
			if len(targets) == 0 {
				v.addf(gp, "must name at least one flint group")
			}
			for j, t := range targets {
				if !ValidUserName(t) {
					v.addf(fmt.Sprintf("%s[%d]", gp, j), "%q %s", t, nameRule)
				}
			}
		}
		for j, a := range p.SigningAlgorithms {
			if !slices.Contains(OIDCSigningAlgorithms, a) {
				v.addf(fmt.Sprintf("%s.signingAlgorithms[%d]", path, j), "%q is not supported; supported: %s",
					a, strings.Join(OIDCSigningAlgorithms, ", "))
			}
		}
		if p.SigningAlgorithms != nil && len(p.SigningAlgorithms) == 0 {
			v.addf(path+".signingAlgorithms", "must not be empty if set")
		}
	}
}

// checkIdPGroups checks a list of group names at a provider.
func checkIdPGroups(v *validator, path string, groups []string) {
	for j, g := range groups {
		if g == "" || strings.ContainsFunc(g, isControl) {
			v.addf(fmt.Sprintf("%s[%d]", path, j), "group names must be non-empty, without control characters")
		}
	}
}

func isControl(r rune) bool { return r < ' ' || r == 0x7f }

// validScopeToken reports whether s is an OAuth 2 scope token (RFC 6749,
// section 3.3).
func validScopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// CheckIssuerURL checks an OIDC issuer URL: https, or http to a loopback
// address only, with a host, and without credentials, a query, or a
// fragment.
func CheckIssuerURL(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return errors.New("is not a URL")
	case u.Scheme != "https" && u.Scheme != "http":
		return errors.New("must be an https URL")
	case u.Host == "":
		return errors.New("has no host")
	case u.User != nil:
		return errors.New("must not contain credentials")
	case u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return errors.New("must not have a query or fragment")
	case u.Scheme == "http" && !IsLoopback(u.Hostname()):
		return errors.New("must be an https URL; http is allowed only for a loopback address")
	}
	return nil
}

// IsLoopback reports whether host, a URL's host name, is "localhost" or a
// loopback IP address.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
