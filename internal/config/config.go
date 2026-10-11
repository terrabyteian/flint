// Package config loads and validates flint's JSON configuration file.
//
// The file is decoded strictly: an unknown field, a value of the wrong
// type, or trailing data is an error, so a typo never silently falls back
// to a default. Validation then checks every field and reports all
// problems at once, each prefixed with its JSON path. docs/configuration.md
// documents the schema; the Helm chart renders it from YAML values.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/hostpattern"
)

// Default values for optional fields.
const (
	DefaultListen          = ":5000"
	DefaultLogLevel        = "info"
	DefaultShutdownTimeout = 25 * time.Second
	DefaultBootstrapAdmin  = "admin"
	// DefaultRevalidateAfter is how long a proxy repository serves a
	// cached tag before checking it upstream again.
	DefaultRevalidateAfter = 5 * time.Minute
	// DefaultMinFreeSpace is the free space below which proxy
	// repositories stop caching new content.
	DefaultMinFreeSpace = "5%"
	// DefaultGCGracePeriod is how long garbage collection keeps an
	// unreferenced blob after its commit.
	DefaultGCGracePeriod = 24 * time.Hour
	// MinGCGracePeriod is the shortest grace period allowed.
	MinGCGracePeriod = time.Hour
	// DefaultLoginTokenTTL is how long an API token minted by a client's
	// login command stays valid.
	DefaultLoginTokenTTL = 90 * 24 * time.Hour
)

// Config is the configuration file.
type Config struct {
	// Listen is the TCP address the server listens on, host:port.
	// Default ":5000".
	Listen string `json:"listen"`
	// DataDir is the data directory: an absolute path. Required.
	DataDir string `json:"dataDir"`
	// TLS, if set, serves HTTPS from certificate files that are reloaded
	// when they change. Without it the server speaks plain HTTP, for
	// example behind a TLS-terminating trusted proxy.
	TLS *TLS `json:"tls,omitempty"`
	// TrustedProxies lists the proxies, as IP addresses or CIDR prefixes,
	// whose X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host
	// headers are believed. Forwarded headers from anyone else are ignored.
	TrustedProxies []string `json:"trustedProxies,omitempty"`
	// PublicURL, if set, is the URL clients reach flint at, such as
	// "https://flint.example.com": the base of every absolute URL flint
	// writes into the metadata it serves, which clients may store, as in
	// lockfiles. Without it, absolute URLs are built from the scheme and
	// host of each request, as seen through trusted proxies.
	PublicURL string `json:"publicURL,omitempty"`
	// ShutdownTimeout bounds how long a graceful shutdown waits for
	// in-flight requests. Default 25s.
	ShutdownTimeout Duration `json:"shutdownTimeout,omitzero"`
	// Log configures logging.
	Log Log `json:"log"`
	// Repositories declares repositories. Repositories declared here are
	// read-only through the API.
	Repositories []Repository `json:"repositories,omitempty"`
	// Auth declares permission grants.
	Auth Auth `json:"auth"`
	// ProxyCache configures how proxy repositories cache content.
	ProxyCache ProxyCache `json:"proxyCache"`
	// Backup configures backups.
	Backup Backup `json:"backup"`
	// GC configures garbage collection.
	GC GC `json:"gc"`
	// Audit configures the audit log.
	Audit Audit `json:"audit"`
}

// Backup configures where the admin API writes backups.
type Backup struct {
	// Directory is the backup directory: an absolute path outside the
	// data directory, normally on another disk or a mounted volume.
	// Without it, backups are disabled.
	Directory string `json:"directory,omitempty"`
}

// GC configures garbage collection, which deletes the blobs nothing in
// the metadata references any more.
type GC struct {
	// GracePeriod is how long an unreferenced blob is kept after its
	// commit, and a blob link no manifest references after it was
	// linked or read. Default 24h; at least 1h.
	GracePeriod Duration `json:"gracePeriod,omitzero"`
	// Interval, if set, runs garbage collection on a schedule: this long
	// after the previous run started. Without it, garbage collection runs
	// only when an administrator starts it.
	Interval Duration `json:"interval,omitzero"`
}

// Audit configures the audit log, which records every change to the
// metadata store under <dataDir>/audit.
type Audit struct {
	// Retention bounds how long records are kept. Without it, they are
	// kept forever.
	Retention AuditRetention `json:"retention"`
}

// AuditRetention bounds the audit log. Old records are deleted a whole
// segment at a time, oldest first, and segments are sized and aged from
// these limits so that the audit log stays close to them.
type AuditRetention struct {
	// MaxAge, if set, deletes records once they are older, such as
	// "8760h". Default: no limit.
	MaxAge Duration `json:"maxAge,omitzero"`
	// MaxSize, if set, deletes the oldest records while the audit log is
	// larger, such as "10GiB". Default: no limit.
	MaxSize ByteSize `json:"maxSize,omitzero"`
}

// ProxyCache configures the cache that proxy repositories share.
type ProxyCache struct {
	// MinFreeSpace is the free space, on the data directory's
	// filesystem, below which proxy repositories stop caching new
	// content and pass it through instead: a percentage of the
	// filesystem's size, such as "5%", or a size, such as "20GiB".
	// Cached content keeps being served, and nothing is deleted to make
	// room. Default "5%".
	MinFreeSpace FreeSpace `json:"minFreeSpace,omitzero"`
}

// TLS names the certificate and key files, in PEM.
type TLS struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Log configures the structured JSON log.
type Log struct {
	// Level is the minimum level logged: debug, info, warn, or error.
	// Default info.
	Level string `json:"level,omitempty"`
}

// Repository formats and types.
const (
	FormatOCI     = "oci"
	FormatPyPI    = "pypi"
	FormatGeneric = "generic"
	FormatCargo   = "cargo"
	FormatNPM     = "npm"
	FormatMaven   = "maven"
	TypeHosted    = "hosted"
	TypeProxy     = "proxy"
	TypeVirtual   = "virtual"
)

// Repository declares one repository.
type Repository struct {
	// Name is the repository's path prefix, such as "docker-local" in
	// host/docker-local/team/app, or "pypi-local" in
	// host/pypi/pypi-local/simple/. Lowercase letters, digits, and
	// separators ".", "_", or "-" between them; at most 64 characters.
	// Names are unique across formats.
	Name string `json:"name"`
	// Format is the package format: one of Formats(), such as "oci" or
	// "pypi".
	Format string `json:"format"`
	// Type is the repository type: "hosted", "proxy", or "virtual", as
	// the format supports.
	Type string `json:"type"`
	// ImmutableTags makes a pushed tag permanent. Hosted OCI repositories
	// only.
	ImmutableTags bool `json:"immutableTags,omitempty"`
	// AnonymousPull lets unauthenticated clients pull.
	AnonymousPull bool `json:"anonymousPull,omitempty"`
	// HelmIndex also serves the Helm charts pushed to the repository as a
	// classic Helm chart repository at /helm/<name>/. Hosted OCI
	// repositories only.
	HelmIndex bool `json:"helmIndex,omitempty"`
	// Proxy configures a proxy repository's upstream. Required for type
	// "proxy", and not allowed for other types.
	Proxy *Proxy `json:"proxy,omitempty"`
	// Virtual configures a virtual repository's members. Required for
	// type "virtual", and not allowed for other types.
	Virtual *Virtual `json:"virtual,omitempty"`
	// Generic holds the settings of a generic files repository.
	Generic *Generic `json:"generic,omitempty"`
	// Maven holds the settings of a Maven repository. Maven repositories
	// only.
	Maven *Maven `json:"maven,omitempty"`
}

// Proxy configures the upstream registry a proxy repository caches.
type Proxy struct {
	// URL is the upstream. For OCI, it is the registry's base URL, such
	// as "https://registry-1.docker.io" or "https://ghcr.io"; for Docker
	// Hub, single-component image names get the "library/" prefix. For
	// PyPI, it is the simple index URL, such as
	// "https://pypi.org/simple/"; a URL without a path gets "/simple/".
	// For generic files, it is any base URL, such as
	// "https://example.com/releases/download/", under which a request
	// for <path> fetches <url>/<path>.
	// For Cargo, it is the sparse index URL, such as
	// "sparse+https://index.crates.io/"; the "sparse+" prefix is optional.
	// For Maven, it is the repository's base URL, such as
	// "https://repo.maven.apache.org/maven2".
	URL string `json:"url"`
	// Username and PasswordFile, if set, authenticate to the upstream.
	// PasswordFile holds the password or access token, such as a mounted
	// Kubernetes Secret; one trailing newline is ignored. It is read
	// whenever flint authenticates, so a rotated secret takes effect
	// without a restart.
	Username     string `json:"username,omitempty"`
	PasswordFile string `json:"passwordFile,omitempty"`
	// RevalidateAfter is how long a cached tag or package listing is
	// served before it is checked upstream again. Default 5m.
	RevalidateAfter Duration `json:"revalidateAfter,omitzero"`
	// SizeLimit, if set, caps the content cached in the repository: when
	// it is exceeded, the least recently pulled content is evicted.
	// Without it, everything is cached forever.
	SizeLimit ByteSize `json:"sizeLimit,omitzero"`
	// MaxConcurrent bounds the requests the repository has in flight to
	// its upstream at once; further requests wait. Default 64.
	MaxConcurrent int `json:"maxConcurrent,omitempty"`
	// AllowHosts are hosts besides the upstream's own that the repository
	// may fetch from when upstream metadata or a redirect points at them:
	// a host name or IP address, optionally with a port, or
	// "*.example.com" for every subdomain of example.com. Unlike hosts
	// only upstream content leads to, they may be internal addresses.
	AllowHosts []string `json:"allowHosts,omitempty"`
}

// DefaultMaxConcurrent is a proxy repository's default bound on its
// concurrent upstream requests.
const DefaultMaxConcurrent = 64

// Roles a permission grant can give.
const (
	RoleRead   = "read"
	RoleWrite  = "write"
	RoleDelete = "delete"
	RoleAdmin  = "admin"
)

// Auth holds the access-control settings declared in the file. Users and
// API tokens are runtime data in the metadata store, not configuration.
type Auth struct {
	// Permissions grants repository roles to users and groups.
	Permissions []Permission `json:"permissions,omitempty"`
	// BootstrapAdmin, if set, creates the first administrator when no
	// administrator exists yet.
	BootstrapAdmin *BootstrapAdmin `json:"bootstrapAdmin,omitempty"`
	// LoginTokenTTL is how long an API token minted by a package
	// client's login command stays valid. Default 2160h (90 days).
	LoginTokenTTL Duration `json:"loginTokenTTL,omitzero"`
}

// BootstrapAdmin names the first administrator and the file holding its
// password, such as a mounted Kubernetes Secret.
type BootstrapAdmin struct {
	// Username is the administrator's name. Default "admin".
	Username string `json:"username,omitempty"`
	// PasswordFile holds the password; one trailing newline is ignored.
	PasswordFile string `json:"passwordFile"`
}

// Permission grants one role on matching repositories to users and groups.
type Permission struct {
	// Repositories are repository names or patterns in which "*" matches
	// any run of characters, such as "team-a-*".
	Repositories []string `json:"repositories"`
	// Role is read, write, delete, or admin.
	Role string `json:"role"`
	// Users and Groups receive the role; at least one must be named.
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Duration is a time.Duration written in JSON as a string such as "30s".
type Duration struct {
	time.Duration
	// invalid describes a JSON value that is not a duration. Decoding
	// records it rather than failing, so Validate can report it with the
	// field's path, which encoding/json does not give a custom decoder.
	invalid string
	// set reports whether the duration was given or defaulted, so an
	// explicit zero can be told from an absent field.
	set bool
}

// UnmarshalJSON parses a Go duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		*d = Duration{invalid: fmt.Sprintf("%s is not a duration string such as \"30s\"", b)}
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		*d = Duration{invalid: fmt.Sprintf("%q is not a duration: use a number with a unit, such as \"30s\" or \"1m30s\"", s)}
		return nil
	}
	*d = Duration{Duration: v, set: true}
	return nil
}

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

// Load reads, decodes, and validates the configuration file at path, and
// fills in defaults.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

// Parse decodes and validates a configuration file's contents, and fills
// in defaults.
func Parse(b []byte) (*Config, error) {
	c := Config{
		ShutdownTimeout: Duration{Duration: DefaultShutdownTimeout, set: true},
		Auth:            Auth{LoginTokenTTL: Duration{Duration: DefaultLoginTokenTTL, set: true}},
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, decodeError(b, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after the top-level object at %s", position(b, dec.InputOffset()))
	}
	c.setDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) setDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.Log.Level == "" {
		c.Log.Level = DefaultLogLevel
	}
	if b := c.Auth.BootstrapAdmin; b != nil && b.Username == "" {
		b.Username = DefaultBootstrapAdmin
	}
	for _, r := range c.Repositories {
		if p := r.Proxy; p != nil && p.RevalidateAfter.Duration == 0 && p.RevalidateAfter.invalid == "" {
			p.RevalidateAfter = Duration{Duration: DefaultRevalidateAfter, set: true}
		}
	}
	if c.ProxyCache.MinFreeSpace.IsZero() {
		c.ProxyCache.MinFreeSpace, _ = ParseFreeSpace(DefaultMinFreeSpace)
	}
	if g := &c.GC.GracePeriod; !g.set && g.invalid == "" {
		*g = Duration{Duration: DefaultGCGracePeriod, set: true}
	}
}

// decodeError turns a json decoding error into a message naming the field
// or the line and column.
func decodeError(b []byte, err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("invalid JSON at %s: %v", position(b, syn.Offset), syn)
	case errors.As(err, &typ):
		if typ.Field == "" {
			return fmt.Errorf("the configuration must be a JSON object, not %s", typ.Value)
		}
		return fmt.Errorf("%s: want %s, got %s (at %s)", fieldPath(typ.Field), jsonType(typ.Type.Kind().String()), typ.Value, position(b, typ.Offset))
	case errors.Is(err, io.EOF):
		return errors.New("the file is empty; it must be a JSON object")
	case errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("invalid JSON: unexpected end of file")
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return fmt.Errorf("unknown field %s", strings.TrimPrefix(err.Error(), "json: unknown field "))
	}
	return err
}

// fieldPath rewrites encoding/json's dotted field path, such as
// "repositories.0.name", in the form validation uses: "repositories[0].name".
func fieldPath(field string) string {
	var b strings.Builder
	for i, part := range strings.Split(field, ".") {
		if _, err := strconv.Atoi(part); err == nil && i > 0 {
			b.WriteString("[" + part + "]")
			continue
		}
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(part)
	}
	return b.String()
}

// jsonType names a Go kind in JSON terms.
func jsonType(kind string) string {
	switch kind {
	case "string":
		return "a string"
	case "bool":
		return "true or false"
	case "slice", "array":
		return "an array"
	case "struct", "map", "ptr":
		return "an object"
	}
	return "a number"
}

// position formats a byte offset as line:column.
func position(b []byte, off int64) string {
	if off > int64(len(b)) {
		off = int64(len(b))
	}
	line := 1 + bytes.Count(b[:off], []byte("\n"))
	col := off - int64(bytes.LastIndexByte(b[:off], '\n'))
	return fmt.Sprintf("line %d, column %d", line, col)
}

// Validate checks every field and returns all problems found, joined.
func (c *Config) Validate() error {
	var v validator
	if host, port, err := net.SplitHostPort(c.Listen); err != nil {
		v.addf("listen", "%q is not a host:port address, such as \":5000\" or \"0.0.0.0:443\"", c.Listen)
	} else {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			v.addf("listen", "port %q is not a number from 0 to 65535", port)
		}
		if host != "" && net.ParseIP(host) == nil && !validHostname(host) {
			v.addf("listen", "host %q is not an IP address or hostname", host)
		}
	}

	switch {
	case c.DataDir == "":
		v.addf("dataDir", "is required")
	case !filepath.IsAbs(c.DataDir):
		v.addf("dataDir", "%q must be an absolute path", c.DataDir)
	}

	if c.TLS != nil {
		if c.TLS.CertFile == "" {
			v.addf("tls.certFile", "is required when tls is set")
		}
		if c.TLS.KeyFile == "" {
			v.addf("tls.keyFile", "is required when tls is set")
		}
	}

	for i, s := range c.TrustedProxies {
		if _, err := ParseProxy(s); err != nil {
			v.addf(fmt.Sprintf("trustedProxies[%d]", i), "%v", err)
		}
	}

	if c.PublicURL != "" {
		if err := checkPublicURL(c.PublicURL); err != nil {
			v.addf("publicURL", "%q %v", c.PublicURL, err)
		}
	}

	if c.ShutdownTimeout.invalid != "" {
		v.addf("shutdownTimeout", "%s", c.ShutdownTimeout.invalid)
	} else if c.ShutdownTimeout.Duration <= 0 {
		v.addf("shutdownTimeout", "must be positive")
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		v.addf("log.level", "%q is not one of debug, info, warn, error", c.Log.Level)
	}

	names := map[string]int{}
	for i, r := range c.Repositories {
		path := fmt.Sprintf("repositories[%d]", i)
		if !validRepoName(r.Name) {
			v.addf(path+".name", "%q is not a valid repository name: use 1 to 64 lowercase letters and digits, "+
				"with single \".\", \"_\", or \"-\" separators between them", r.Name)
		} else if j, dup := names[r.Name]; dup {
			v.addf(path+".name", "%q is already declared by repositories[%d]", r.Name, j)
		} else {
			names[r.Name] = i
		}
		validateFormat(&v, path, &c.Repositories[i])
		switch {
		case !r.ImmutableTags || r.Format == FormatOCI && r.Type == TypeHosted:
		case r.Type == TypeProxy:
			v.addf(path+".immutableTags", "is not allowed for a proxy repository, whose tags follow the upstream")
		default:
			v.addf(path+".immutableTags", "is only allowed for a hosted OCI repository")
		}
		switch {
		case !r.HelmIndex || r.Format == FormatOCI && r.Type == TypeHosted:
		case r.Type == TypeProxy:
			v.addf(path+".helmIndex", "is not allowed for a proxy repository, which holds only the charts pulled through it")
		default:
			v.addf(path+".helmIndex", "is only allowed for a hosted OCI repository")
		}
		if r.Proxy != nil && r.Type != TypeProxy {
			v.addf(path+".proxy", "is only allowed for type %q", TypeProxy)
		}
		if r.Virtual != nil && r.Type != TypeVirtual {
			v.addf(path+".virtual", "is only allowed for type %q", TypeVirtual)
		}
		switch r.Type {
		case TypeHosted:
		case TypeProxy:
			if r.Proxy == nil {
				v.addf(path+".proxy", "is required for type %q", TypeProxy)
			} else {
				validateProxy(&v, path+".proxy", r.Format, r.Proxy)
			}
		case TypeVirtual:
			if r.Virtual == nil {
				v.addf(path+".virtual", "is required for type %q", TypeVirtual)
			}
		case "":
			v.addf(path+".type", "is required")
		default:
			v.addf(path+".type", "%q is not supported; supported types: hosted, proxy, virtual", r.Type)
		}
	}
	for i, r := range c.Repositories {
		if f := formatOf(r.Format); r.Type == TypeVirtual && r.Virtual != nil && f != nil && slices.Contains(f.types, TypeVirtual) {
			c.validateVirtual(&v, fmt.Sprintf("repositories[%d].virtual", i), r, names)
		}
	}
	if f := c.ProxyCache.MinFreeSpace; f.invalid != "" {
		v.addf("proxyCache.minFreeSpace", "%s", f.invalid)
	}
	switch g := c.GC.GracePeriod; {
	case g.invalid != "":
		v.addf("gc.gracePeriod", "%s", g.invalid)
	case g.Duration < MinGCGracePeriod:
		v.addf("gc.gracePeriod", "%s is shorter than the minimum, %s", g.Duration, MinGCGracePeriod)
	}
	switch i := c.GC.Interval; {
	case i.invalid != "":
		v.addf("gc.interval", "%s", i.invalid)
	case i.Duration < 0:
		v.addf("gc.interval", "must be positive")
	}
	switch d := c.Audit.Retention.MaxAge; {
	case d.invalid != "":
		v.addf("audit.retention.maxAge", "%s", d.invalid)
	case d.Duration < 0:
		v.addf("audit.retention.maxAge", "must not be negative")
	}
	if s := c.Audit.Retention.MaxSize; s.invalid != "" {
		v.addf("audit.retention.maxSize", "%s", s.invalid)
	} else if s.set && s.Bytes <= 0 {
		v.addf("audit.retention.maxSize", "must be positive")
	}

	for i, p := range c.Auth.Permissions {
		path := fmt.Sprintf("auth.permissions[%d]", i)
		if len(p.Repositories) == 0 {
			v.addf(path+".repositories", "must name at least one repository or pattern")
		}
		for j, pat := range p.Repositories {
			if !ValidRepoPattern(pat) {
				v.addf(fmt.Sprintf("%s.repositories[%d]", path, j),
					"%q is not a repository name or a pattern of name characters and \"*\"", pat)
			}
		}
		switch p.Role {
		case RoleRead, RoleWrite, RoleDelete, RoleAdmin:
		default:
			v.addf(path+".role", "%q is not one of read, write, delete, admin", p.Role)
		}
		if len(p.Users) == 0 && len(p.Groups) == 0 {
			v.addf(path, "must name at least one user or group")
		}
		for j, u := range p.Users {
			if !ValidUserName(u) {
				v.addf(fmt.Sprintf("%s.users[%d]", path, j), "%q %s", u, nameRule)
			}
		}
		for j, g := range p.Groups {
			if !ValidUserName(g) {
				v.addf(fmt.Sprintf("%s.groups[%d]", path, j), "%q %s", g, nameRule)
			}
		}
	}

	if d := c.Backup.Directory; d != "" {
		switch {
		case !filepath.IsAbs(d):
			v.addf("backup.directory", "%q must be an absolute path", d)
		case c.DataDir != "" && (within(d, c.DataDir) || within(c.DataDir, d)):
			v.addf("backup.directory", "%q must be outside the data directory, and must not contain it", d)
		}
	}

	if b := c.Auth.BootstrapAdmin; b != nil {
		if !ValidUserName(b.Username) {
			v.addf("auth.bootstrapAdmin.username", "%q %s", b.Username, nameRule)
		}
		if b.PasswordFile == "" {
			v.addf("auth.bootstrapAdmin.passwordFile", "is required when auth.bootstrapAdmin is set")
		}
	}
	switch d := c.Auth.LoginTokenTTL; {
	case d.invalid != "":
		v.addf("auth.loginTokenTTL", "%s", d.invalid)
	case d.Duration <= 0:
		v.addf("auth.loginTokenTTL", "must be positive")
	}
	return v.err()
}

// within reports whether path is dir or inside it.
func within(path, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// validateProxy checks a proxy repository's upstream settings.
func validateProxy(v *validator, path, format string, p *Proxy) {
	if p.URL == "" {
		v.addf(path+".url", "is required")
	} else if err := checkUpstreamURL(p.URL, format); err != nil {
		v.addf(path+".url", "%q %v", p.URL, err)
	}
	switch {
	case p.Username != "" && p.PasswordFile == "":
		v.addf(path+".passwordFile", "is required with username")
	case p.Username == "" && p.PasswordFile != "":
		v.addf(path+".username", "is required with passwordFile")
	case strings.ContainsAny(p.Username, ":\r\n"):
		v.addf(path+".username", "must not contain \":\" or line breaks")
	}
	if p.PasswordFile != "" && !filepath.IsAbs(p.PasswordFile) {
		v.addf(path+".passwordFile", "%q must be an absolute path", p.PasswordFile)
	}
	switch d := p.RevalidateAfter; {
	case d.invalid != "":
		v.addf(path+".revalidateAfter", "%s", d.invalid)
	case d.Duration <= 0:
		v.addf(path+".revalidateAfter", "must be positive")
	}
	if s := p.SizeLimit; s.invalid != "" {
		v.addf(path+".sizeLimit", "%s", s.invalid)
	} else if s.set && s.Bytes <= 0 {
		v.addf(path+".sizeLimit", "must be positive")
	}
	if p.MaxConcurrent < 0 {
		v.addf(path+".maxConcurrent", "must be positive")
	}
	for i, h := range p.AllowHosts {
		if _, err := hostpattern.Parse(h); err != nil {
			v.addf(fmt.Sprintf("%s.allowHosts[%d]", path, i), "%v", err)
		}
	}
}

// checkUpstreamURL checks an upstream's URL: a registry's base URL for
// OCI, or a URL that may have a path: a simple index URL for PyPI, a base
// URL for generic files, a sparse index URL, which may also have the
// "sparse+" prefix, for Cargo, and a repository's base URL for Maven.
func checkUpstreamURL(s, format string) error {
	if format == FormatCargo {
		s = strings.TrimPrefix(s, "sparse+")
	}
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return errors.New("is not a URL")
	case u.Scheme != "https" && u.Scheme != "http":
		return errors.New("must be an http or https URL")
	case u.Host == "":
		return errors.New("has no host")
	case u.User != nil:
		return errors.New("must not contain credentials; use username and passwordFile")
	case u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return errors.New("must not have a query or fragment")
	case format == FormatOCI && u.Path != "" && u.Path != "/":
		return errors.New("must be the registry's base URL, without a path: the registry API is served at /v2/")
	}
	return nil
}

// checkPublicURL checks the public URL: an absolute http or https URL,
// optionally with a path that flint is served under.
func checkPublicURL(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return errors.New("is not a URL")
	case u.Scheme != "https" && u.Scheme != "http":
		return errors.New("must be an http or https URL")
	case u.Host == "":
		return errors.New("has no host")
	case u.User != nil:
		return errors.New("must not contain credentials")
	case u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return errors.New("must not have a query or fragment")
	}
	return nil
}

// PublicBase returns the public URL without a trailing "/", to which a
// path starting with "/" is appended, or "" if it is not set.
func (c *Config) PublicBase() string {
	return strings.TrimRight(c.PublicURL, "/")
}

// PyPIIndexURL returns the simple index URL of a PyPI proxy repository's
// upstream: its URL, ending in "/", with "/simple/" when it has no path.
func PyPIIndexURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/simple/"
	} else if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawPath = ""
	return u.String()
}

// CargoIndexURL returns the sparse index URL of a Cargo proxy
// repository's upstream: its URL without the "sparse+" prefix, ending in
// "/".
func CargoIndexURL(s string) string {
	s = strings.TrimPrefix(s, "sparse+")
	if !strings.HasSuffix(s, "/") {
		s += "/"
	}
	return s
}

// Proxies returns the parsed trusted-proxy prefixes. The configuration
// must be valid.
func (c *Config) Proxies() []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(c.TrustedProxies))
	for _, s := range c.TrustedProxies {
		if p, err := ParseProxy(s); err == nil {
			ps = append(ps, p)
		}
	}
	return ps
}

// ParseProxy parses a trusted-proxy entry: an IP address, which means
// that single address, or a CIDR prefix. IPv4-mapped IPv6 forms are
// treated as IPv4.
func ParseProxy(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR prefix", s)
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q has a zone, which a prefix cannot match", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR prefix", s)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// validRepoName reports whether s is a repository name: 1 to 64 characters
// of [a-z0-9] runs joined by single ".", "_", or "-" separators. A name is
// one path component, so it cannot contain "/".
func validRepoName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	sep := true // at the start, a separator is not allowed
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
			sep = false
		case c == '.' || c == '_' || c == '-':
			if sep {
				return false
			}
			sep = true
		default:
			return false
		}
	}
	return !sep
}

// ValidRepoPattern reports whether s is a repository name in which any
// characters may be replaced by "*", as permission grants use.
func ValidRepoPattern(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '*') {
			return false
		}
	}
	return true
}

// nameRule describes the user and group name syntax in errors.
const nameRule = "is not a valid name: use 1 to 64 lowercase letters, digits, \".\", \"_\", \"-\", or \"@\", starting with a letter or digit"

// ValidUserName reports whether s is a valid user or group name: 1 to 64
// lowercase letters, digits, ".", "_", "-", or "@", starting with a letter
// or digit. The rule keeps names unambiguous in HTTP basic credentials,
// which split at ":", and keeps the reserved "__token__" out.
func ValidUserName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || c != '.' && c != '_' && c != '-' && c != '@') {
			return false
		}
	}
	return true
}

// validHostname reports whether s looks like a DNS hostname.
func validHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// validator collects validation problems.
type validator struct{ errs []error }

func (v *validator) addf(path, format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, args...)))
}

func (v *validator) err() error { return errors.Join(v.errs...) }
