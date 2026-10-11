package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// formatSpec describes a package format the configuration accepts. A
// format is added here when flint serves it, so a repository the server
// would not serve is never valid configuration.
type formatSpec struct {
	// name is the format's value in a repository's "format", and the
	// name of its settings object.
	name string
	// types are the repository types the format supports.
	types []string
	// settings, for a format with a settings object, returns repository
	// r's settings object, or nil if r has none. The object is a field of
	// Repository named after the format, such as
	// `json:"maven,omitempty"`, so it is decoded as strictly as the rest
	// of the file.
	settings func(r *Repository) any
	// check, if set, validates the settings of a repository of this
	// format, whose JSON path is path; r's settings object may be absent.
	check func(v *validator, path string, r *Repository)
}

// formats are the formats the configuration accepts.
var formats = []formatSpec{
	{name: FormatOCI, types: []string{TypeHosted, TypeProxy}},
	{name: FormatPyPI, types: []string{TypeHosted, TypeProxy, TypeVirtual}},
	{name: FormatGeneric, types: []string{TypeHosted, TypeProxy, TypeVirtual},
		settings: func(r *Repository) any {
			if r.Generic == nil {
				return nil
			}
			return r.Generic
		},
		check: checkGeneric},
}

// Generic holds the settings of a generic files repository.
type Generic struct {
	// AllowOverwrite lets a client with write replace a file, and one
	// with delete remove it without leaving a tombstone, such as for a
	// scratch area or a "latest build" directory. Without it, files are
	// immutable: an upload of different content to a file's path is
	// refused, and a deleted file's path can never be used again. Hosted
	// repositories only.
	AllowOverwrite bool `json:"allowOverwrite,omitempty"`
	// Immutable caches files fetched from the upstream forever, never
	// revalidating them, as suits release download sites whose files
	// never change. Without it, a cached file is checked upstream again
	// after the repository's revalidateAfter. Proxy repositories only.
	Immutable bool `json:"immutable,omitempty"`
}

// checkGeneric checks a generic files repository's settings, at path.
func checkGeneric(v *validator, path string, r *Repository) {
	if g := r.Generic; g != nil {
		if g.AllowOverwrite && r.Type != TypeHosted {
			v.addf(path+".allowOverwrite", "is only allowed for a hosted repository")
		}
		if g.Immutable && r.Type != TypeProxy {
			v.addf(path+".immutable", "is only allowed for a proxy repository")
		}
	}
	// Only files cached forever count against a size limit; a file that
	// is revalidated is a document of the proxy cache, which does not.
	if p := r.Proxy; r.Type == TypeProxy && p != nil && (p.SizeLimit.set || p.SizeLimit.Bytes != 0) && (r.Generic == nil || !r.Generic.Immutable) {
		base, _ := strings.CutSuffix(path, "."+FormatGeneric)
		v.addf(base+".proxy.sizeLimit", "needs generic.immutable: only files cached forever count against a size limit")
	}
}

// Formats returns the names of the package formats the configuration
// accepts.
func Formats() []string {
	out := make([]string, len(formats))
	for i, f := range formats {
		out[i] = f.name
	}
	return out
}

// formatOf returns the format called name, or nil.
func formatOf(name string) *formatSpec {
	for i := range formats {
		if formats[i].name == name {
			return &formats[i]
		}
	}
	return nil
}

// validateFormat checks a repository's format, whether its format
// supports its type, and the settings objects it has: only its own
// format's is allowed.
func validateFormat(v *validator, path string, r *Repository) {
	f := formatOf(r.Format)
	switch {
	case r.Format == "":
		v.addf(path+".format", "is required")
	case f == nil:
		v.addf(path+".format", "%q is not supported; supported formats: %s", r.Format, strings.Join(Formats(), ", "))
	case validType(r.Type) && !slices.Contains(f.types, r.Type):
		v.addf(path+".type", "%q is not supported for format %s; supported types: %s", r.Type, r.Format, strings.Join(f.types, ", "))
	}
	for _, o := range formats {
		if o.settings == nil || o.settings(r) == nil || o.name == r.Format {
			continue
		}
		v.addf(path+"."+o.name, "is only allowed for a repository of format %s", o.name)
	}
	if f != nil && f.check != nil {
		f.check(v, path+"."+f.name, r)
	}
}

// validType reports whether t is a repository type of any format.
func validType(t string) bool {
	return t == TypeHosted || t == TypeProxy || t == TypeVirtual
}

// Virtual configures a virtual repository: one view merged from an
// ordered list of hosted and proxy repositories of the same format.
type Virtual struct {
	// Members are the repositories merged, in order: where several have
	// the same version or file of a package, the first one's is served.
	Members []VirtualMember `json:"members"`
	// PublishTo, if set, names the hosted member that receives what
	// clients publish to the virtual repository, so one URL serves both
	// installing and publishing. Without it, the virtual repository
	// refuses publishes.
	PublishTo string `json:"publishTo,omitempty"`
	// DependencyConfusionProtection, on by default, never serves a
	// package from a proxy member once a hosted member owns its name.
	DependencyConfusionProtection *bool `json:"dependencyConfusionProtection,omitempty"`
}

// Protected reports whether dependency-confusion protection is on.
func (v *Virtual) Protected() bool {
	return v.DependencyConfusionProtection == nil || *v.DependencyConfusionProtection
}

// VirtualMember is a member of a virtual repository. In JSON it is the
// member's name, or an object with the name and filters.
type VirtualMember struct {
	// Name is the member repository's name.
	Name string `json:"name"`
	// Include, if set, are the package names the member is consulted for:
	// names, or patterns in which "*" matches any run of characters, such
	// as "acme-*". Without it, every name is included.
	Include []string `json:"include,omitempty"`
	// Exclude are package names or patterns the member is never
	// consulted for, even if Include matches them.
	Exclude []string `json:"exclude,omitempty"`
	// invalid describes a JSON value that is not a member. Decoding
	// records it rather than failing, so Validate can report it with the
	// member's path.
	invalid string
}

// Members returns members named names, without filters.
func Members(names ...string) []VirtualMember {
	out := make([]VirtualMember, len(names))
	for i, n := range names {
		out[i] = VirtualMember{Name: n}
	}
	return out
}

// UnmarshalJSON decodes a member's name, or an object with its name and
// filters, strictly.
func (m *VirtualMember) UnmarshalJSON(b []byte) error {
	*m = VirtualMember{}
	b = bytes.TrimSpace(b)
	switch {
	case len(b) > 0 && b[0] == '"':
		if err := json.Unmarshal(b, &m.Name); err != nil {
			m.invalid = "is not a valid JSON string"
		}
		return nil
	case len(b) == 0 || b[0] != '{':
		m.invalid = fmt.Sprintf("want a repository name or an object with a name and filters, got %s", b)
		return nil
	}
	type plain VirtualMember // without this method
	var p plain
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		var typ *json.UnmarshalTypeError
		switch {
		case errors.As(err, &typ) && typ.Field != "":
			m.invalid = fmt.Sprintf("%s: want %s, got %s", fieldPath(typ.Field), jsonType(typ.Type.Kind().String()), typ.Value)
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			m.invalid = "unknown field " + strings.TrimPrefix(err.Error(), "json: unknown field ")
		default:
			m.invalid = err.Error()
		}
		return nil
	}
	*m = VirtualMember(p)
	return nil
}

// MarshalJSON writes a member without filters as its name.
func (m VirtualMember) MarshalJSON() ([]byte, error) {
	if len(m.Include) == 0 && len(m.Exclude) == 0 {
		return json.Marshal(m.Name)
	}
	type plain VirtualMember
	return json.Marshal(plain(m))
}

// maxNamePattern bounds a member filter's length.
const maxNamePattern = 256

// ValidNamePattern reports whether s is a package name filter of a
// virtual repository's member: 1 to 256 printable ASCII characters other
// than space, in which "*" matches any run of characters. Package names
// differ by format (npm scopes, Maven coordinates, Go module paths), so
// the syntax admits all of them; each format compares names after its own
// normalization.
func ValidNamePattern(s string) bool {
	if s == "" || len(s) > maxNamePattern {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// validateVirtual checks a virtual repository's members, their filters,
// and publishTo: each member must be a hosted or proxy repository of the
// same format, named once, and publishTo one of the hosted members.
func (c *Config) validateVirtual(v *validator, path string, r Repository, names map[string]int) {
	mpath := path + ".members"
	if len(r.Virtual.Members) == 0 {
		v.addf(mpath, "must name at least one hosted or proxy repository")
	}
	seen := map[string]bool{}
	for j, m := range r.Virtual.Members {
		mp := fmt.Sprintf("%s[%d]", mpath, j)
		if m.invalid != "" {
			v.addf(mp, "%s", m.invalid)
			continue
		}
		i, ok := names[m.Name]
		switch {
		case m.Name == "":
			v.addf(mp+".name", "is required")
		case seen[m.Name]:
			v.addf(mp, "%q is named twice", m.Name)
		case m.Name == r.Name:
			v.addf(mp, "a virtual repository cannot be its own member")
		case !ok:
			v.addf(mp, "%q is not a declared repository", m.Name)
		case c.Repositories[i].Format != r.Format:
			v.addf(mp, "%q is a %s repository, not %s", m.Name, c.Repositories[i].Format, r.Format)
		case c.Repositories[i].Type != TypeHosted && c.Repositories[i].Type != TypeProxy:
			v.addf(mp, "%q is a %s repository; members must be hosted or proxy repositories", m.Name, c.Repositories[i].Type)
		}
		seen[m.Name] = true
		for _, f := range []struct {
			field string
			pats  []string
		}{{"include", m.Include}, {"exclude", m.Exclude}} {
			for k, p := range f.pats {
				if !ValidNamePattern(p) {
					v.addf(fmt.Sprintf("%s.%s[%d]", mp, f.field, k),
						"%q is not a package name or pattern: use 1 to %d printable characters other than space, with \"*\" matching any run of characters",
						p, maxNamePattern)
				}
			}
		}
	}
	if p := r.Virtual.PublishTo; p != "" {
		i, declared := names[p]
		member := slices.ContainsFunc(r.Virtual.Members, func(m VirtualMember) bool { return m.Name == p })
		switch {
		case !member:
			v.addf(path+".publishTo", "%q is not a member of the virtual repository", p)
		case declared && c.Repositories[i].Type != TypeHosted:
			v.addf(path+".publishTo", "%q is a %s repository; publishTo must name a hosted member", p, c.Repositories[i].Type)
		}
	}
}
