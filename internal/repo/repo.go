// Package repo is flint's repository model: what repository types mean
// whatever the package format, and the rules that span repositories, such
// as how a virtual repository chooses among its members. Format packages
// serve the protocols; this package decides which repositories a request
// may draw from.
//
// A hosted repository holds first-party packages that clients publish. A
// proxy repository caches one upstream. A virtual repository serves one
// index merged from an ordered list of hosted and proxy repositories of
// its format, so clients need a single URL; with dependency-confusion
// protection, on by default, a name that a hosted member owns is never
// served from a proxy member, so a package published upstream under the
// same name can never replace or mix with the first-party one.
package repo

import (
	"fmt"

	"github.com/terrabyteian/flint/internal/config"
)

// Member is a member of a virtual repository.
type Member struct {
	// Name is the member repository's name.
	Name string
	// Hosted reports whether the member is a hosted repository; otherwise
	// it is a proxy repository.
	Hosted bool
}

// Virtual is a virtual repository.
type Virtual struct {
	// Name is the virtual repository's name.
	Name string
	// Members are the member repositories, in order of precedence.
	Members []Member
	// Protect turns on dependency-confusion protection.
	Protect bool
}

// NewVirtual returns the virtual repository rc declares, with the types of
// its members looked up in all, the configured repositories. The
// configuration must be valid.
func NewVirtual(rc config.Repository, all []config.Repository) (*Virtual, error) {
	if rc.Type != config.TypeVirtual || rc.Virtual == nil {
		return nil, fmt.Errorf("repo: %s is not a virtual repository", rc.Name)
	}
	byName := make(map[string]config.Repository, len(all))
	for _, r := range all {
		byName[r.Name] = r
	}
	v := &Virtual{Name: rc.Name, Protect: rc.Virtual.Protected()}
	for _, name := range rc.Virtual.Members {
		m, ok := byName[name]
		switch {
		case !ok:
			return nil, fmt.Errorf("repo: virtual repository %s: member %s is not declared", rc.Name, name)
		case m.Format != rc.Format || (m.Type != config.TypeHosted && m.Type != config.TypeProxy):
			return nil, fmt.Errorf("repo: virtual repository %s: member %s is not a hosted or proxy %s repository", rc.Name, name, rc.Format)
		}
		v.Members = append(v.Members, Member{Name: name, Hosted: m.Type == config.TypeHosted})
	}
	return v, nil
}

// Hosted returns the names of the hosted members, in order.
func (v *Virtual) Hosted() []string {
	var out []string
	for _, m := range v.Members {
		if m.Hosted {
			out = append(out, m.Name)
		}
	}
	return out
}

// Sources returns the members that may serve the package called name, in
// order of precedence. owns reports whether a hosted member owns the
// name, which for PyPI means a file of the project was ever published
// there. Without protection, every member is a source. With it, once a
// hosted member owns the name, the proxy members are left out, so
// upstream versions of the name are never served.
func (v *Virtual) Sources(owns func(hosted string) bool) []Member {
	if !v.Protect {
		return v.Members
	}
	owned := false
	for _, m := range v.Members {
		if m.Hosted && owns(m.Name) {
			owned = true
			break
		}
	}
	if !owned {
		return v.Members
	}
	out := make([]Member, 0, len(v.Members))
	for _, m := range v.Members {
		if m.Hosted {
			out = append(out, m)
		}
	}
	return out
}
