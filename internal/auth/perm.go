package auth

import (
	"strings"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/repo"
)

// Role is a repository role. Roles are ordered, and each includes every
// role below it: read < write < delete < admin.
type Role uint8

// Repository roles. RoleNone grants nothing.
const (
	RoleNone Role = iota
	RoleRead
	RoleWrite
	RoleDelete
	RoleAdmin
)

// ParseRole parses a role name: read, write, delete, or admin.
func ParseRole(s string) (Role, bool) {
	switch s {
	case config.RoleRead:
		return RoleRead, true
	case config.RoleWrite:
		return RoleWrite, true
	case config.RoleDelete:
		return RoleDelete, true
	case config.RoleAdmin:
		return RoleAdmin, true
	}
	return RoleNone, false
}

// String returns the role's name, or "none".
func (r Role) String() string {
	switch r {
	case RoleRead:
		return config.RoleRead
	case RoleWrite:
		return config.RoleWrite
	case RoleDelete:
		return config.RoleDelete
	case RoleAdmin:
		return config.RoleAdmin
	}
	return "none"
}

// Repository actions, as named in Docker token scopes.
const (
	ActionPull   = "pull"
	ActionPush   = "push"
	ActionDelete = "delete"
)

// allActions are the repository actions in the order tokens list them.
var allActions = []string{ActionPull, ActionPush, ActionDelete}

// actionRole returns the role an action needs.
func actionRole(action string) (Role, bool) {
	switch action {
	case ActionPull:
		return RoleRead, true
	case ActionPush:
		return RoleWrite, true
	case ActionDelete:
		return RoleDelete, true
	}
	return RoleNone, false
}

// Scope grants one role on the repositories matching any of its patterns.
// Config grants and API token permissions are both lists of scopes.
type Scope struct {
	Repositories []string
	Role         Role
}

// matches reports whether the scope covers repository name, matching
// patterns as repo.Match does.
func (s Scope) matches(name string) bool {
	for _, p := range s.Repositories {
		if repo.Match(p, name) {
			return true
		}
	}
	return false
}

// scopesRole returns the highest role scopes grant on repo.
func scopesRole(scopes []Scope, repo string) Role {
	r := RoleNone
	for _, s := range scopes {
		if s.Role > r && s.matches(repo) {
			r = s.Role
		}
	}
	return r
}

// repoOf returns the flint repository a repository path names: its first
// path component, as in "docker-local" for "docker-local/team/app".
// Permissions apply to flint repositories.
func repoOf(path string) string {
	repo, _, _ := strings.Cut(path, "/")
	return repo
}

// grant is a configured permission grant.
type grant struct {
	Scope
	users  map[string]bool
	groups map[string]bool
}

// policy is the permission configuration: grants and the repositories
// that allow anonymous pulls.
type policy struct {
	grants    []grant
	anonymous map[string]bool
}

func newPolicy(cfg *config.Config) *policy {
	p := &policy{anonymous: map[string]bool{}}
	if cfg == nil {
		return p
	}
	for _, r := range cfg.Repositories {
		if r.AnonymousPull {
			p.anonymous[r.Name] = true
		}
	}
	for _, cp := range cfg.Auth.Permissions {
		role, _ := ParseRole(cp.Role) // the config is validated
		g := grant{
			Scope:  Scope{Repositories: cp.Repositories, Role: role},
			users:  map[string]bool{},
			groups: map[string]bool{},
		}
		for _, u := range cp.Users {
			g.users[u] = true
		}
		for _, gr := range cp.Groups {
			g.groups[gr] = true
		}
		p.grants = append(p.grants, g)
	}
	return p
}

// role returns the role a principal holds on flint repository repo.
func (p *policy) role(pr *Principal, repo string) Role {
	r := RoleNone
	if p.anonymous[repo] {
		r = RoleRead
	}
	if pr.User == "" {
		return r
	}
	user := RoleNone
	if pr.userAdmin {
		user = RoleAdmin
	} else {
		for _, g := range p.grants {
			if g.Role > user && (g.users[pr.User] || g.anyGroup(pr.Groups)) && g.matches(repo) {
				user = g.Role
			}
		}
	}
	if pr.TokenID != "" {
		// A token carries at most its owner's permissions.
		user = min(user, scopesRole(pr.scopes, repo))
	}
	return max(r, user)
}

func (g grant) anyGroup(groups []string) bool {
	for _, gr := range groups {
		if g.groups[gr] {
			return true
		}
	}
	return false
}
