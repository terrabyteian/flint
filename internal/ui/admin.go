package ui

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/terrabyteian/flint/internal/backup"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/gc"
)

// The administrators' status page shows, read-only, what the
// configuration declares and how the background work went. Changing any
// of it is done through the admin API and the configuration file.

type adminRepo struct {
	RepoRow
	Settings []string
}

type grantRow struct {
	Repositories, Role, Users, Groups string
}

type adminData struct {
	GC        *gc.Status
	Backup    *backup.Status
	HasBackup bool
	// HasSpace reports whether the free space is watched, which it is
	// while there are proxy repositories.
	HasSpace bool
	Free     int64
	Pressure bool
	Repos    []adminRepo
	Grants   []grantRow
	Auth     []string
}

func (adminData) nav() string { return navAdmin }

func (h *Handler) admin(rq *request) {
	if !rq.signedIn() {
		rq.denied()
		return
	}
	if !rq.p.Admin {
		rq.notFound()
		return
	}
	cfg := h.opts.Config
	st := h.opts.Status
	d := adminData{}
	if st.GC != nil {
		s := st.GC()
		d.GC = &s
	}
	if st.Backup != nil {
		if s, ok := st.Backup(); ok {
			d.Backup, d.HasBackup = &s, true
		}
	}
	if st.Space != nil {
		d.HasSpace, d.Free, d.Pressure = true, int64(min(st.Space.Free(), 1<<62)), st.Space.Pressure()
	}
	for i := range h.repos {
		rc := &h.repos[i]
		d.Repos = append(d.Repos, adminRepo{RepoRow: h.row(rc), Settings: settingsOf(rc)})
	}
	for _, p := range cfg.Auth.Permissions {
		d.Grants = append(d.Grants, grantRow{Repositories: strings.Join(p.Repositories, ", "), Role: p.Role,
			Users: strings.Join(p.Users, ", "), Groups: strings.Join(p.Groups, ", ")})
	}
	d.Auth = []string{
		"Web sessions last " + cfg.Auth.SessionTTL.Duration.String() + ".",
		"Tokens minted by package clients' login commands last " + cfg.Auth.LoginTokenTTL.Duration.String() + ".",
	}
	if b := cfg.Auth.BootstrapAdmin; b != nil {
		d.Auth = append(d.Auth, "The bootstrap administrator is "+b.Username+".")
	}
	rq.render(http.StatusOK, "admin", "Status", d)
}

// settingsOf describes a repository's notable settings.
func settingsOf(rc *config.Repository) []string {
	var s []string
	if rc.AnonymousPull {
		s = append(s, "anonymous pull")
	}
	if rc.ImmutableTags {
		s = append(s, "immutable tags")
	}
	if rc.HelmIndex {
		s = append(s, "Helm repository view")
	}
	if p := rc.Proxy; p != nil {
		s = append(s, "revalidate after "+p.RevalidateAfter.Duration.String())
		if p.SizeLimit.Bytes > 0 {
			s = append(s, "size limit "+formatSize(p.SizeLimit.Bytes))
		}
		if p.Username != "" || p.PasswordFile != "" {
			s = append(s, "upstream credentials")
		}
	}
	if v := rc.Virtual; v != nil {
		if v.PublishTo != "" {
			s = append(s, "publishes to "+v.PublishTo)
		}
		if !v.Protected() {
			s = append(s, "dependency-confusion protection off")
		}
	}
	if g := rc.Generic; g != nil {
		if g.AllowOverwrite {
			s = append(s, "overwrite allowed")
		}
		if g.Immutable {
			s = append(s, "immutable")
		}
	}
	if m := rc.Maven; m != nil && m.VersionPolicy != "" {
		s = append(s, fmt.Sprintf("version policy %s", m.VersionPolicy))
	}
	return s
}
