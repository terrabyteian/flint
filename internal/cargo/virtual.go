package cargo

import (
	"context"
	"net/http"
	"strings"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/repo"
)

// A virtual repository serves one index merged from its members, in
// order, by the rules of repo.Virtual: a crate's index file lists the
// versions of every member that may serve the crate (see
// repo.Virtual.Sources), and where members have the same version, the
// first member's line is served, and its .crate file downloaded from that
// member. With dependency-confusion protection, once a hosted member owns
// a crate name, in any spelling, the proxy members are not even asked
// about it. A member that fails is skipped (see repo.Consult), so one
// unreachable upstream does not take the merged index down.
//
// A hosted crate's dependency on a registry a proxy member caches, such
// as crates.io, is served as a dependency on the virtual repository
// itself, so the whole dependency graph resolves through the virtual
// repository even without source replacement.

// virtualSources returns the members of rp that may serve crate.
func (h *Handler) virtualSources(rp *repository, crate string) []repo.Member {
	v := h.meta.View()
	defer v.Release()
	norm := Normalize(crate)
	return rp.virtual.Sources(crate, func(m string) bool { return owns(v, m, norm) })
}

// virtualIndex returns the lines of virtual repository rp's merged index
// file for crate, a lowercase name.
func (h *Handler) virtualIndex(ctx context.Context, actor string, rp *repository, crate string) ([]*entry, error) {
	answers, err := repo.Consult(ctx, rp.virtual, h.virtualSources(rp, crate), crate,
		func(ctx context.Context, m repo.Member) ([]*entry, error) {
			mr := h.repos[m.Name]
			if mr.typ == config.TypeHosted {
				v := h.meta.View()
				defer v.Release()
				es, _, err := hostedIndex(v, mr, crate)
				return es, err
			}
			es, d, err := h.proxyIndex(ctx, actor, mr, crate)
			if err == nil {
				h.pm.Requests.With(mr.name, d.Result).Inc()
			}
			return es, err
		}, isNotFound)
	if err != nil {
		return nil, err
	}
	if len(answers) == 0 {
		return nil, notFound(crate)
	}
	lists := make([][]*entry, len(answers))
	for i, a := range answers {
		lists[i] = a.Value
	}
	merged := repo.Merge(lists, func(e *entry) string { return e.key })
	if len(rp.local) == 0 {
		return merged, nil
	}
	for i, e := range merged {
		if e.rec == nil {
			continue
		}
		l, err := decodeLine(e.raw)
		if err != nil {
			return nil, err
		}
		if l.localize(rp.local) {
			c := *e
			c.raw = l.encode()
			merged[i] = &c
		}
	}
	return merged, nil
}

// virtualVersion returns the index line of the version that virtual
// repository rp serves for crate: the one its merged index file lists.
func (h *Handler) virtualVersion(r *http.Request, rp *repository, crate, vers string) (*entry, error) {
	es, err := h.virtualIndex(r.Context(), h.actor(r), rp, strings.ToLower(crate))
	if err != nil {
		return nil, err
	}
	e := findVersion(es, vers)
	if e == nil {
		return nil, errorf(http.StatusNotFound, "crate %s has no version %s", crate, vers)
	}
	return e, nil
}
