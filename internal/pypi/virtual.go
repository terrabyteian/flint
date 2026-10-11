package pypi

import (
	"context"
	"errors"
	"net/http"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/repo"
)

// A virtual repository serves one index merged from its members, in
// order: a project page lists the files of every member that may serve
// the project (see repo.Virtual.Sources), and where members have a file
// of the same name, the first member's is served. With
// dependency-confusion protection, once a hosted member owns a project
// name, the proxy members are not even asked about it. A member that
// fails is left out with a warning, so one unreachable upstream does not
// take the merged index down; the request fails only if no member could
// answer.

// virtualSources returns the members of rp that may serve project.
func (h *Handler) virtualSources(rp *repository, project string) []repo.Member {
	v := h.view()
	defer v.Release()
	return rp.virtual.Sources(func(m string) bool { return owns(v, m, project) })
}

// virtualProject returns the merged project page of virtual repository rp.
func (h *Handler) virtualProject(ctx context.Context, actor string, rp *repository, project string) (*projectDoc, error) {
	merged := &projectDoc{Format: pageFormat, Name: project}
	seen := map[string]bool{}
	var failure error
	found := false
	for _, m := range h.virtualSources(rp, project) {
		mr := h.repos[m.Name]
		doc, result, err := h.projectOf(ctx, actor, mr, project)
		var he *httpError
		switch {
		case err == nil:
		case errors.As(err, &he) && he.status == http.StatusNotFound:
			continue
		case ctx.Err() != nil:
			return nil, ctx.Err()
		default:
			if failure == nil {
				failure = err
			}
			h.log.WarnContext(ctx, "a member of a virtual repository failed; serving the other members", "repository", rp.name,
				"member", m.Name, "project", project, "err", err)
			continue
		}
		if mr.typ == config.TypeProxy {
			h.pm.Requests.With(mr.name, result).Inc()
		}
		found = true
		for _, f := range doc.Files {
			if !seen[f.Filename] {
				seen[f.Filename] = true
				merged.Files = append(merged.Files, f)
			}
		}
		merged.Versions = append(merged.Versions, doc.Versions...)
	}
	if !found {
		if failure != nil {
			return nil, failure
		}
		return nil, notFound(project)
	}
	merged.finish()
	return merged, nil
}

// virtualFile returns the entry of the file that virtual repository rp
// serves under filename: the one its merged page lists.
func (h *Handler) virtualFile(r *http.Request, rp *repository, project, filename string) (*file, error) {
	p, err := h.virtualProject(r.Context(), h.actor(r), rp, project)
	if err != nil {
		return nil, err
	}
	f := p.find(filename)
	if f == nil {
		return nil, errorf(http.StatusNotFound, "%s is not a file of project %s", filename, project)
	}
	return f, nil
}
