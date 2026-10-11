package pypi

import (
	"context"
	"errors"
	"net/http"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/repo"
)

// A virtual repository serves one index merged from its members, in
// order, by the rules of repo.Virtual: a project page lists the files of
// every member that may serve the project (see repo.Virtual.Sources), and
// where members have a file of the same name, the first member's is
// served. With dependency-confusion protection, once a hosted member owns
// a project name, the proxy members are not even asked about it. A member
// that fails is skipped (see repo.Consult), so one unreachable upstream
// does not take the merged index down; the request fails only if no
// member could answer.

// virtualSources returns the members of rp that may serve project.
func (h *Handler) virtualSources(rp *repository, project string) []repo.Member {
	v := h.view()
	defer v.Release()
	return rp.virtual.Sources(project, func(m string) bool { return owns(v, m, project) })
}

// memberPage is a member's project page and how it was served.
type memberPage struct {
	doc    *projectDoc
	result string
}

// virtualProject returns the merged project page of virtual repository rp.
func (h *Handler) virtualProject(ctx context.Context, actor string, rp *repository, project string) (*projectDoc, error) {
	pages, err := repo.Consult(ctx, rp.virtual, h.virtualSources(rp, project), project,
		func(ctx context.Context, m repo.Member) (memberPage, error) {
			doc, result, err := h.projectOf(ctx, actor, h.repos[m.Name], project)
			return memberPage{doc, result}, err
		},
		func(err error) bool {
			var he *httpError
			return errors.As(err, &he) && he.status == http.StatusNotFound
		})
	if err != nil {
		return nil, err
	}
	if len(pages) == 0 {
		return nil, notFound(project)
	}
	merged := &projectDoc{Format: pageFormat, Name: project}
	files := make([][]*file, len(pages))
	for i, p := range pages {
		if mr := h.repos[p.Member.Name]; mr.typ == config.TypeProxy {
			h.pm.Requests.With(mr.name, p.Value.result).Inc()
		}
		files[i] = p.Value.doc.Files
		merged.Versions = append(merged.Versions, p.Value.doc.Versions...)
	}
	merged.Files = repo.Merge(files, func(f *file) string { return f.Filename })
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
