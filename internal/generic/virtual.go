package generic

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
)

// A virtual repository serves each path from the first member that has
// it, consulting the members repo.Virtual.Sources gives for the path:
// those whose filters admit it, and, with dependency-confusion
// protection, only the hosted ones once a hosted one holds the path,
// live or as a tombstone. Paths are compared exactly. A member that
// fails, such as a proxy whose upstream cannot be reached with nothing
// cached, is skipped, logged, and counted, and the next is consulted.

// errNoFile means a member does not have a path.
var errNoFile = errors.New("generic: the member does not have the file")

// memberFailure is a member's failed answer, kept to answer the request
// with if no other member has the file.
type memberFailure struct {
	status int
	header http.Header
	body   []byte
}

func (f *memberFailure) Error() string {
	return fmt.Sprintf("status %d: %s", f.status, bytes.TrimSpace(f.body))
}

// virtualFile serves GET and HEAD of the file at path p of virtual
// repository rp.
func (h *Handler) virtualFile(w http.ResponseWriter, r *http.Request, rp *repository, p string) {
	ctx := r.Context()
	v := rp.virtual
	owns := func(hosted string) bool {
		f, err := h.lookup(hosted, p)
		return err != nil || f != nil // an unreadable record is owned too
	}
	var failure error
	for _, m := range v.Sources(p, owns) {
		ans, err := repo.Consult(ctx, v, []repo.Member{m}, p, func(ctx context.Context, m repo.Member) (bool, error) {
			return true, h.memberFile(w, r, m, p)
		}, func(err error) bool { return errors.Is(err, errNoFile) })
		switch {
		case len(ans) > 0:
			return // served
		case ctx.Err() != nil:
			return
		case err != nil && failure == nil:
			failure = err
		}
	}
	var mf *memberFailure
	switch {
	case errors.As(failure, &mf):
		maps.Copy(w.Header(), mf.header)
		w.WriteHeader(mf.status)
		w.Write(mf.body)
	case failure != nil:
		h.fail(w, r, failure)
	default:
		writeError(w, http.StatusNotFound, "%s is not found", abbrev(p))
	}
}

// memberFile serves the file at path p from member m if it has it, and
// returns errNoFile if it does not, writing nothing, or the member's
// failure, a *memberFailure for a proxy member, also writing nothing.
func (h *Handler) memberFile(w http.ResponseWriter, r *http.Request, m repo.Member, p string) error {
	mr := h.repos[m.Name]
	if mr == nil {
		return errNoFile
	}
	if mr.typ == config.TypeHosted {
		f, err := h.lookup(mr.name, p)
		switch {
		case err != nil:
			return err
		case f == nil || f.Kind != kindFile:
			return errNoFile
		case !h.serveBlob(w, r, mr, f):
			return fmt.Errorf("generic: the blob of %s in %s is missing from the blob store", p, mr.name)
		}
		return nil
	}
	pw := &probe{w: w, h: http.Header{}}
	h.proxyFile(pw, r, mr, p)
	switch {
	case pw.passed:
		return nil
	case pw.status == http.StatusNotFound || pw.status == http.StatusGone:
		return errNoFile
	}
	return &memberFailure{status: pw.status, header: pw.h, body: pw.body.Bytes()}
}

// probe is a ResponseWriter that passes a member's answer through to w,
// unless it says the member does not have the file (404 or 410) or
// failed (5xx); those it keeps, so the next member can be consulted.
type probe struct {
	w      http.ResponseWriter
	h      http.Header
	status int
	passed bool
	body   bytes.Buffer
}

// maxProbeBody bounds the error body a probe keeps.
const maxProbeBody = 4 << 10

func (p *probe) Header() http.Header { return p.h }

func (p *probe) WriteHeader(status int) {
	if p.status != 0 {
		return
	}
	p.status = status
	if status == http.StatusNotFound || status == http.StatusGone || status >= 500 {
		return
	}
	maps.Copy(p.w.Header(), p.h)
	p.w.WriteHeader(status)
	p.passed = true
}

func (p *probe) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.WriteHeader(http.StatusOK)
	}
	if p.passed {
		return p.w.Write(b)
	}
	if n := maxProbeBody - p.body.Len(); n > 0 {
		p.body.Write(b[:min(n, len(b))])
	}
	return len(b), nil
}

// Unwrap lets http.ResponseController reach w.
func (p *probe) Unwrap() http.ResponseWriter { return p.w }

// virtualListing lists directory dir of virtual repository rp: the
// entries of its hosted members, each filtered by the member's filters,
// the first member's entry winning where several have the same name.
// Proxy members' directories are not listed, as for a proxy repository.
func (h *Handler) virtualListing(v meta.View, rp *repository, dir string) ([]entry, error) {
	var lists [][]entry
	for _, m := range rp.virtual.Members {
		if !m.Hosted {
			continue
		}
		l, err := list(v, m.Name, dir, func(p string) bool { return rp.virtual.Admits(m, p) })
		if err != nil {
			return nil, err
		}
		lists = append(lists, l)
	}
	out := repo.Merge(lists, func(e entry) string { return e.Name })
	sortEntries(out)
	if out == nil {
		out = []entry{}
	}
	return out, nil
}

// sortEntries sorts entries by name, as a hosted repository lists them.
func sortEntries(es []entry) {
	slices.SortFunc(es, func(a, b entry) int { return strings.Compare(a.Name, b.Name) })
}
