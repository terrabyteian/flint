package gomod

import (
	"context"
	"net/http"
	"strings"

	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A virtual repository serves one module proxy merged from its members,
// in order, by the rules of repo.Virtual, comparing module paths
// exactly:
//
//   - A module's version list is the union of the lists of the members
//     whose filters admit the module.
//   - A version's .info, .mod, and .zip come from the first of those
//     members that has the version, which is the first whose .info of
//     the version answers; .info files of canonical versions are cached
//     forever, so after the first request this asks no upstream.
//   - @latest, and the answer to any other query, come from the first
//     member that answers.
//   - The checksum database is served through the first member that
//     proxies the database the request names, whatever its filters.
//
// A member that fails, such as a proxy whose upstream cannot be reached
// with nothing cached, is skipped (see repo.Consult), so one unreachable
// upstream does not take the virtual repository down. Go has no hosted
// repositories yet, so no member owns a module path.

// owns reports that no member owns a module path: they are all proxies.
func owns(string) bool { return false }

// serveVirtual serves a request of virtual repository rp.
func (h *Handler) serveVirtual(w http.ResponseWriter, r *http.Request, rp *repository, req *request) {
	v := rp.virtual
	if req.kind == kindSumDB {
		for _, m := range v.Members {
			if p := h.repos[m.Name].proxy; p.verifier.Name() == req.db {
				h.serveSumDB(w, r, p, req)
				return
			}
		}
		writeError(w, http.StatusNotFound, "no member of %s proxies the checksum database %s", rp.name, abbrev(req.db))
		return
	}
	ctx := r.Context()
	actor := h.actor(r)
	members := v.Sources(req.mod, owns)
	switch {
	case req.kind == kindList:
		lists, err := repo.Consult(ctx, v, members, req.mod, func(ctx context.Context, m repo.Member) ([]string, error) {
			b, err := h.memberDoc(ctx, m, req, actor, maxList)
			if err != nil {
				return nil, err
			}
			return strings.SplitAfter(string(b), "\n"), nil
		}, notFound)
		switch {
		case err != nil:
			h.failVirtual(w, rp, req, err)
		case len(lists) == 0:
			h.notFoundVirtual(w, rp, req)
		default:
			ls := make([][]string, len(lists))
			for i, l := range lists {
				ls[i] = l.Value
			}
			var b strings.Builder
			for _, line := range repo.Merge(ls, listVersion) {
				if listVersion(line) == "" {
					continue
				}
				b.WriteString(strings.TrimSuffix(line, "\n") + "\n")
			}
			serveBytes(w, r, ctText, []byte(b.String()))
		}
	case req.kind == kindLatest || req.kind == kindInfo && !canonical(req.ver):
		a, ok, err := repo.First(ctx, v, members, req.mod, func(ctx context.Context, m repo.Member) ([]byte, error) {
			return h.memberDoc(ctx, m, req, actor, maxInfo)
		}, notFound)
		switch {
		case err != nil:
			h.failVirtual(w, rp, req, err)
		case !ok:
			h.notFoundVirtual(w, rp, req)
		default:
			serveBytes(w, r, ctJSON, a.Value)
		}
	default:
		// A version's files come from the first member that has its
		// .info.
		info := *req
		info.kind = kindInfo
		a, ok, err := repo.First(ctx, v, members, req.mod, func(ctx context.Context, m repo.Member) (memberInfo, error) {
			p := h.repos[m.Name].proxy
			b, result, err := h.paths.Read(ctx, p.path, h.route(p, &info, actor), actor, maxInfo)
			return memberInfo{b, result}, err
		}, notFound)
		switch {
		case err != nil:
			h.failVirtual(w, rp, req, err)
		case !ok:
			h.notFoundVirtual(w, rp, req)
		case req.kind == kindInfo:
			h.pm.Requests.With(a.Member.Name, a.Value.result).Inc()
			serveBytes(w, r, ctJSON, a.Value.b)
		default:
			p := h.repos[a.Member.Name].proxy
			h.paths.Serve(w, r, p.path, h.route(p, req, actor), actor)
		}
	}
}

// memberInfo is a member's .info of a version, and how it was found.
type memberInfo struct {
	b      []byte
	result string
}

// memberDoc returns member m's document of req, a version list or a
// query's answer, at most max bytes.
func (h *Handler) memberDoc(ctx context.Context, m repo.Member, req *request, actor string, max int64) ([]byte, error) {
	p := h.repos[m.Name].proxy
	d, err := h.paths.Doc(ctx, p.path, h.route(p, req, actor), actor)
	if err != nil {
		return nil, err
	}
	return h.readDoc(ctx, d, max)
}

// listVersion returns the version a line of a version list names: its
// first field, as the go command reads it.
func listVersion(line string) string {
	f, _, _ := strings.Cut(strings.TrimSpace(line), " ")
	return f
}

// notFoundVirtual answers that no member of rp has what req names.
func (h *Handler) notFoundVirtual(w http.ResponseWriter, rp *repository, req *request) {
	what := req.mod
	if req.ver != "" {
		what += "@" + req.ver
	}
	writeError(w, http.StatusNotFound, "%s is not found in any member of %s", what, rp.name)
}

// failVirtual answers that every member of rp that could have what req
// names failed, err being the first failure.
func (h *Handler) failVirtual(w http.ResponseWriter, rp *repository, req *request, err error) {
	status, _ := upstream.StatusOf(err, "")
	if status == http.StatusNotFound {
		status = http.StatusBadGateway
	}
	writeError(w, status, "no member of %s could answer for %s: %v", rp.name, req.mod, err)
}
