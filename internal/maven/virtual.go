package maven

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A virtual repository resolves every request by the artifact it belongs
// to, groupId:artifactId, with the rules of internal/repo: members'
// filters match that name, and once a hosted member owns it (a file of it
// was ever deployed there) only hosted members are consulted.
//
//   - Artifact-level maven-metadata.xml merges the versions of the
//     members, and latest and release are computed from the merged list.
//     Group-level plugin entries merge by artifactId, the first member's
//     winning, each admitted by the member's filters as
//     groupId:artifactId.
//   - A file, and a snapshot version's metadata, come from the first
//     member that has the version: a hosted member that lists it, or else
//     the first proxy member that has the file.
//   - A member that fails, such as a proxy whose upstream cannot be
//     reached with nothing cached, is skipped.
//   - Deploys and deletes go to publishTo.

// serveVirtual answers a GET or HEAD request of a virtual repository.
func (h *Handler) serveVirtual(w http.ResponseWriter, r *http.Request, rp *repository, mp *mpath) {
	switch {
	case mp.kind == kindFile:
		h.virtualFile(w, r, rp, mp, mp.c)
	case mp.kind == kindSidecar && mp.target.kind == kindFile:
		h.virtualFile(w, r, rp, mp, mp.target.c)
	case mp.kind == kindMetadata, mp.kind == kindSidecar && mp.target.kind == kindMetadata:
		dir, alg := mp.dir, ""
		if mp.kind == kindSidecar {
			dir, alg = mp.target.dir, mp.alg
		}
		b, err := h.virtualDocument(r.Context(), h.actor(r), rp, dir)
		switch {
		case err != nil:
			h.virtualFail(w, r, err)
		case b == nil:
			writeError(w, http.StatusNotFound, "%s is not found", mp.path)
		case alg != "":
			serveDocumentChecksum(w, r, b, alg)
		default:
			serveDocument(w, r, b)
		}
	default:
		writeError(w, http.StatusNotFound, "%s is not found", mp.path)
	}
}

// errNoVersion means a member does not have a version, or a file of it.
var errNoVersion = errors.New("maven: the member does not have the version")

func memberNotFound(err error) bool {
	return errors.Is(err, errNoVersion) || errors.Is(err, upstream.ErrNotFound)
}

// sources returns the members of virtual repository rp that may serve
// the artifact called ga.
func (h *Handler) sources(rp *repository, ga string) []repo.Member {
	v := h.meta.View()
	defer v.Release()
	return rp.virtual.Sources(ga, func(hosted string) bool { return owns(v, hosted, ga) })
}

// virtualFile answers a request for a file, or a file's checksum
// sidecar, of artifact coordinates c, from the first member that has its
// version.
func (h *Handler) virtualFile(w http.ResponseWriter, r *http.Request, rp *repository, mp *mpath, c *coords) {
	ctx := r.Context()
	var failure error
	for _, m := range h.sources(rp, c.name()) {
		member := h.repos[m.Name]
		answers, err := repo.Consult(ctx, rp.virtual, []repo.Member{m}, c.name(), func(ctx context.Context, m repo.Member) (bool, error) {
			if m.Hosted {
				v := h.meta.View()
				vr, err := hostedVersion(v, m.Name, c.Group, c.Artifact, c.Version)
				v.Release()
				switch {
				case err != nil:
					return false, err
				case vr == nil || vr.Files == 0:
					return false, errNoVersion
				}
				// The hosted member lists the version, so it alone serves
				// its files.
				h.serveHosted(w, r, member, mp)
				return true, nil
			}
			tw := &tryWriter{w: w, header: http.Header{}}
			h.serveProxy(tw, r, member, mp)
			return tw.result()
		}, memberNotFound)
		switch {
		case len(answers) > 0:
			return
		case ctx.Err() != nil:
			return
		case err != nil && failure == nil:
			failure = err
		}
	}
	if failure != nil {
		h.virtualFail(w, r, failure)
		return
	}
	writeError(w, http.StatusNotFound, "%s is not found", mp.path)
}

// virtualFail answers a request that every member failed.
func (h *Handler) virtualFail(w http.ResponseWriter, r *http.Request, err error) {
	var me *memberError
	if errors.As(err, &me) {
		for k, v := range me.header {
			w.Header()[k] = v
		}
		writeError(w, me.status, "%s", me.msg)
		return
	}
	var he *httpError
	if errors.As(err, &he) || !isUpstream(err) {
		h.fail(w, r, err)
		return
	}
	status, msg := upstream.StatusOf(err, "of a member")
	writeError(w, status, "%s", msg)
}

// isUpstream reports whether err is an upstream failure.
func isUpstream(err error) bool {
	var ue *upstream.Error
	return errors.As(err, &ue) || errors.Is(err, upstream.ErrUnavailable) || errors.Is(err, upstream.ErrNoSpace)
}

// memberError is a member's failed response, which a tryWriter held
// back.
type memberError struct {
	status int
	msg    string
	header http.Header
}

func (e *memberError) Error() string { return e.msg }

// tryWriter passes a member's response through if it succeeds, and holds
// it back if it fails, so the next member can answer.
type tryWriter struct {
	w         http.ResponseWriter
	header    http.Header
	status    int
	committed bool
	body      bytes.Buffer // a failed response's body, up to maxErrorBody
}

// maxErrorBody bounds the body of a failed response a tryWriter keeps.
const maxErrorBody = 4 << 10

func (t *tryWriter) Header() http.Header {
	if t.committed {
		return t.w.Header()
	}
	return t.header
}

func (t *tryWriter) WriteHeader(status int) {
	if t.status != 0 {
		return
	}
	t.status = status
	if status < http.StatusBadRequest {
		for k, v := range t.header {
			t.w.Header()[k] = v
		}
		t.w.WriteHeader(status)
		t.committed = true
	}
}

func (t *tryWriter) Write(b []byte) (int, error) {
	if t.status == 0 {
		t.WriteHeader(http.StatusOK)
	}
	if t.committed {
		return t.w.Write(b)
	}
	if room := maxErrorBody - t.body.Len(); room > 0 {
		t.body.Write(b[:min(len(b), room)])
	}
	return len(b), nil
}

// ReadFrom keeps the response writer's own ReadFrom, which can send a
// file with sendfile, once the response is passed through.
func (t *tryWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := t.w.(io.ReaderFrom); ok && t.committed {
		return rf.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{t}, r)
}

// Unwrap returns the response writer, for http.ResponseController.
func (t *tryWriter) Unwrap() http.ResponseWriter { return t.w }

// result reports how the member answered: true if its response was
// passed through, errNoVersion if it answered not found, and its failure
// otherwise.
func (t *tryWriter) result() (bool, error) {
	switch {
	case t.committed:
		return true, nil
	case t.status == http.StatusNotFound || t.status == http.StatusGone:
		return false, errNoVersion
	case t.status == 0:
		// Nothing was written: the client went away.
		return false, context.Canceled
	}
	hd := http.Header{}
	if v := t.header.Get("Retry-After"); v != "" {
		hd.Set("Retry-After", v)
	}
	return false, &memberError{status: t.status, msg: strings.TrimSpace(t.body.String()), header: hd}
}

// contribution is what a member contributes to a merged document.
type contribution struct {
	versions []versionEntry
	updated  time.Time
	plugins  []plugin
}

// virtualDocument returns the maven-metadata.xml of directory dir of
// virtual repository rp, or nil if no member has one.
func (h *Handler) virtualDocument(ctx context.Context, actor string, rp *repository, dir []string) ([]byte, error) {
	n := len(dir)
	path := strings.Join(dir, "/") + "/" + metadataName
	if n >= 3 && IsSnapshot(dir[n-1]) {
		return h.virtualSnapshotDocument(ctx, actor, rp, dir, path)
	}
	// Members are consulted as the artifact the directory names admits
	// them; plugin entries of a group-level document are admitted one by
	// one, by their own names.
	group := strings.Join(dir, ".")
	members := rp.virtual.Members
	var ga string
	if n >= 2 {
		ga = strings.Join(dir[:n-1], ".") + ":" + dir[n-1]
		members = h.sources(rp, ga)
	}
	answers, err := repo.Consult(ctx, rp.virtual, members, ga, func(ctx context.Context, m repo.Member) (*contribution, error) {
		if m.Hosted {
			v := h.meta.View()
			defer v.Release()
			hm, err := hostedMetadata(v, m.Name, dir)
			if err != nil {
				return nil, err
			}
			if hm == nil {
				return nil, errNoVersion
			}
			return contributionOf(hm), nil
		}
		md, err := h.proxyDocument(ctx, actor, h.repos[m.Name], path)
		if err != nil {
			return nil, err
		}
		return contributionOf(md.m), nil
	}, memberNotFound)
	if err != nil {
		return nil, err
	}
	var lists [][]versionEntry
	var pluginLists [][]plugin
	var updated time.Time
	v := h.meta.View()
	defer v.Release()
	for _, a := range answers {
		if n >= 2 {
			lists = append(lists, a.Value.versions)
			updated = laterOf(updated, a.Value.updated)
		}
		var ps []plugin
		for _, p := range a.Value.plugins {
			name := group + ":" + p.ArtifactID
			if !rp.virtual.Admits(a.Member, name) {
				continue
			}
			if !a.Member.Hosted && rp.virtual.Protect && hostedOwner(v, rp, name) {
				continue
			}
			ps = append(ps, p)
		}
		pluginLists = append(pluginLists, ps)
	}
	vs := repo.Merge(lists, func(e versionEntry) string { return e.Version })
	ps := repo.Merge(pluginLists, func(p plugin) string { return p.ArtifactID })
	if len(vs) == 0 && len(ps) == 0 {
		return nil, nil
	}
	m := &metadataXML{}
	if len(vs) > 0 {
		m = artifactMetadata(strings.Join(dir[:n-1], "."), dir[n-1], vs, updated)
	}
	m.Plugins = pluginsMetadata(ps)
	return encodeMetadata(m), nil
}

// hostedOwner reports whether a hosted member of rp whose filters admit
// the artifact called ga owns it.
func hostedOwner(v meta.View, rp *repository, ga string) bool {
	for _, m := range rp.virtual.Members {
		if m.Hosted && rp.virtual.Admits(m, ga) && owns(v, m.Name, ga) {
			return true
		}
	}
	return false
}

// contributionOf is what a document contributes to a merged one.
func contributionOf(m *metadataXML) *contribution {
	vs, updated := metadataVersions(m)
	c := &contribution{updated: updated, plugins: metadataPlugins(m)}
	for _, v := range vs {
		c.versions = append(c.versions, versionEntry{Version: v})
	}
	return c
}

// virtualSnapshotDocument returns a snapshot version's metadata from the
// first member that has the version.
func (h *Handler) virtualSnapshotDocument(ctx context.Context, actor string, rp *repository, dir []string, path string) ([]byte, error) {
	n := len(dir)
	ga := strings.Join(dir[:n-2], ".") + ":" + dir[n-2]
	var failure error
	for _, m := range h.sources(rp, ga) {
		answers, err := repo.Consult(ctx, rp.virtual, []repo.Member{m}, ga, func(ctx context.Context, m repo.Member) ([]byte, error) {
			if m.Hosted {
				b, err := h.hostedDocument(m.Name, dir)
				if err == nil && b == nil {
					err = errNoVersion
				}
				return b, err
			}
			md, err := h.proxyDocument(ctx, actor, h.repos[m.Name], path)
			if err != nil {
				return nil, err
			}
			return md.b, nil
		}, memberNotFound)
		switch {
		case len(answers) > 0:
			return answers[0].Value, nil
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case err != nil && failure == nil:
			failure = err
		}
	}
	return nil, failure
}
