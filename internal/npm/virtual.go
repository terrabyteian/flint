package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/terrabyteian/flint/internal/repo"
)

// A virtual repository serves one registry merged from its members, in
// order, by the rules of repo.Virtual, by full package name: a packument
// is merged from the members that may serve the package (see
// repo.Virtual.Sources), and with dependency-confusion protection, once a
// hosted member owns a name, which it does from its first publish, the
// proxy members are not even asked about it. Scope patterns such as
// "@acme/*" are the natural member filters.
//
// Where members have the same version, the first member's manifest is
// served, and its tarball downloaded from that member; the dist-tags come
// from the first member that has the package, and each version's time
// from the member that supplied it. Tarball URLs point at the virtual
// repository. A member that fails is skipped (see repo.Consult), so one
// unreachable upstream does not take the registry down.
//
// Publishes and the other changes to packages go to the publishTo
// member, so one registry URL serves both install and publish.

// owner reports whether a hosted member, name, owns package pkg: has a
// package record for it, which it keeps forever once it published the
// package.
func (h *Handler) owner(pkg string) func(hosted string) bool {
	return func(hosted string) bool {
		v := h.meta.View()
		defer v.Release()
		_, ok := v.Get(pkgKey(hosted, pkg))
		return ok
	}
}

// virtualSources returns the members of rp that may serve package name.
func (h *Handler) virtualSources(rp *repository, name string) []repo.Member {
	return rp.virtual.Sources(name, h.owner(name))
}

// virtualBody returns virtual repository rp's packument of name, its URLs
// below base: one member's, if only one has the package, and otherwise
// merged from theirs. Members' packuments whose combined size exceeds
// rp's merge limit are not merged: the first member's is served alone.
func (h *Handler) virtualBody(ctx context.Context, actor string, rp *repository, name string, abbreviated bool, base string) (*docBody, error) {
	var bodies []*docBody
	answers, err := repo.Consult(ctx, rp.virtual, h.virtualSources(rp, name), name,
		func(ctx context.Context, m repo.Member) (*docBody, error) {
			b, err := h.packumentBody(ctx, actor, h.repos[m.Name], name, abbreviated, base)
			if err == nil {
				bodies = append(bodies, b)
			}
			return b, err
		}, isNotFound)
	if err != nil {
		closeBodies(bodies)
		return nil, err
	}
	switch len(answers) {
	case 0:
		return nil, notFound(name)
	case 1:
		return answers[0].Value, nil
	}
	var total int64
	for _, a := range answers {
		total += a.Value.size()
	}
	if total > rp.mergeLimit {
		h.log.WarnContext(ctx, "the members' packuments are too large to merge; serving the first member's alone",
			"repository", rp.name, "package", name, "member", answers[0].Member.Name, "bytes", total, "mergeLimit", rp.mergeLimit)
		h.mergeFallbacks.With(rp.name).Inc()
		closeBodies(bodies[1:])
		return answers[0].Value, nil
	}
	defer closeBodies(bodies)
	ids := make([]string, len(answers))
	for i, a := range answers {
		ids[i] = a.Value.id
	}
	// Hosted renderings are cached under keys that start with a
	// repository name, which is never empty.
	key := strings.Join(append([]string{"", rp.name, name, base, boolString(abbreviated)}, ids...), "\x00")
	b, etag, err := h.merged(ctx, key, name, answers, abbreviated)
	if err != nil {
		return nil, err
	}
	return &docBody{b: b, etag: etag, abbreviated: abbreviated, id: "v" + etag}, nil
}

// closeBodies closes the streams of bodies.
func closeBodies(bodies []*docBody) {
	for _, b := range bodies {
		b.close()
	}
}

// mergeFlight is a merge being built, which concurrent requests for it
// wait for rather than build it again.
type mergeFlight struct {
	done chan struct{}
	b    []byte
	etag string
	err  error
}

// merged returns the merge of the members' packuments answers, rendered
// under key: from the render cache, or built once however many requests
// want it at the same time.
func (h *Handler) merged(ctx context.Context, key, name string, answers []repo.Answer[*docBody], abbreviated bool) ([]byte, string, error) {
	if b, etag, ok := h.renders.get(key); ok {
		return b, etag, nil
	}
	h.mergeMu.Lock()
	f, building := h.merges[key]
	if !building {
		f = &mergeFlight{done: make(chan struct{})}
		h.merges[key] = f
	}
	h.mergeMu.Unlock()
	if building {
		select {
		case <-f.done:
			return f.b, f.etag, f.err
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	defer func() {
		h.mergeMu.Lock()
		delete(h.merges, key)
		h.mergeMu.Unlock()
		close(f.done)
	}()
	docs := make([]*mergeDoc, 0, len(answers))
	for _, a := range answers {
		d, err := readMergeDoc(a.Value.reader())
		if err != nil {
			f.err = err
			return nil, "", err
		}
		docs = append(docs, d)
	}
	f.b = mergePackuments(name, docs, abbreviated)
	f.etag = h.renders.put(key, f.b)
	return f.b, f.etag, nil
}

func boolString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// field is a field of a JSON object.
type field struct {
	key string
	val json.RawMessage
}

// mergeDoc is a member's packument read for merging.
type mergeDoc struct {
	fields   []field // the top-level fields not merged, in order
	tags     json.RawMessage
	modified string // the abbreviated form's
	time     map[string]json.RawMessage
	versions []field
}

// Top-level fields a merge computes rather than taking from the first
// member.
var mergedFields = map[string]bool{"_id": true, "_rev": true, "name": true, "dist-tags": true, "modified": true,
	"time": true, "versions": true}

// readMergeDoc reads a served packument for merging.
func readMergeDoc(r io.Reader) (*mergeDoc, error) {
	d := &mergeDoc{}
	err := scanPackument(r, packumentVisitor{
		field: func(k string, raw json.RawMessage) error {
			switch k {
			case "dist-tags":
				d.tags = raw
			case "modified":
				json.Unmarshal(raw, &d.modified)
			case "time":
				json.Unmarshal(raw, &d.time)
			default:
				if !mergedFields[k] {
					d.fields = append(d.fields, field{k, raw})
				}
			}
			return nil
		},
		version: func(ver string, raw json.RawMessage) error {
			d.versions = append(d.versions, field{ver, raw})
			return nil
		},
	})
	return d, err
}

// mergePackuments merges members' packuments of package name, in order
// of precedence: versions by union, the first member's manifest of a
// version winning; dist-tags from the first member that has a version;
// each version's time from the member that supplied it; and the other
// fields from the first member.
func mergePackuments(name string, docs []*mergeDoc, abbreviated bool) []byte {
	var versions []field
	from := map[string]*mergeDoc{}
	var tags json.RawMessage
	var modified, created, changed string
	for _, d := range docs {
		if tags == nil && len(d.versions) > 0 {
			tags = d.tags
		}
		for _, v := range d.versions {
			if from[v.key] == nil {
				from[v.key] = d
				versions = append(versions, v)
			}
		}
		modified = max(modified, d.modified)
		var c, m string
		json.Unmarshal(d.time["created"], &c)
		json.Unmarshal(d.time["modified"], &m)
		if c != "" && (created == "" || c < created) {
			created = c
		}
		changed = max(changed, m)
	}
	if tags == nil {
		tags = docs[0].tags
	}
	if tags == nil {
		tags = json.RawMessage("{}")
	}
	var out bytes.Buffer
	o := newObjectWriter(&out)
	if !abbreviated {
		o.raw("_id", jsonString(name))
	}
	o.raw("name", jsonString(name))
	if modified != "" {
		o.raw("modified", jsonString(modified))
	}
	if !abbreviated {
		for _, f := range docs[0].fields {
			o.raw(f.key, f.val)
		}
	}
	o.raw("dist-tags", tags)
	o.key("versions")
	vo := newObjectWriter(&out)
	for _, v := range versions {
		vo.raw(v.key, v.val)
	}
	vo.close()
	if !abbreviated {
		o.key("time")
		to := newObjectWriter(&out)
		if created != "" {
			to.raw("created", jsonString(created))
		}
		if changed != "" {
			to.raw("modified", jsonString(changed))
		}
		for _, v := range versions {
			if t, ok := from[v.key].time[v.key]; ok {
				to.raw(v.key, t)
			}
		}
		to.close()
	}
	o.close()
	return out.Bytes()
}

// virtualTarball serves a tarball of virtual repository rp from the
// first member, of those that may serve the package, that has its
// version: a hosted member that has it published, or a proxy member that
// has it cached or whose upstream packument lists it.
func (h *Handler) virtualTarball(w http.ResponseWriter, r *http.Request, rp *repository, name, file string) {
	ctx := r.Context()
	actor := h.actor(r)
	var failure error
	for _, m := range h.virtualSources(rp, name) {
		mr := h.repos[m.Name]
		ans, err := repo.Consult(ctx, rp.virtual, []repo.Member{m}, name, func(ctx context.Context, m repo.Member) (func(), error) {
			if m.Hosted {
				ver, ok := tarballVersion(name, file)
				if !ok || !h.hostedHas(mr, name, ver) {
					return nil, notFound(name)
				}
				return func() { h.hostedTarball(w, r, rp, mr, name, file) }, nil
			}
			if h.cachedTarball(ctx, mr, name, file) {
				return func() { h.proxyTarball(w, r, rp, mr, name, file, nil) }, nil
			}
			dists, err := h.proxyDists(ctx, actor, mr, name)
			if err != nil {
				return nil, err
			}
			if ver, ok := proxyTarballVersion(name, file); !ok || dists[ver] == nil {
				return nil, notFound(name)
			}
			return func() { h.proxyTarball(w, r, rp, mr, name, file, dists) }, nil
		}, isNotFound)
		switch {
		case len(ans) > 0:
			ans[0].Value()
			return
		case ctx.Err() != nil:
			return
		case err != nil && failure == nil:
			failure = err
		}
	}
	if failure != nil {
		h.fail(w, r, failure)
		return
	}
	writeError(w, http.StatusNotFound, "%s is not a tarball of %s in repository %s", abbrev(file), name, rp.name)
}

// hostedHas reports whether hosted repository rp has version ver of
// package name published.
func (h *Handler) hostedHas(rp *repository, name, ver string) bool {
	v := h.meta.View()
	defer v.Release()
	rec, ok := v.Get(versionKey(rp.name, name, ver))
	if !ok {
		return false
	}
	vr, err := decodeVersion(rec.Value)
	return err == nil && vr.Kind == kindLive
}

// supplier returns the member of virtual repository rp that supplies
// version ver of package name, as virtualTarball finds it, or nil.
func (h *Handler) supplier(ctx context.Context, actor string, rp *repository, name, ver string) (*repository, error) {
	var failure error
	for _, m := range h.virtualSources(rp, name) {
		mr := h.repos[m.Name]
		ans, err := repo.Consult(ctx, rp.virtual, []repo.Member{m}, name, func(ctx context.Context, m repo.Member) (bool, error) {
			if m.Hosted {
				if h.hostedHas(mr, name, ver) {
					return true, nil
				}
				return false, notFound(name)
			}
			dists, err := h.proxyDists(ctx, actor, mr, name)
			if err == nil && dists[ver] == nil {
				err = notFound(name)
			}
			return err == nil, err
		}, isNotFound)
		switch {
		case len(ans) > 0:
			return mr, nil
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case err != nil && failure == nil:
			failure = err
		}
	}
	return nil, failure
}
