package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/server"
)

// A virtual repository serves one view of its members, hosted and proxy
// OCI repositories, at /v2/<virtual>/<name>, by the rules of
// repo.Virtual:
//
//   - A pull asks the members that may serve the image name (see
//     repo.Virtual.Sources) in order, and the first that has what it asks
//     for serves it, as a pull from that member would. With
//     dependency-confusion protection, once a hosted member owns the name,
//     holding a tag of it or a manifest of it without a subject, the
//     proxy members are not asked about it, so an upstream image never
//     shadows a first-party one. A referrer, such as a signature or an
//     attestation, does not own the name, nor does a tag of the signature
//     tag schema (sha256-<hex>.sig, .att, .sbom) or a manifest only such
//     tags point to, so signing an upstream image through the virtual
//     repository leaves the image pullable.
//   - A manifest by tag follows the members' order, so the first member's
//     tag wins. Content addressed by digest is the same whichever member
//     serves it, so a manifest by digest or a blob is asked first of the
//     members that hold it under the name already, then of the member
//     that last served a manifest of the name, then of the others in
//     order. Each member serves only what it legitimately holds under the
//     name: a hosted member what is linked there, a proxy what its
//     upstream has under the name. The virtual repository links nothing,
//     so it never links a blob by its digest alone.
//   - A blob's HEAD, which push clients send to learn whether a blob
//     needs uploading, is answered only by the members that hold the
//     blob under the name already, never by asking an upstream, so that
//     it says what a push can use.
//   - A tag listing is the union of the members' listings, sorted and
//     paginated as a hosted repository's is.
//   - A proxy member's not-found answer for a manifest reference or a tag
//     listing is remembered for the member's revalidation window, so an
//     image a later member serves costs the proxies before it one upstream
//     request per window, not one per pull.
//   - Referrers of a manifest are the union of the referrers each member
//     that holds it, or referrers of it, serves, the first member's
//     winning where several have the same digest.
//   - A member that fails, such as a proxy whose upstream cannot be
//     reached with nothing cached, is skipped (see repo.First); a request
//     fails only if no member answered.
//   - A request with the ns query parameter, which containerd adds to the
//     requests it sends to a registry mirror to name the registry the
//     image comes from, is answered by the proxy members whose upstream is
//     that registry only, so one mirror endpoint fronts several
//     registries. Without such a member it is not found, and containerd
//     tries its next host.
//   - Pushes and deletes go to the publishTo member, as if addressed to
//     it, with the locations in responses naming the virtual repository.
//     They are refused if there is no publishTo or its filters do not
//     admit the name. A manifest pushed may reference blobs and child
//     manifests another member holds under the name, whether or not a
//     hosted member owns it, which a client that checked for them through
//     the virtual repository was told exist: they are linked into the
//     publishTo member, as a cross-repository mount would link them, a
//     child manifest with what it references.
//
// A virtual repository stores nothing of its own; it remembers in memory
// only which member last served a manifest of each name.

const (
	// maxSuppliers bounds the names whose manifest's member is
	// remembered.
	maxSuppliers = 4096
	// maxTagPages bounds the pages of one member's tag listing that a
	// virtual repository's listing reads.
	maxTagPages = 64
	// maxHeldError bounds the body of a member's error response held back.
	maxHeldError = 64 << 10
)

// errMiss means a member does not have what a request asks for.
var errMiss = errors.New("oci: the member does not have it")

func isMiss(err error) bool { return errors.Is(err, errMiss) }

// serveFunc serves a request for repository name rn.
type serveFunc func(http.ResponseWriter, *http.Request, *repoName, string)

// suppliers remembers which member of a virtual repository last served a
// manifest of each image name, so the blobs of the image are asked of
// that member first.
type suppliers struct {
	mu sync.Mutex
	m  map[string]string // member by full name in the virtual repository
}

func (s *suppliers) get(full string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[full]
}

func (s *suppliers) put(full, member string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	if _, ok := s.m[full]; !ok && len(s.m) >= maxSuppliers {
		for k := range s.m { // drop an arbitrary entry
			delete(s.m, k)
			break
		}
	}
	s.m[full] = member
}

// member returns name rn of a virtual repository within its member
// called member.
func (h *Handler) member(rn *repoName, member string) *repoName {
	return &repoName{full: member + "/" + rn.name, repo: member, name: rn.name, cfg: h.repos[member], addr: rn.full}
}

// serveVirtual serves a request to virtual repository rn, which a hosted
// repository would serve with o.
func (h *Handler) serveVirtual(w http.ResponseWriter, r *http.Request, rn *repoName, ep endpoint, arg string, o op) {
	if !slices.Equal(o.actions, []string{ActionPull}) {
		h.virtualPublish(w, r, rn, ep, arg, o)
		return
	}
	if !h.auth.Authorize(w, r, rn.full, ActionPull) {
		return
	}
	members, err := h.virtualSources(r, rn)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	switch ep {
	case epBlob:
		h.virtualBlob(w, r, rn, members, arg)
	case epManifest:
		h.virtualManifest(w, r, rn, members, arg)
	case epTags:
		h.virtualTags(w, r, rn, members)
	case epReferrers:
		h.virtualReferrers(w, r, rn, members, arg)
	}
}

// virtualPublish serves a push or delete to virtual repository rn, with
// o, the operation of its publishTo member.
func (h *Handler) virtualPublish(w http.ResponseWriter, r *http.Request, rn *repoName, ep endpoint, arg string, o op) {
	v := rn.cfg.virtual
	if v.PublishTo == "" {
		allowed := "" // uploads: nothing is allowed
		if ep == epBlob || ep == epManifest {
			allowed = "GET, HEAD"
		}
		instead := "a hosted repository"
		if hosted := v.Hosted(); len(hosted) > 0 {
			instead = "one of its hosted members: " + strings.Join(hosted, ", ")
		}
		w.Header().Set("Allow", allowed)
		h.writeError(w, r, newError(http.StatusMethodNotAllowed, codeUnsupported,
			"repository %s is a virtual repository without publishTo; push to %s", rn.repo, instead))
		return
	}
	mrn := h.member(rn, v.PublishTo)
	if !h.authorizeVirtual(w, r, rn, mrn, o.actions...) {
		return
	}
	if err := v.CheckPublish(rn.name); err != nil {
		h.writeError(w, r, newError(http.StatusForbidden, codeDenied, "%v", err))
		return
	}
	server.LogAttrs(r.Context(), slog.String("member", mrn.repo))
	if ep == epManifest && r.Method == http.MethodPut {
		if err := h.linkFromMembers(r, rn, mrn); err != nil {
			h.writeError(w, r, err)
			return
		}
	}
	o.serve(w, r, mrn, arg)
}

// linkFromMembers links into mrn, the publishTo member of virtual
// repository name rn, what the manifest that r pushes references that mrn
// does not hold but another member of the virtual repository holds under
// the name, whether or not a hosted member owns it: blobs, and child
// manifests, each with what it references in turn, if every one of those
// is held. A client that checked for them through the virtual repository
// was told they exist. It leaves r's body to be read again.
func (h *Handler) linkFromMembers(r *http.Request, rn, mrn *repoName) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxManifestSize+1))
	if err != nil {
		return manifestInvalid("reading the manifest: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	pm, err := parseManifest(body, r.Header.Get("Content-Type"))
	if err != nil || len(body) > maxManifestSize {
		return nil // the push answers it
	}
	var others []*repoName
	for _, m := range rn.cfg.virtual.Sources(rn.name, func(string) bool { return false }) {
		if m.Name != mrn.repo {
			others = append(others, h.member(rn, m.Name))
		}
	}
	if len(others) == 0 {
		return nil
	}
	type link struct {
		d    blob.Digest
		from string
		size int64           // a blob's
		m    *manifestRecord // a child manifest's, or nil for a blob
	}
	var links []link
	held := map[manifestRef]bool{}
	v := h.view()
	// hold reports whether mrn holds ref, or will once links are made.
	var hold func(ref manifestRef) bool
	hold = func(ref manifestRef) bool {
		if ok, seen := held[ref]; seen {
			return ok
		}
		held[ref] = false
		key := blobKey(mrn, ref.Digest)
		if ref.Kind == refManifest {
			key = manifestKey(mrn, ref.Digest)
		}
		if _, ok := v.Get(key); ok {
			held[ref] = true
			return true
		}
		for _, o := range others {
			if ref.Kind == refBlob {
				rec, ok := v.Get(blobKey(o, ref.Digest))
				if !ok {
					continue
				}
				if size, _, err := decodeBlobLink(rec.Value); err == nil {
					links = append(links, link{d: ref.Digest, from: o.full, size: size})
					held[ref] = true
				}
				break
			}
			m, err := cachedManifest(v, o, ref.Digest)
			if err != nil || m == nil {
				continue
			}
			for _, child := range m.Refs {
				if !hold(child) {
					return false
				}
			}
			m.Pushed = h.now()
			links = append(links, link{d: ref.Digest, from: o.full, m: m})
			held[ref] = true
			break
		}
		return held[ref]
	}
	for _, desc := range pm.blobs {
		if d, err := blob.ParseDigest(desc.Digest); err == nil {
			hold(manifestRef{refBlob, d})
		}
	}
	for _, desc := range pm.members {
		if d, err := blob.ParseDigest(desc.Digest); err == nil {
			hold(manifestRef{refManifest, d})
		}
	}
	v.Release()
	if len(links) == 0 {
		return nil
	}
	linked := make([]blob.Digest, len(links))
	for i, l := range links {
		linked[i] = l.d
	}
	err = h.commitLink(r.Context(), linked, func(v meta.View, b *meta.Batch) error {
		for _, l := range links {
			if l.m != nil {
				if _, ok := v.Get(manifestKey(mrn, l.d)); !ok {
					putManifestRecord(b, mrn, l.d, l.m)
				}
			} else if _, ok := v.Get(blobKey(mrn, l.d)); !ok {
				b.Put(blobKey(mrn, l.d), encodeBlobLink(l.size, h.now()))
			}
		}
		b.SetOrigin(h.origin(r, "oci.blob.mount", links[0].from+"@"+links[0].d.String()+" -> "+mrn.full))
		return nil
	}, h.statExists(r.Context(), linked...))
	if err == errRetry {
		return nil // the push reports what it lacks
	}
	return err
}

// authorizeVirtual authorizes actions through virtual repository name rn,
// whose publishTo member's name is mrn.
func (h *Handler) authorizeVirtual(w http.ResponseWriter, r *http.Request, rn, mrn *repoName, actions ...string) bool {
	if va, ok := h.auth.(VirtualAuthorizer); ok {
		return va.AuthorizeVirtual(w, r, rn.full, mrn.full, actions...)
	}
	for _, a := range actions {
		target := mrn.full
		if a == ActionPull {
			target = rn.full
		}
		if !h.auth.Authorize(w, r, target, a) {
			return false
		}
	}
	return true
}

// virtualSources returns the members of virtual repository rn that may
// serve a pull of its image name, in order: for a request with the ns
// parameter, the proxy members that mirror that registry and admit the
// name, and otherwise the members repo.Virtual.Sources returns.
func (h *Handler) virtualSources(r *http.Request, rn *repoName) ([]repo.Member, error) {
	ns := r.URL.Query().Get("ns")
	if ns == "" {
		return h.sourcesOf(rn), nil
	}
	v := rn.cfg.virtual
	var out []repo.Member
	for _, m := range v.Members {
		if p := h.repos[m.Name].proxy; p != nil && p.mirrors(ns) && v.Admits(m, rn.name) {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil, newError(http.StatusNotFound, codeNameUnknown,
			"virtual repository %s has no member that mirrors registry %s for %s", rn.repo, abbrev(ns), rn.name)
	}
	return out, nil
}

// sourcesOf returns the members of virtual repository rn that may serve
// its image name; a hosted member owns the name as ownsName says.
func (h *Handler) sourcesOf(rn *repoName) []repo.Member {
	v := h.view()
	defer v.Release()
	return rn.cfg.virtual.Sources(rn.name, func(hosted string) bool {
		return ownsName(v, &repoName{repo: hosted, name: rn.name})
	})
}

// ownsName reports whether rn holds a tag or a manifest without a
// subject. A manifest with a subject, a referrer, does not own the name,
// so a signature of an upstream image does not hide the image. Neither
// does a tag of the signature tag schema, nor a manifest only such tags
// point to, so cosign's tag-schema signatures do not hide the image
// either. A record that cannot be read owns it.
func ownsName(v meta.View, rn *repoName) bool {
	found := false
	signatures := map[string]bool{}
	pfx := prefix(nsTag, rn)
	v.Scan(pfx, nil, func(key []byte, rec meta.Record) bool {
		if !signatureTag(string(key[len(pfx):])) {
			found = true
			return false
		}
		d, err := decodeTag(rec.Value)
		if err != nil {
			found = true
			return false
		}
		signatures[d.String()] = true
		return true
	})
	if found {
		return true
	}
	pfx = prefix(nsManifest, rn)
	v.Scan(pfx, nil, func(key []byte, rec meta.Record) bool {
		m, err := decodeManifest(rec.Value)
		found = err != nil || m.Subject.IsZero() && !signatures[string(key[len(pfx):])]
		return !found
	})
	return found
}

// signatureTag reports whether tag follows the signature tag schema,
// sha256-<hex digest>.sig, .att, or .sbom, under which cosign stores the
// signatures, attestations and SBOMs of the image with that digest.
func signatureTag(tag string) bool {
	hex, ok := strings.CutPrefix(tag, "sha256-")
	if !ok {
		return false
	}
	i := strings.LastIndexByte(hex, '.')
	if i < 0 || !slices.Contains([]string{".sig", ".att", ".sbom"}, hex[i:]) {
		return false
	}
	hex = hex[:i]
	return len(hex) == 64 && strings.Trim(hex, "0123456789abcdef") == ""
}

// byDigest orders members for content addressed by digest: first those
// that hold it under rn's image name already, as held reports, then the
// member that last served a manifest of the name, then the others, each
// in the members' order.
func (h *Handler) byDigest(rn *repoName, members []repo.Member, held func(meta.View, *repoName) bool) []repo.Member {
	v := h.view()
	defer v.Release()
	supplier := h.suppliers.get(rn.full)
	rank := make(map[string]int, len(members))
	for _, m := range members {
		switch {
		case held(v, h.member(rn, m.Name)):
			rank[m.Name] = 0
		case m.Name == supplier:
			rank[m.Name] = 1
		default:
			rank[m.Name] = 2
		}
	}
	out := slices.Clone(members)
	slices.SortStableFunc(out, func(a, b repo.Member) int { return rank[a.Name] - rank[b.Name] })
	return out
}

// virtualFirst serves a request to virtual repository rn from the first
// of members that has what it asks for, with the handler serve returns
// for the member. If none has it, it answers notFound, or the first
// member's failure if one failed. It returns the member that served the
// request.
func (h *Handler) virtualFirst(w http.ResponseWriter, r *http.Request, rn *repoName, members []repo.Member, arg string,
	serve func(repo.Member) serveFunc, notFound error, missed func(repo.Member)) (repo.Member, bool) {
	a, ok, err := repo.First(r.Context(), rn.cfg.virtual, members, rn.name, func(ctx context.Context, m repo.Member) (struct{}, error) {
		mw := newMemberWriter(w)
		serve(m)(mw, r, h.member(rn, m.Name), arg)
		err := mw.result()
		if isMiss(err) && missed != nil {
			missed(m)
		}
		return struct{}{}, err
	}, isMiss)
	switch {
	case ok:
		server.LogAttrs(r.Context(), slog.String("member", a.Member.Name))
	case err == nil:
		h.writeError(w, r, notFound)
	default:
		h.writeMemberError(w, r, err)
	}
	return a.Member, ok
}

// writeMemberError answers with err, a member's failure: its response
// as the member wrote it, if it is one.
func (h *Handler) writeMemberError(w http.ResponseWriter, r *http.Request, err error) {
	var held *heldResponse
	switch {
	case errors.As(err, &held):
		held.replay(w, r)
	case r.Context().Err() != nil: // the client went away
	default:
		h.writeError(w, r, err)
	}
}

// virtualManifest serves GET and HEAD /v2/<name>/manifests/<reference> of
// a virtual repository.
func (h *Handler) virtualManifest(w http.ResponseWriter, r *http.Request, rn *repoName, members []repo.Member, ref string) {
	switch {
	case strings.Contains(ref, ":"):
		d, err := parseDigest(ref)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		members = h.byDigest(rn, members, func(v meta.View, mrn *repoName) bool {
			_, ok := v.Get(manifestKey(mrn, d))
			return ok
		})
	case !validTag(ref):
		h.writeError(w, r, manifestUnknown(rn, ref))
		return
	}
	members = h.withoutMisses(rn, members, ref)
	m, ok := h.virtualFirst(w, r, rn, members, ref, func(m repo.Member) serveFunc {
		if h.repos[m.Name].proxy != nil {
			return h.proxyGetManifest
		}
		return h.memberGetManifest
	}, manifestUnknown(rn, ref), func(m repo.Member) {
		// A proxy holding the reference cached answered not found for the
		// request's Accept header, which another request may not share.
		v := h.view()
		_, _, _, err := lookupManifest(v, h.member(rn, m.Name), ref)
		v.Release()
		if err != nil {
			h.missed(rn, m, ref)
		}
	})
	if ok {
		h.suppliers.put(rn.full, m.Name)
	}
}

// missKey is the key under which a proxy member's not-found answer for
// what of virtual repository name rn is remembered: a manifest reference,
// or "" for the tag listing.
func missKey(rn *repoName, m repo.Member, what string) string {
	return rn.repo + "\x00" + m.Name + "\x00" + rn.name + "\x00" + what
}

// missed remembers that proxy member m answered not found for what of
// name rn, for its revalidation window.
func (h *Handler) missed(rn *repoName, m repo.Member, what string) {
	if p := h.repos[m.Name].proxy; p != nil {
		h.misses.Remember(missKey(rn, m, what), false, p.revalidate)
	}
}

// withoutMisses returns members without the proxies that answered not
// found for what of name rn within their revalidation window.
func (h *Handler) withoutMisses(rn *repoName, members []repo.Member, what string) []repo.Member {
	return slices.DeleteFunc(slices.Clone(members), func(m repo.Member) bool {
		known, _ := h.misses.Known(missKey(rn, m, what))
		return known
	})
}

// memberGetManifest is getManifest for a hosted member of a virtual
// repository. Once the member holds the manifest, its answer is final,
// even a 404 because the request's Accept header does not include the
// manifest's media type: another member's manifest of the tag must not
// take its place.
func (h *Handler) memberGetManifest(w http.ResponseWriter, r *http.Request, rn *repoName, ref string) {
	v := h.view()
	_, _, _, err := lookupManifest(v, rn, ref)
	v.Release()
	if mw, ok := w.(*memberWriter); ok && err == nil {
		mw.final = true
	}
	h.getManifest(w, r, rn, ref)
}

// virtualBlob serves GET and HEAD /v2/<name>/blobs/<digest> of a virtual
// repository.
func (h *Handler) virtualBlob(w http.ResponseWriter, r *http.Request, rn *repoName, members []repo.Member, arg string) {
	d, err := parseDigest(arg)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	held := func(v meta.View, mrn *repoName) bool {
		_, ok := v.Get(blobKey(mrn, d))
		return ok
	}
	members = h.byDigest(rn, members, held)
	if r.Method == http.MethodHead {
		v := h.view()
		members = slices.DeleteFunc(members, func(m repo.Member) bool { return !m.Hosted && !held(v, h.member(rn, m.Name)) })
		v.Release()
	}
	h.virtualFirst(w, r, rn, members, arg, func(m repo.Member) serveFunc {
		if h.repos[m.Name].proxy != nil {
			return h.proxyGetBlob
		}
		return h.getBlob
	}, blobUnknown(d), nil)
}

// virtualTags serves GET /v2/<name>/tags/list of a virtual repository:
// the union of its members' tags, in lexical order.
func (h *Handler) virtualTags(w http.ResponseWriter, r *http.Request, rn *repoName, members []repo.Member) {
	n, last, err := pageParams(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	answers, err := repo.Consult(r.Context(), rn.cfg.virtual, h.withoutMisses(rn, members, ""), rn.name,
		func(ctx context.Context, m repo.Member) ([]string, error) {
			tags, err := h.memberTags(r, h.member(rn, m.Name))
			if isMiss(err) {
				h.missed(rn, m, "")
			}
			return tags, err
		}, isMiss)
	if err != nil {
		h.writeMemberError(w, r, err)
		return
	}
	if len(answers) == 0 {
		h.writeError(w, r, newError(http.StatusNotFound, codeNameUnknown, "repository %s has no manifests", rn.full))
		return
	}
	lists := make([][]string, len(answers))
	for i, a := range answers {
		lists[i] = a.Value
	}
	all := repo.Merge(lists, func(t string) string { return t })
	sort.Strings(all)
	i := sort.SearchStrings(all, last)
	if i < len(all) && last != "" && all[i] == last {
		i++
	}
	tags := all[i:]
	more := len(tags) > n
	if more {
		tags = tags[:n]
	}
	if more && n > 0 {
		setNextLink(w, "/v2/"+rn.full+"/tags/list", n, tags[len(tags)-1])
	}
	writeJSON(w, "application/json", struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}{rn.full, tags})
}

// memberTags returns every tag a member's tag listing holds, reading its
// pages, or errMiss if the member does not know the name.
func (h *Handler) memberTags(r *http.Request, mrn *repoName) ([]string, error) {
	serve := serveFunc(h.listTags)
	if mrn.cfg.proxy != nil {
		serve = h.proxyListTags
	}
	tags := []string{}
	query := ""
	for range maxTagPages {
		req := r.Clone(r.Context())
		req.URL.RawQuery = query
		mw := newMemberWriter(nil)
		serve(mw, req, mrn, "")
		if err := mw.result(); err != nil {
			return nil, err
		}
		var tl struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(mw.body, &tl); err != nil {
			return nil, fmt.Errorf("the tag listing of %s is not valid JSON: %w", mrn.full, err)
		}
		tags = append(tags, tl.Tags...)
		if query = nextQuery(mw.header.Get("Link")); query == "" {
			break
		}
	}
	return tags, nil
}

// virtualReferrers serves GET /v2/<name>/referrers/<digest> of a virtual
// repository: the union of the referrers the members that hold the
// manifest, or referrers of it, serve, or none if no member holds either.
// A signature pushed through the virtual repository for an image a proxy
// member serves is held by the publishTo member, so both are asked.
func (h *Handler) virtualReferrers(w http.ResponseWriter, r *http.Request, rn *repoName, members []repo.Member, arg string) {
	d, err := parseDigest(arg)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	answers, err := repo.Consult(r.Context(), rn.cfg.virtual, h.subjectHolders(r, rn, members, d), rn.name,
		func(ctx context.Context, m repo.Member) ([]referrerEntry, error) {
			return h.memberReferrers(r, h.member(rn, m.Name), arg)
		}, isMiss)
	if err != nil {
		h.writeMemberError(w, r, err)
		return
	}
	lists := make([][]referrerEntry, len(answers))
	for i, a := range answers {
		lists[i] = a.Value
	}
	filter := r.URL.Query().Get("artifactType")
	refs := []json.RawMessage{}
	for _, e := range repo.Merge(lists, func(e referrerEntry) string { return e.Digest }) {
		if filter == "" || e.ArtifactType == filter {
			refs = append(refs, e.raw)
		}
	}
	if filter != "" {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	writeJSON(w, mtOCIIndex, struct {
		SchemaVersion int               `json:"schemaVersion"`
		MediaType     string            `json:"mediaType"`
		Manifests     []json.RawMessage `json:"manifests"`
	}{2, mtOCIIndex, refs})
}

// referrerEntry is a descriptor in a referrers listing.
type referrerEntry struct {
	Digest       string `json:"digest"`
	ArtifactType string `json:"artifactType"`
	raw          json.RawMessage
}

// memberReferrers returns the descriptors of a member's referrers listing
// of manifest arg, or errMiss if the member does not know the name.
func (h *Handler) memberReferrers(r *http.Request, mrn *repoName, arg string) ([]referrerEntry, error) {
	serve := serveFunc(h.listReferrers)
	if mrn.cfg.proxy != nil {
		serve = h.proxyListReferrers
	}
	mw := newMemberWriter(nil)
	serve(mw, r, mrn, arg)
	if err := mw.result(); err != nil {
		return nil, err
	}
	var idx struct {
		Manifests []json.RawMessage `json:"manifests"`
	}
	if err := json.Unmarshal(mw.body, &idx); err != nil {
		return nil, fmt.Errorf("the referrers listing of %s is not valid JSON: %w", mrn.full, err)
	}
	out := make([]referrerEntry, 0, len(idx.Manifests))
	for _, raw := range idx.Manifests {
		e := referrerEntry{raw: raw}
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("the referrers listing of %s is not valid JSON: %w", mrn.full, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// subjectHolders returns the members that hold manifest d under rn's
// image name, or referrers of it, in the members' order; if none holds
// the manifest itself, the first that can serve it is among them.
func (h *Handler) subjectHolders(r *http.Request, rn *repoName, members []repo.Member, d blob.Digest) []repo.Member {
	v := h.view()
	holds := map[string]bool{}
	subject := false
	for _, m := range members {
		mrn := h.member(rn, m.Name)
		_, ok := v.Get(manifestKey(mrn, d))
		if ok || hasReferrers(v, mrn, d) {
			holds[m.Name] = true
			subject = subject || ok
		}
	}
	v.Release()
	if !subject {
		head := r.Clone(r.Context())
		head.Method = http.MethodHead
		head.Header.Del("Accept") // the referrers request's, for the index it wants
		a, ok, _ := repo.First(r.Context(), rn.cfg.virtual, h.byDigest(rn, members, func(meta.View, *repoName) bool { return false }), rn.name,
			func(ctx context.Context, m repo.Member) (struct{}, error) {
				mrn := h.member(rn, m.Name)
				mw := newMemberWriter(nil)
				if mrn.cfg.proxy != nil {
					h.proxyGetManifest(mw, head, mrn, d.String())
				} else {
					h.getManifest(mw, head, mrn, d.String())
				}
				return struct{}{}, mw.result()
			}, isMiss)
		if ok {
			holds[a.Member.Name] = true
		}
	}
	return slices.DeleteFunc(slices.Clone(members), func(m repo.Member) bool { return !holds[m.Name] })
}

// hasReferrers reports whether rn holds a manifest whose subject is d.
func hasReferrers(v meta.View, rn *repoName, d blob.Digest) bool {
	found := false
	v.Scan(referrerPrefix(rn, d), nil, func([]byte, meta.Record) bool {
		found = true
		return false
	})
	return found
}

// memberWriter is the ResponseWriter through which a member of a virtual
// repository answers a request. A success, or an error other than not
// found or a server failure, passes through to the client as the member
// writes it. A not found or a server failure is held back, so that the
// next member can be asked instead, unless final is set. With no client
// writer, every response is held back, for the virtual repository to
// read.
type memberWriter struct {
	w      http.ResponseWriter // nil to hold back every response
	header http.Header
	status int
	passed bool // the response passes through to w
	final  bool // pass through whatever the status
	body   []byte
	limit  int // bounds a held-back body
}

func newMemberWriter(w http.ResponseWriter) *memberWriter {
	mw := &memberWriter{w: w, header: http.Header{}, limit: maxHeldError}
	if w == nil {
		mw.limit = maxListingSize
	}
	return mw
}

func (m *memberWriter) Header() http.Header { return m.header }

func (m *memberWriter) WriteHeader(status int) {
	if m.status != 0 {
		return
	}
	m.status = status
	if m.w == nil || !m.final && (status == http.StatusNotFound || status >= 500) {
		return
	}
	m.passed = true
	hd := m.w.Header()
	for k, vs := range m.header {
		hd[k] = vs
	}
	m.w.WriteHeader(status)
}

func (m *memberWriter) Write(p []byte) (int, error) {
	if m.status == 0 {
		m.WriteHeader(http.StatusOK)
	}
	if m.passed {
		return m.w.Write(p)
	}
	if len(m.body)+len(p) > m.limit {
		return 0, errors.New("oci: the response is too large to hold back")
	}
	m.body = append(m.body, p...)
	return len(p), nil
}

// ReadFrom passes a blob the member serves from the blob store through to
// the client's writer, so it still reaches net/http's sendfile path.
func (m *memberWriter) ReadFrom(src io.Reader) (int64, error) {
	if m.status == 0 {
		m.WriteHeader(http.StatusOK)
	}
	if rf, ok := m.w.(io.ReaderFrom); ok && m.passed {
		return rf.ReadFrom(src)
	}
	return io.Copy(struct{ io.Writer }{m}, src)
}

// result returns nil if the member answered the request, errMiss if it
// does not have what the request asks for, and otherwise its failure.
func (m *memberWriter) result() error {
	switch {
	case m.status == 0:
		return errors.New("oci: the member wrote no response")
	case m.passed, m.status != http.StatusNotFound && m.status < 500:
		return nil
	case m.status == http.StatusNotFound:
		return errMiss
	}
	return &heldResponse{status: m.status, header: m.header, body: m.body}
}

// heldResponse is a member's failure, the response it wrote.
type heldResponse struct {
	status int
	header http.Header
	body   []byte
}

func (e *heldResponse) Error() string {
	msg := bytes.TrimSpace(e.body)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return fmt.Sprintf("status %d: %s", e.status, msg)
}

// replay writes the response to the client.
func (e *heldResponse) replay(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	for k, vs := range e.header {
		hd[k] = vs
	}
	if r.Method != http.MethodHead {
		hd.Set("Content-Length", strconv.Itoa(len(e.body)))
	}
	w.WriteHeader(e.status)
	if r.Method != http.MethodHead {
		w.Write(e.body)
	}
}
