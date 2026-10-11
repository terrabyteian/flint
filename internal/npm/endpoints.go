package npm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
)

// serveDistTags serves /npm/<repo>/-/package/<name>/dist-tags, which
// lists a package's dist-tags, and .../dist-tags/<tag>, which sets a tag
// (PUT, with the version as a JSON string) or removes it (DELETE). Both
// changes need write; the "latest" tag cannot be removed.
func (h *Handler) serveDistTags(w http.ResponseWriter, r *http.Request, rp *repository, sub string) {
	name, rest, ok := splitName(sub)
	tag, isTag := strings.CutPrefix(rest, "dist-tags/")
	switch {
	case !ok || !ValidName(name) || rest != "dist-tags" && (!isTag || strings.Contains(tag, "/")):
		writeError(w, http.StatusNotFound, "not found")
	case !isTag:
		if !allow(w, r, http.MethodGet, http.MethodHead) || !h.permit(w, r, rp, ActionPull) {
			return
		}
		if rp.typ != config.TypeHosted {
			body, err := h.packumentBody(r.Context(), h.actor(r), rp, name, true, tarballBase(r, rp))
			var tags map[string]string
			if err == nil {
				f := body.reader()
				tags, err = distTagsIn(f)
				f.Close()
			}
			if err != nil {
				h.fail(w, r, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, tags)
			return
		}
		v := h.meta.View()
		p, _, err := hostedPackage(v, rp, name)
		v.Release()
		switch {
		case err != nil:
			h.fail(w, r, err)
		case p == nil || p.tag("latest") == "":
			h.fail(w, r, notFound(name))
		default:
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, tagMap(p))
		}
	default:
		if !allow(w, r, http.MethodPut, http.MethodDelete) {
			return
		}
		if rp = h.writable(w, r, rp, name); rp == nil || !h.permit(w, r, rp, ActionPush) {
			return
		}
		var ver string
		if r.Method == http.MethodPut {
			if err := readJSON(w, r, &ver); err != nil {
				h.fail(w, r, err)
				return
			}
			if ver == "" {
				writeError(w, http.StatusBadRequest, "the dist-tag must be set to a version; remove it with DELETE instead")
				return
			}
			if !validTag(tag) {
				writeError(w, http.StatusBadRequest, "invalid dist-tag %q: use a letter, then letters, digits, \".\", \"_\", and \"-\", in a name that is not a version range", abbrev(tag))
				return
			}
		} else if tag == "latest" {
			writeError(w, http.StatusBadRequest, "the latest dist-tag cannot be removed; point it at another version instead")
			return
		}
		var tags map[string]string
		_, _, err := h.update(r, rp, name, 0, func(_ meta.View, p *pkgRecord, vrs map[string]*versionRecord) (*change, error) {
			if p == nil || p.tag("latest") == "" {
				return nil, notFound(name)
			}
			tags = tagMap(p)
			switch {
			case ver != "" && (vrs[ver] == nil || vrs[ver].Kind != kindLive):
				return nil, errorf(http.StatusNotFound, "%s@%s is not found", name, abbrev(ver))
			case ver == "" && p.tag(tag) == "":
				return nil, errorf(http.StatusNotFound, "%s has no dist-tag %s", name, abbrev(tag))
			case p.tag(tag) == ver:
				return nil, nil
			}
			np := p.clone(h.now)
			np.Modified = h.now().UTC()
			np.setTag(tag, ver)
			tags = tagMap(np)
			target := rp.name + "/" + name + " " + tag
			if ver != "" {
				target += "=" + ver
			}
			return &change{action: "npm.dist-tag", target: target, pkg: np}, nil
		})
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, tags)
	}
}

// tagMap returns a package's dist-tags as npm lists them.
func tagMap(p *pkgRecord) map[string]string {
	out := make(map[string]string, len(p.Tags))
	for _, t := range p.Tags {
		out[t.Tag] = t.Version
	}
	return out
}

// serveWhoami serves GET /npm/<repo>/-/whoami: the user the request's
// credentials belong to.
func (h *Handler) serveWhoami(w http.ResponseWriter, r *http.Request) {
	user := h.user(r)
	if user == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"username": user})
}

// serveLogin serves PUT /npm/<repo>/-/user/org.couchdb.user:<user>, npm's
// legacy login, which npm login falls back to when the web login is not
// found: the body carries the user name and password, which flint
// verifies before it answers with a new API token for the user.
func (h *Handler) serveLogin(w http.ResponseWriter, r *http.Request, user string) {
	var body struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &body); err != nil {
		h.fail(w, r, err)
		return
	}
	switch {
	case h.login == nil:
		writeError(w, http.StatusNotFound, "logging in is not supported; configure an API token")
		return
	case body.Name == "":
		body.Name = user
	case user != "" && body.Name != user:
		writeError(w, http.StatusBadRequest, "the body's name %q is not the user %q of the URL", abbrev(body.Name), abbrev(user))
		return
	}
	if body.Name == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "a login needs a user name and a password")
		return
	}
	token, err := h.login(r, body.Name, body.Password, "npm")
	if errors.Is(err, ErrInvalidLogin) {
		writeError(w, http.StatusUnauthorized, "incorrect user name or password")
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, struct {
		OK    bool   `json:"ok"`
		ID    string `json:"id"`
		Token string `json:"token"`
	}{true, "org.couchdb.user:" + body.Name, token})
}

// Search limits.
const (
	defaultSearchSize = 20
	maxSearchSize     = 250
)

// searchResult is the answer to a search.
type searchResult struct {
	Objects []json.RawMessage `json:"objects"`
	Total   int               `json:"total"`
	Time    string            `json:"time"`
}

// serveSearch serves GET /npm/<repo>/-/v1/search. A hosted repository
// answers with the packages whose names contain every word of the text
// parameter, names that start with the first word first; qualifiers
// such as "keywords:x" are ignored. A proxy repository passes the search
// through to its upstream. A virtual repository answers with its hosted
// members' matches, then its proxy members' answers, each package once,
// as the members' filters and dependency-confusion protection admit it.
func (h *Handler) serveSearch(w http.ResponseWriter, r *http.Request, rp *repository) {
	q := r.URL.Query()
	size := intParam(q.Get("size"), defaultSearchSize, maxSearchSize)
	from := intParam(q.Get("from"), 0, 1<<30)
	var res *searchResult
	var err error
	switch rp.typ {
	case config.TypeProxy:
		res, err = h.proxySearch(r.Context(), rp, q)
	case config.TypeVirtual:
		res, err = h.virtualSearch(r, rp, q, from, size)
	default:
		res, err = h.hostedSearch(r.Context(), rp, q.Get("text"), from, size)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if res.Objects == nil {
		res.Objects = []json.RawMessage{}
	}
	res.Time = npmTime(h.now())
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, res)
}

// hostedSearch searches hosted repository rp's package names for text,
// and returns the page from, size long, of the matches.
func (h *Handler) hostedSearch(ctx context.Context, rp *repository, text string, from, size int) (*searchResult, error) {
	var words []string
	for word := range strings.FieldsSeq(strings.ToLower(text)) {
		if !strings.Contains(word, ":") {
			words = append(words, word)
		}
	}
	v := h.meta.View()
	defer v.Release()
	type match struct {
		name   string
		prefix bool
		p      *pkgRecord
	}
	var matches []match
	pfx := key(nsPkg, rp.name, "")
	var failure error
	v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
		name := string(k[len(pfx):])
		lower := strings.ToLower(name)
		for _, word := range words {
			if !strings.Contains(lower, word) {
				return true
			}
		}
		p, err := decodePkg(rec.Value)
		if err != nil {
			failure = err
			return false
		}
		if p.tag("latest") != "" {
			prefix := len(words) > 0 && (strings.HasPrefix(lower, words[0]) || strings.HasPrefix(unscoped(lower), words[0]))
			matches = append(matches, match{name, prefix, p})
		}
		return true
	})
	if failure != nil {
		return nil, failure
	}
	slices.SortStableFunc(matches, func(a, b match) int {
		switch {
		case a.prefix == b.prefix:
			return 0
		case a.prefix:
			return -1
		}
		return 1
	})
	type result struct {
		Package     map[string]any `json:"package"`
		Score       map[string]any `json:"score"`
		SearchScore float64        `json:"searchScore"`
	}
	res := &searchResult{Total: len(matches)}
	page := matches[min(from, len(matches)):]
	page = page[:min(size, len(page))]
	for _, m := range page {
		latest := m.p.tag("latest")
		pkg := map[string]any{"name": m.name, "version": latest, "date": npmTime(m.p.Modified),
			"links": map[string]string{}, "maintainers": []any{}, "scope": "unscoped"}
		if scope, _, scoped := splitScope(m.name); scoped {
			pkg["scope"] = scope
		}
		if rec, ok := v.Get(versionKey(rp.name, m.name, latest)); ok {
			if vr, err := decodeVersion(rec.Value); err == nil && vr.Kind == kindLive {
				if pv, err := h.liveVersion(ctx, latest, vr); err == nil {
					for _, f := range []string{"description", "keywords", "author"} {
						var x any
						if json.Unmarshal(pv.manifest[f], &x) == nil && x != nil {
							pkg[f] = x
						}
					}
					var publisher struct {
						Name string `json:"name"`
					}
					if json.Unmarshal(pv.manifest["_npmUser"], &publisher) == nil && publisher.Name != "" {
						u := map[string]string{"username": publisher.Name}
						pkg["publisher"], pkg["maintainers"] = u, []any{u}
					}
				}
			}
		}
		b, err := json.Marshal(result{Package: pkg, SearchScore: 1,
			Score: map[string]any{"final": 1, "detail": map[string]float64{"quality": 1, "popularity": 1, "maintenance": 1}}})
		if err != nil {
			return nil, err
		}
		res.Objects = append(res.Objects, b)
	}
	return res, nil
}

// proxySearch passes a search through to proxy repository rp's upstream.
func (h *Handler) proxySearch(ctx context.Context, rp *repository, q url.Values) (*searchResult, error) {
	b, err := h.forward(ctx, rp, "-/v1/search?"+q.Encode(), nil, "the upstream search")
	if err != nil {
		return nil, err
	}
	var res searchResult
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, upstreamError(rp, "the upstream search", err)
	}
	return &res, nil
}

// searchName returns the package name of a search result.
func searchName(obj json.RawMessage) string {
	var o struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	}
	json.Unmarshal(obj, &o)
	return o.Package.Name
}

// virtualSearch searches virtual repository rp's members: the hosted
// ones' matches first, then the proxy ones' answers, each package once,
// from a member that may serve it. A member that fails is skipped.
func (h *Handler) virtualSearch(r *http.Request, rp *repository, q url.Values, from, size int) (*searchResult, error) {
	ctx := r.Context()
	// Each member is asked for the results up to the end of the page.
	mq := url.Values{}
	for k, vs := range q {
		mq[k] = vs
	}
	mq.Set("from", "0")
	mq.Set("size", strconv.Itoa(from+size))
	answers, err := repo.Consult(ctx, rp.virtual, rp.virtual.Members, q.Get("text"),
		func(ctx context.Context, m repo.Member) (*searchResult, error) {
			mr := h.repos[m.Name]
			if m.Hosted {
				return h.hostedSearch(ctx, mr, q.Get("text"), 0, from+size)
			}
			return h.proxySearch(ctx, mr, mq)
		}, func(error) bool { return false })
	if err != nil {
		return nil, err
	}
	res := &searchResult{}
	seen := map[string]bool{}
	for _, a := range answers {
		res.Total += a.Value.Total
		for _, obj := range a.Value.Objects {
			name := searchName(obj)
			if name == "" || seen[name] || !slices.ContainsFunc(h.virtualSources(rp, name), func(s repo.Member) bool { return s.Name == a.Member.Name }) {
				continue
			}
			seen[name] = true
			res.Objects = append(res.Objects, obj)
		}
	}
	res.Objects = res.Objects[min(from, len(res.Objects)):]
	res.Objects = res.Objects[:min(size, len(res.Objects))]
	return res, nil
}

// intParam parses a non-negative integer query parameter, or returns def,
// at most max.
func intParam(s string, def, max int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return min(n, max)
}

// serveAdvisories serves POST
// /npm/<repo>/-/npm/v1/security/advisories/bulk, with which npm audit asks
// for the advisories of the package versions it installed: an object of
// package names, each with its versions. flint knows of none for hosted
// packages. A proxy repository forwards the request to its upstream, and
// a virtual repository to its proxy members' upstreams, each with only
// the names the member may serve and no hosted member owns, so the names
// of internal packages never leave the network; with forwardAudit off,
// neither forwards anything.
func (h *Handler) serveAdvisories(w http.ResponseWriter, r *http.Request, rp *repository) {
	var req map[string]json.RawMessage
	if err := readJSON(w, r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	out := json.RawMessage("{}")
	if rp.audit {
		var err error
		switch rp.typ {
		case config.TypeProxy:
			out, err = h.forwardAudit(r.Context(), rp, req)
		case config.TypeVirtual:
			out, err = h.virtualAudit(r.Context(), rp, req)
		}
		if err != nil {
			h.fail(w, r, err)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// forwardAudit forwards an audit of the packages in req to proxy
// repository rp's upstream, and returns its answer.
func (h *Handler) forwardAudit(ctx context.Context, rp *repository, req map[string]json.RawMessage) (json.RawMessage, error) {
	if len(req) == 0 {
		return json.RawMessage("{}"), nil
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return h.forward(ctx, rp, "-/npm/v1/security/advisories/bulk", body, "the upstream audit")
}

// virtualAudit forwards an audit to each proxy member of virtual
// repository rp, with the packages of req that the member may serve and
// no hosted member owns, and merges their answers, the first member's
// advisories of a package winning.
func (h *Handler) virtualAudit(ctx context.Context, rp *repository, req map[string]json.RawMessage) (json.RawMessage, error) {
	parts := map[string]map[string]json.RawMessage{} // by member
	for name, vers := range req {
		owned := false
		admitting := []string{}
		for _, m := range rp.virtual.Members {
			switch {
			case !rp.virtual.Admits(m, name):
			case m.Hosted:
				owned = owned || h.owner(name)(m.Name)
			default:
				admitting = append(admitting, m.Name)
			}
		}
		if owned {
			continue
		}
		for _, m := range admitting {
			if parts[m] == nil {
				parts[m] = map[string]json.RawMessage{}
			}
			parts[m][name] = vers
		}
	}
	var proxies []repo.Member
	for _, m := range rp.virtual.Members {
		if parts[m.Name] != nil {
			proxies = append(proxies, m)
		}
	}
	answers, err := repo.Consult(ctx, rp.virtual, proxies, "audit",
		func(ctx context.Context, m repo.Member) (map[string]json.RawMessage, error) {
			b, err := h.forwardAudit(ctx, h.repos[m.Name], parts[m.Name])
			if err != nil {
				return nil, err
			}
			var adv map[string]json.RawMessage
			if err := json.Unmarshal(b, &adv); err != nil {
				return nil, upstreamError(h.repos[m.Name], "the upstream audit", err)
			}
			return adv, nil
		}, func(error) bool { return false })
	if err != nil {
		return nil, err
	}
	out := map[string]json.RawMessage{}
	for _, a := range answers {
		for name, adv := range a.Value {
			if _, ok := out[name]; !ok && parts[a.Member.Name][name] != nil {
				out[name] = adv
			}
		}
	}
	return json.Marshal(out)
}

// serveKeys serves GET /npm/<repo>/-/npm/v1/keys: the keys the registry
// signs packuments with, which npm audit signatures verifies dist.signatures
// with. flint signs nothing, so a hosted repository has none; a proxy
// repository serves its upstream's, and a virtual repository those of its
// proxy members.
func (h *Handler) serveKeys(w http.ResponseWriter, r *http.Request, rp *repository) {
	ctx := r.Context()
	var members []*repository
	switch rp.typ {
	case config.TypeProxy:
		members = []*repository{rp}
	case config.TypeVirtual:
		for _, m := range rp.virtual.Members {
			if !m.Hosted {
				members = append(members, h.repos[m.Name])
			}
		}
	}
	keys := []json.RawMessage{}
	seen := map[string]bool{}
	var failure error
	answered := len(members) == 0
	for _, mr := range members {
		ks, err := h.proxyKeys(ctx, h.actor(r), mr)
		if err != nil {
			if failure == nil {
				failure = err
			}
			continue
		}
		answered = true
		for _, k := range ks {
			var id struct {
				KeyID string `json:"keyid"`
			}
			json.Unmarshal(k, &id)
			if id.KeyID == "" || !seen[id.KeyID] {
				seen[id.KeyID] = true
				keys = append(keys, k)
			}
		}
	}
	if !answered {
		h.fail(w, r, failure)
		return
	}
	w.Header().Set("Cache-Control", cacheControl(rp, "max-age=300"))
	writeJSON(w, http.StatusOK, map[string][]json.RawMessage{"keys": keys})
}

// serveAttestations serves GET
// /npm/<repo>/-/npm/v1/attestations/<name>@<version>: the provenance
// bundle published with a version, which dist.attestations points at and
// npm audit signatures verifies.
func (h *Handler) serveAttestations(w http.ResponseWriter, r *http.Request, rp *repository, spec string) {
	i := strings.LastIndexByte(spec, '@')
	if i <= 0 || !ValidName(spec[:i]) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	name, ver := spec[:i], spec[i+1:]
	switch rp.typ {
	case config.TypeProxy:
		h.serveProxyAttestations(w, r, rp, name, ver)
		return
	case config.TypeVirtual:
		mr, err := h.supplier(r.Context(), h.actor(r), rp, name, ver)
		switch {
		case err != nil:
			h.fail(w, r, err)
		case mr == nil:
			writeError(w, http.StatusNotFound, "%s@%s is not found", name, abbrev(ver))
		case mr.proxy != nil:
			h.serveProxyAttestations(w, r, mr, name, ver)
		default:
			h.hostedAttestations(w, r, rp, mr, name, ver)
		}
		return
	}
	h.hostedAttestations(w, r, rp, rp, name, ver)
}

// hostedAttestations serves the attestations of name@ver of hosted
// repository rp, as repository front, which the request named.
func (h *Handler) hostedAttestations(w http.ResponseWriter, r *http.Request, front, rp *repository, name, ver string) {
	v := h.meta.View()
	rec, ok := v.Get(versionKey(rp.name, name, ver))
	v.Release()
	var vr *versionRecord
	if ok {
		var err error
		if vr, err = decodeVersion(rec.Value); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	if vr == nil || vr.Kind != kindLive || vr.Provenance.IsZero() {
		writeError(w, http.StatusNotFound, "%s@%s has no attestations", name, abbrev(ver))
		return
	}
	bundle, err := h.readBlob(r.Context(), vr.Provenance, vr.ProvenanceSize)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	type attestation struct {
		PredicateType string          `json:"predicateType"`
		Bundle        json.RawMessage `json:"bundle"`
	}
	w.Header().Set("Cache-Control", cacheControl(front, "max-age=300"))
	writeJSON(w, http.StatusOK, map[string][]attestation{"attestations": {{vr.PredicateType, bundle}}})
}
