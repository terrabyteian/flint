package npm

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/terrabyteian/flint/internal/meta"
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
		if !allow(w, r, http.MethodPut, http.MethodDelete) || !h.permit(w, r, rp, ActionPush) {
			return
		}
		var ver string
		if r.Method == http.MethodPut {
			if err := readJSON(w, r, &ver); err != nil {
				h.fail(w, r, err)
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

// serveSearch serves GET /npm/<repo>/-/v1/search: the packages whose
// names contain every word of the text parameter, names that start with
// the first word first. Qualifiers such as "keywords:x" are ignored.
func (h *Handler) serveSearch(w http.ResponseWriter, r *http.Request, rp *repository) {
	q := r.URL.Query()
	var words []string
	for word := range strings.FieldsSeq(strings.ToLower(q.Get("text"))) {
		if !strings.Contains(word, ":") {
			words = append(words, word)
		}
	}
	size := intParam(q.Get("size"), defaultSearchSize, maxSearchSize)
	from := intParam(q.Get("from"), 0, 1<<30)

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
		h.fail(w, r, failure)
		return
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
	objects := []result{}
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
				if pv, err := h.liveVersion(r.Context(), latest, vr); err == nil {
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
		objects = append(objects, result{Package: pkg, SearchScore: 1,
			Score: map[string]any{"final": 1, "detail": map[string]float64{"quality": 1, "popularity": 1, "maintenance": 1}}})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"objects": objects, "total": len(matches), "time": npmTime(h.now())})
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
// for the advisories of the package versions it installed. flint knows
// of none for hosted packages.
func (h *Handler) serveAdvisories(w http.ResponseWriter, r *http.Request, rp *repository) {
	var req map[string]json.RawMessage
	if err := readJSON(w, r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, struct{}{})
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
	w.Header().Set("Cache-Control", cacheControl(rp, "max-age=300"))
	writeJSON(w, http.StatusOK, map[string][]attestation{"attestations": {{vr.PredicateType, bundle}}})
}
