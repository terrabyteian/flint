package cargo

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
)

// Search, GET /cargo/<repo>/api/v1/crates?q=<query>&per_page=<n>, which
// cargo search calls. There is no search index: a hosted repository
// matches the query as a prefix of or a substring in the names it holds,
// a proxy repository passes the search through to its upstream's web
// API, and a virtual repository lists its hosted members' results first,
// then its proxy members', each crate once, as its members' filters and
// dependency-confusion protection admit it.

// searchResult is the web API's search response.
type searchResult struct {
	Crates []searchCrate `json:"crates"`
	Meta   struct {
		Total int `json:"total"`
	} `json:"meta"`
}

// searchCrate is a crate in a search response.
type searchCrate struct {
	Name        string `json:"name"`
	MaxVersion  string `json:"max_version"`
	Description string `json:"description"`
}

// Search limits.
const (
	defaultPerPage = 10
	maxPerPage     = 100
	maxQuery       = 256
)

// serveSearch serves a search.
func (h *Handler) serveSearch(w http.ResponseWriter, r *http.Request, rp *repository) {
	q := r.URL.Query().Get("q")
	if len(q) > maxQuery {
		writeError(w, http.StatusBadRequest, "the query is longer than %d bytes", maxQuery)
		return
	}
	perPage := defaultPerPage
	if s := r.URL.Query().Get("per_page"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "per_page %s is not a positive number", quote(s))
			return
		}
		perPage = min(n, maxPerPage)
	}
	res, err := h.search(r.Context(), h.actor(r), rp, q, perPage)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) search(ctx context.Context, actor string, rp *repository, q string, perPage int) (*searchResult, error) {
	switch rp.typ {
	case config.TypeHosted:
		v := h.meta.View()
		defer v.Release()
		return hostedSearch(v, rp, q, perPage)
	case config.TypeProxy:
		return h.proxySearch(ctx, actor, rp, q, perPage)
	}
	answers, err := repo.Consult(ctx, rp.virtual, rp.virtual.Members, q,
		func(ctx context.Context, m repo.Member) (*searchResult, error) {
			return h.search(ctx, actor, h.repos[m.Name], q, perPage)
		}, func(error) bool { return false })
	if err != nil {
		return nil, err
	}
	// Hosted members' results first, then the proxies', in member order.
	slices.SortStableFunc(answers, func(a, b repo.Answer[*searchResult]) int {
		if a.Member.Hosted == b.Member.Hosted {
			return 0
		}
		if a.Member.Hosted {
			return -1
		}
		return 1
	})
	v := h.meta.View()
	defer v.Release()
	res := &searchResult{Crates: []searchCrate{}}
	seen := map[string]bool{}
	more := 0
	for _, a := range answers {
		for _, c := range a.Value.Crates {
			norm := Normalize(c.Name)
			if seen[norm] || !rp.virtual.Admits(a.Member, c.Name) {
				continue
			}
			if !a.Member.Hosted && rp.virtual.Protect && slices.ContainsFunc(rp.virtual.Members, func(m repo.Member) bool {
				return m.Hosted && rp.virtual.Admits(m, c.Name) && owns(v, m.Name, norm)
			}) {
				continue
			}
			seen[norm] = true
			res.Crates = append(res.Crates, c)
		}
		more += max(0, a.Value.Meta.Total-len(a.Value.Crates))
	}
	res.Meta.Total = len(res.Crates) + more
	if len(res.Crates) > perPage {
		res.Crates = res.Crates[:perPage]
	}
	return res, nil
}

// hostedSearch matches q against the names of the crates of hosted
// repository rp: exact matches first, then those it starts, then those
// it is in, each in name order.
func hostedSearch(v meta.View, rp *repository, q string, perPage int) (*searchResult, error) {
	type match struct {
		rank int
		norm string
		c    searchCrate
	}
	nq := Normalize(strings.TrimSpace(q))
	pfx := key(nsCrate, rp.name, "")
	var matches []match
	var err error
	v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
		norm := string(k[len(pfx):])
		if !strings.Contains(norm, nq) {
			return true
		}
		c, derr := decodeCrate(rec.Value)
		if derr != nil {
			err = fmt.Errorf("cargo: metadata key %q: %w", k, derr)
			return false
		}
		sc, ok, lerr := latest(v, rp, norm)
		if lerr != nil {
			err = lerr
			return false
		}
		if !ok {
			return true // every version deleted
		}
		sc.Name = c.Name
		rank := 2
		switch {
		case norm == nq:
			rank = 0
		case strings.HasPrefix(norm, nq):
			rank = 1
		}
		matches = append(matches, match{rank, norm, sc})
		return true
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(matches, func(a, b match) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), strings.Compare(a.norm, b.norm))
	})
	res := &searchResult{Crates: []searchCrate{}}
	res.Meta.Total = len(matches)
	for i := 0; i < len(matches) && i < perPage; i++ {
		res.Crates = append(res.Crates, matches[i].c)
	}
	return res, nil
}

// latest returns a hosted crate's highest live version, preferring
// versions that are neither yanked nor pre-releases, and its
// description, or false if it has no live version.
func latest(v meta.View, rp *repository, norm string) (searchCrate, bool, error) {
	var best *versionRecord
	bestRank := -1
	var err error
	v.Scan(versionsPrefix(rp.name, norm), nil, func(k []byte, rec meta.Record) bool {
		vr, derr := decodeVersion(rec.Value)
		if derr != nil {
			err = fmt.Errorf("cargo: metadata key %q: %w", k, derr)
			return false
		}
		if vr.Kind != kindLive {
			return true
		}
		rank := 0
		if l, lerr := decodeLine(vr.Line); lerr == nil && !l.Yanked {
			rank++
			if pv, ok := parseVersion(vr.Vers); ok && len(pv.pre) == 0 {
				rank++
			}
		}
		if rank > bestRank || rank == bestRank && compareVersions(vr.Vers, best.Vers) > 0 {
			best, bestRank = vr, rank
		}
		return true
	})
	if err != nil || best == nil {
		return searchCrate{}, false, err
	}
	return searchCrate{MaxVersion: best.Vers, Description: best.Description}, true, nil
}
