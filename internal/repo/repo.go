// Package repo is flint's repository model: what repository types mean
// whatever the package format, and the rules that span repositories, such
// as how a virtual repository chooses among its members, where each
// format's repositories are served, and how immutable names are
// published. Format packages serve the protocols; this package decides
// which repositories a request may draw from.
//
// A hosted repository holds first-party packages that clients publish. A
// proxy repository caches one upstream. A virtual repository serves one
// view merged from an ordered list of hosted and proxy repositories of
// its format, so clients need a single URL:
//
//   - Each member may carry include and exclude filters of package names;
//     a member is consulted for a name only if its filters admit it.
//   - With dependency-confusion protection, on by default, once a hosted
//     member the filters admit owns a name, only hosted members are
//     consulted for it, so a package published upstream under the same
//     name can never replace or mix with the first-party one.
//   - Otherwise the members are consulted in order, and where several
//     have the same version or file, the first member's is served.
//   - A member that fails, such as a proxy whose upstream cannot be
//     reached with nothing cached, is skipped, logged, and counted; the
//     view is built from the others.
//   - An optional publishTo member receives what clients publish to the
//     virtual repository.
//
// Names are compared after the format's normalization, which the format
// supplies with VirtualOptions.Normalize, and so are filters.
package repo

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/metrics"
)

// Member is a member of a virtual repository.
type Member struct {
	// Name is the member repository's name.
	Name string
	// Hosted reports whether the member is a hosted repository; otherwise
	// it is a proxy repository.
	Hosted bool
	// include and exclude are the member's name filters, normalized.
	include, exclude []string
}

// Virtual is a virtual repository.
type Virtual struct {
	// Name is the virtual repository's name.
	Name string
	// Members are the member repositories, in order of precedence.
	Members []Member
	// Protect turns on dependency-confusion protection.
	Protect bool
	// PublishTo names the hosted member that receives publishes, or is
	// empty if the virtual repository refuses them.
	PublishTo string

	normalize func(string) string
	log       *slog.Logger
	metrics   *Metrics
}

// VirtualOptions configures a Virtual.
type VirtualOptions struct {
	// Normalize returns the form in which the format compares package
	// names, such as PEP 503 normalization for PyPI; member filters are
	// normalized with it too. Nil compares names exactly. It must keep
	// "*" as it is.
	Normalize func(string) string
	// Logger receives the members skipped because they failed; nil means
	// slog.Default().
	Logger *slog.Logger
	// Metrics counts the members skipped; nil counts nothing.
	Metrics *Metrics
}

// NewVirtual returns the virtual repository rc declares, with the types of
// its members looked up in all, the configured repositories. The
// configuration must be valid.
func NewVirtual(rc config.Repository, all []config.Repository, opts VirtualOptions) (*Virtual, error) {
	if rc.Type != config.TypeVirtual || rc.Virtual == nil {
		return nil, fmt.Errorf("repo: %s is not a virtual repository", rc.Name)
	}
	byName := make(map[string]config.Repository, len(all))
	for _, r := range all {
		byName[r.Name] = r
	}
	v := &Virtual{Name: rc.Name, Protect: rc.Virtual.Protected(), PublishTo: rc.Virtual.PublishTo,
		normalize: opts.Normalize, log: opts.Logger, metrics: opts.Metrics}
	if v.normalize == nil {
		v.normalize = func(s string) string { return s }
	}
	if v.log == nil {
		v.log = slog.Default()
	}
	for _, mc := range rc.Virtual.Members {
		m, ok := byName[mc.Name]
		switch {
		case !ok:
			return nil, fmt.Errorf("repo: virtual repository %s: member %s is not declared", rc.Name, mc.Name)
		case m.Format != rc.Format || (m.Type != config.TypeHosted && m.Type != config.TypeProxy):
			return nil, fmt.Errorf("repo: virtual repository %s: member %s is not a hosted or proxy %s repository", rc.Name, mc.Name, rc.Format)
		}
		member := Member{Name: mc.Name, Hosted: m.Type == config.TypeHosted}
		for _, p := range mc.Include {
			member.include = append(member.include, v.normalize(p))
		}
		for _, p := range mc.Exclude {
			member.exclude = append(member.exclude, v.normalize(p))
		}
		v.Members = append(v.Members, member)
	}
	if p := v.PublishTo; p != "" {
		if m, ok := byName[p]; !ok || m.Type != config.TypeHosted || !v.has(p) {
			return nil, fmt.Errorf("repo: virtual repository %s: publishTo %s is not a hosted member", rc.Name, p)
		}
	}
	return v, nil
}

// has reports whether name is a member.
func (v *Virtual) has(name string) bool {
	for _, m := range v.Members {
		if m.Name == name {
			return true
		}
	}
	return false
}

// Normalize returns name in the form the virtual repository compares
// names in.
func (v *Virtual) Normalize(name string) string { return v.normalize(name) }

// Hosted returns the names of the hosted members, in order.
func (v *Virtual) Hosted() []string {
	var out []string
	for _, m := range v.Members {
		if m.Hosted {
			out = append(out, m.Name)
		}
	}
	return out
}

// Admits reports whether m's filters admit the package called name: name
// matches one of its include patterns, or it has none, and none of its
// exclude patterns.
func (v *Virtual) Admits(m Member, name string) bool {
	name = v.normalize(name)
	if len(m.include) > 0 && !matchAny(m.include, name) {
		return false
	}
	return !matchAny(m.exclude, name)
}

// Sources returns the members that may serve the package called name, in
// order of precedence: the members whose filters admit it, and with
// dependency-confusion protection, once one of those that is hosted owns
// the name, only the hosted ones, so the proxies are never even asked.
// owns reports whether a hosted member owns the name: holds it published,
// yanked or deprecated, or as a tombstone; what that means is the
// format's to say.
func (v *Virtual) Sources(name string, owns func(hosted string) bool) []Member {
	out := make([]Member, 0, len(v.Members))
	owned := false
	for _, m := range v.Members {
		if !v.Admits(m, name) {
			continue
		}
		out = append(out, m)
		if v.Protect && m.Hosted && !owned && owns(m.Name) {
			owned = true
		}
	}
	if !owned {
		return out
	}
	hosted := out[:0]
	for _, m := range out {
		if m.Hosted {
			hosted = append(hosted, m)
		}
	}
	return hosted
}

// Answer is a member's answer for a package name.
type Answer[T any] struct {
	Member Member
	Value  T
}

// Consult asks members, in order, for the package called name, and
// returns the answers of those that have it. A member whose error
// notFound reports as not found is left out. A member that fails
// otherwise, such as a proxy whose upstream cannot be reached and that
// has nothing cached, is skipped: logged, counted, and left out, so one
// outage does not take the virtual repository down. Consult fails only if
// no member answered and one failed, with the first failure, or if ctx
// ends. With no answers and no failure it returns neither.
func Consult[T any](ctx context.Context, v *Virtual, members []Member, name string,
	ask func(context.Context, Member) (T, error), notFound func(error) bool) ([]Answer[T], error) {
	var out []Answer[T]
	var failure error
	for _, m := range members {
		val, err := ask(ctx, m)
		switch {
		case err == nil:
			out = append(out, Answer[T]{m, val})
		case notFound(err):
		case ctx.Err() != nil:
			return nil, ctx.Err()
		default:
			if failure == nil {
				failure = err
			}
			v.log.WarnContext(ctx, "a member of a virtual repository failed; serving the other members", "repository", v.Name,
				"member", m.Name, "package", name, "err", err)
			v.metrics.skipped(v.Name, m.Name)
		}
	}
	if len(out) == 0 && failure != nil {
		return nil, failure
	}
	return out, nil
}

// Merge returns the union of lists, the members' answers in order of
// precedence: each item whose key an earlier item has is left out, so
// where members have the same version or file, the first member's wins.
func Merge[T any](lists [][]T, key func(T) string) []T {
	var out []T
	seen := map[string]bool{}
	for _, l := range lists {
		for _, x := range l {
			if k := key(x); !seen[k] {
				seen[k] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// Metrics are the virtual repositories' metrics, shared by every format.
type Metrics struct {
	skips *metrics.Counter
}

// NewMetrics registers the virtual repositories' metrics on reg.
func NewMetrics(reg *metrics.Registry) *Metrics {
	return &Metrics{skips: reg.Counter("flint_virtual_member_skips_total",
		"Members of virtual repositories left out of a response because they failed, such as a proxy whose upstream "+
			"could not be reached with nothing cached, by virtual repository and member.", "repository", "member")}
}

func (m *Metrics) skipped(repo, member string) {
	if m != nil {
		m.skips.With(repo, member).Inc()
	}
}

// matchAny reports whether name matches one of patterns.
func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if Match(p, name) {
			return true
		}
	}
	return false
}

// Match reports whether name matches pattern, in which "*" matches any
// run of characters, including none, and every other byte matches
// itself: the syntax of permission grants and member filters.
func Match(pattern, name string) bool {
	// Greedy matching with backtracking to the most recent star, which is
	// linear in practice and never exponential.
	p, n := 0, 0
	star, retry := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, retry = p, n
			p++
		case p < len(pattern) && pattern[p] == name[n]:
			p++
			n++
		case star >= 0:
			retry++
			p, n = star+1, retry
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
