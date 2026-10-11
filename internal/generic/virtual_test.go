package generic

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// TestVirtualFirstMember checks that a virtual repository serves each
// path from the first member that has it.
func TestVirtualFirstMember(t *testing.T) {
	e := newEnv(t)
	e.put(http.StatusCreated, "/generic/local/both", content(1))
	e.up.set("/dl/both", content(2))
	e.up.set("/dl/upstream-only", content(3))
	if got := e.get(http.StatusOK, "/generic/all/both"); got != string(content(1)) {
		t.Errorf("both: %q", got)
	}
	if got := e.get(http.StatusOK, "/generic/all/upstream-only"); got != string(content(3)) {
		t.Errorf("upstream-only: %q", got)
	}
	e.expect(http.StatusOK, "HEAD", "/generic/all/both", nil)
	e.get(http.StatusNotFound, "/generic/all/nowhere")
	if n := e.up.count("/dl/both"); n != 0 {
		t.Errorf("the proxy was asked for a path a hosted member has: %d", n)
	}
}

// TestVirtualDependencyConfusion checks that once a hosted member holds
// a path, live or deleted, the proxy members are never consulted for it,
// unless the protection is off.
func TestVirtualDependencyConfusion(t *testing.T) {
	e := newEnv(t)
	e.up.set("/dl/internal/tool", content(9))
	e.put(http.StatusCreated, "/generic/local/internal/tool", content(1))
	e.expect(http.StatusNoContent, "DELETE", "/generic/local/internal/tool", nil)
	e.get(http.StatusNotFound, "/generic/all/internal/tool")
	if n := e.up.count("/dl/internal/tool"); n != 0 {
		t.Errorf("the proxy was asked for a path a hosted member owns: %d", n)
	}
	if got := e.get(http.StatusOK, "/generic/open/internal/tool"); got != string(content(9)) {
		t.Errorf("without protection: %q", got)
	}
}

// TestVirtualFilters checks members' filters, which match paths.
func TestVirtualFilters(t *testing.T) {
	e := newEnv(t)
	e.put(http.StatusCreated, "/generic/local/team-a/x", content(1))
	e.put(http.StatusCreated, "/generic/local/team-b/x", content(2))
	e.put(http.StatusCreated, "/generic/team/team-b/x", content(3))
	e.up.set("/dl/internal/y", content(4))
	e.up.set("/dl/public/y", content(5))
	for path, want := range map[string]string{
		"team-a/x": string(content(1)),
		"team-b/x": string(content(3)), // local's filter does not admit it
		"public/y": string(content(5)),
	} {
		if got := e.get(http.StatusOK, "/generic/filtered/"+path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
	e.get(http.StatusNotFound, "/generic/filtered/internal/y")
	if n := e.up.count("/dl/internal/y"); n != 0 {
		t.Errorf("an excluded path was asked upstream %d times", n)
	}
	if got, want := names(e.list("/generic/filtered/")), "team-a/ team-b/"; got != want {
		t.Errorf("filtered root: %q, want %q", got, want)
	}
	l := e.list("/generic/filtered/team-b/")
	if len(l.Entries) != 1 || l.Entries[0].SHA256 != sha(content(3)) {
		t.Errorf("filtered team-b/: %+v", l.Entries)
	}
}

// TestVirtualFailingMember checks that a proxy member whose upstream
// cannot be reached is skipped, logged, and counted, and that the
// request fails with its failure only if no member has the file.
func TestVirtualFailingMember(t *testing.T) {
	e := newEnv(t)
	e.up.down.Store(true)
	w := e.expect(http.StatusServiceUnavailable, "GET", "/generic/all/a", nil)
	if !strings.Contains(w.Body.String(), "unavailable") {
		t.Errorf("failure body %q", w.Body)
	}
	if got := e.metric(`flint_virtual_member_skips_total{repository="all",member="remote"}`); got != "1" {
		t.Errorf("skips metric = %q", got)
	}
	e.put(http.StatusCreated, "/generic/team/a", content(1))
	if got := e.get(http.StatusOK, "/generic/filtered/a"); got != string(content(1)) {
		t.Errorf("with a member down: %q", got)
	}
}

// TestVirtualPublishTo checks uploads through a virtual repository: to
// its publishTo member, refused when that member's filters do not admit
// the path, and refused without publishTo.
func TestVirtualPublishTo(t *testing.T) {
	e := newEnv(t)
	e.put(http.StatusCreated, "/generic/filtered/builds/1/app", content(1))
	if got := e.get(http.StatusOK, "/generic/team/builds/1/app"); got != string(content(1)) {
		t.Errorf("published file: %q", got)
	}
	e.put(http.StatusOK, "/generic/filtered/builds/1/app", content(1))
	e.put(http.StatusConflict, "/generic/filtered/builds/1/app", content(2))
	w := e.put(http.StatusMethodNotAllowed, "/generic/all/builds/1/app", content(1))
	if !strings.Contains(w.Body.String(), "local") {
		t.Errorf("refusal without publishTo does not name the hosted members: %q", w.Body)
	}
	if got := e.auth.reset(); !slices.Contains(got, "virtual filtered>team:push") {
		t.Errorf("authorized %q", got)
	}
}
