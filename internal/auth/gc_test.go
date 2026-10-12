package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/gc/gctest"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/server"
)

// TestGCMarker checks that the auth marker covers every record the
// package writes, none of which references a blob.
func TestGCMarker(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("carol", "carol-password", false, "ci")
	e.addToken("carol", false, time.Time{})
	e.addToken("root", true, e.clock.Now().Add(time.Hour))
	if refs := gctest.CheckMarked(t, e.store, GCMarker()); len(refs) != 0 {
		t.Errorf("auth records reference blobs: %v", refs)
	}
}

// TestHandleAdmin serves another package's admin endpoint to the global
// admin role only, with the client's actor name.
func TestHandleAdmin(t *testing.T) {
	e := newEnv(t, testConfig)
	e.addUser("root", "root-password", true)
	e.addUser("carol", "carol-password", false)
	adminToken := e.addToken("root", true, time.Time{})
	plainToken := e.addToken("root", false, time.Time{})
	srv, err := server.New(server.Options{Addr: "127.0.0.1:0", Logger: quiet, Metrics: metrics.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Register(srv)
	var actors []string
	e.svc.HandleAdmin(srv, "POST /api/v1/thing", func(r *http.Request, actor string) (int, any) {
		actors = append(actors, actor)
		b, _ := io.ReadAll(r.Body)
		if string(b) == "fail" {
			return http.StatusConflict, map[string]string{"error": "busy"}
		}
		return http.StatusAccepted, map[string]string{"got": string(b)}
	})
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	call := func(user, pass, body string) (int, string) {
		req, _ := http.NewRequest("POST", hs.URL+"/api/v1/thing", strings.NewReader(body))
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, tt := range []struct {
		user, pass, body string
		status           int
		out              string
	}{
		{"", "", "x", http.StatusUnauthorized, "authentication required"},
		{"root", "wrong", "x", http.StatusUnauthorized, "authentication required"},
		{"carol", "carol-password", "x", http.StatusForbidden, "admin role"},
		{TokenUser, plainToken, "x", http.StatusForbidden, "admin role"},
		{"root", "root-password", "hello", http.StatusAccepted, `"got": "hello"`},
		{TokenUser, adminToken, "fail", http.StatusConflict, `"error": "busy"`},
		{"root", "root-password", strings.Repeat("x", maxAPIBody+1), http.StatusAccepted, `"got": "` + strings.Repeat("x", maxAPIBody) + `"`},
	} {
		status, out := call(tt.user, tt.pass, tt.body)
		if status != tt.status || !strings.Contains(out, tt.out) {
			t.Errorf("%s: %d %.200s, want %d with %q", tt.user, status, out, tt.status, tt.out)
		}
	}
	if len(actors) != 3 || actors[0] != "root" || !strings.HasPrefix(actors[1], "root (token ") {
		t.Errorf("actors = %q", actors)
	}
}
