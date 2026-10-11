package backup

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/server"
)

func serveAPI(t *testing.T, m *Manager) *httptest.Server {
	t.Helper()
	srv, err := server.New(server.Options{Addr: "127.0.0.1:0", Logger: quiet, Metrics: metrics.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	admin := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Admin") == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	Register(srv, m, admin, func(*http.Request) string { return "tester" })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func call(t *testing.T, ts *httptest.Server, method string, admin bool, out any) int {
	t.Helper()
	r, _ := http.NewRequest(method, ts.URL+APIPath, nil)
	if admin {
		r.Header.Set("X-Admin", "1")
	}
	resp, err := ts.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode != http.StatusForbidden {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: %v in %q", method, APIPath, err, b)
		}
	}
	return resp.StatusCode
}

func TestAPI(t *testing.T) {
	e := newEnv(t)
	e.put("a")
	g := &gcBlobs{Store: e.blobs, opened: make(chan struct{}, 1), release: make(chan struct{})}
	m := e.manager(g)
	ts := serveAPI(t, m)

	if code := call(t, ts, "POST", false, nil); code != http.StatusForbidden {
		t.Fatalf("POST without admin: %d", code)
	}
	var st Status
	if code := call(t, ts, "GET", true, &st); code != http.StatusOK || st.Directory != backupDir || st.Running != nil {
		t.Fatalf("GET = %d %+v", code, st)
	}
	var started Run
	if code := call(t, ts, "POST", true, &started); code != http.StatusAccepted || started.State != StateRunning ||
		started.Actor != "tester" || started.ID == "" {
		t.Fatalf("POST = %d %+v", code, started)
	}
	id := started.ID
	<-g.opened
	var busy struct {
		Error  string `json:"error"`
		Status Status `json:"status"`
	}
	if code := call(t, ts, "POST", true, &busy); code != http.StatusConflict ||
		!strings.Contains(busy.Error, "already running") || busy.Status.Running.ID != id {
		t.Fatalf("second POST = %d %+v", code, busy)
	}
	close(g.release)
	m.Wait(context.Background())
	st = Status{}
	if code := call(t, ts, "GET", true, &st); code != http.StatusOK || st.Running != nil ||
		st.Last.ID != id || st.Last.State != StateSucceeded || st.LastSuccess.ID != id || st.Last.Finished == nil {
		t.Fatalf("GET after = %d %+v", code, st)
	}

	off := serveAPI(t, nil)
	var e404 struct{ Error string }
	for _, method := range []string{"GET", "POST"} {
		if code := call(t, off, method, true, &e404); code != http.StatusNotFound || !strings.Contains(e404.Error, "backup.directory") {
			t.Fatalf("%s without backups configured = %d %q", method, code, e404.Error)
		}
	}
}
