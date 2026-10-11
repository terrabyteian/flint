package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/server"
)

// testAPI serves the audit endpoints behind a guard that admits requests
// with the header "X-Admin: yes".
func testAPI(t *testing.T, l *Log) http.Handler {
	t.Helper()
	srv, err := server.New(server.Options{Addr: "127.0.0.1:0", Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	l.Register(srv, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Admin") != "yes" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			h.ServeHTTP(w, r)
		})
	})
	return srv.Handler()
}

func call(h http.Handler, path string, admin bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if admin {
		req.Header.Set("X-Admin", "yes")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAPI(t *testing.T) {
	m := fsys.NewMem()
	clock := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s := openStore(t, m, func() time.Time { return clock })
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m, SegmentSize: 400})
	defer l.Close()
	h := testAPI(t, l)
	for i := range 25 {
		clock = clock.Add(time.Minute)
		actor := "alice"
		if i%2 == 1 {
			actor = "bob (token t1)"
		}
		commit(t, s, meta.Origin{Actor: actor, Action: "oci.manifest.push", Target: fmt.Sprintf("docker-local/app:%d", i)},
			[]byte("secret-value"), "oci\x00tag\x00docker-local\x00app\x00"+fmt.Sprint(i), "-oci\x00upload\x00x")
	}
	commit(t, s, meta.Origin{Actor: "x"}, nil, "\xff\x00bin")

	if rec := call(h, QueryPath, false); rec.Code != http.StatusForbidden {
		t.Fatalf("query without the guard's approval = %d", rec.Code)
	}

	// The query catches the stream up itself, then pages through it.
	var all []RecordJSON
	after := ""
	for pages := 0; ; pages++ {
		rec := call(h, QueryPath+"?actor=alice&limit=4"+after, true)
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("query = %d %s", rec.Code, rec.Body)
		}
		var page struct {
			Records []RecordJSON
			Next    uint64
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		all = append(all, page.Records...)
		if page.Next == 0 {
			if pages != 3 || len(page.Records) != 1 {
				t.Fatalf("last page %d holds %d records", pages, len(page.Records))
			}
			break
		}
		if len(page.Records) != 4 || page.Next != page.Records[3].Seq {
			t.Fatalf("page %d: %d records, next %d", pages, len(page.Records), page.Next)
		}
		after = fmt.Sprintf("&after=%d", page.Next)
	}
	if len(all) != 13 {
		t.Fatalf("alice has %d records, want 13", len(all))
	}
	r := all[0]
	want := RecordJSON{Seq: 1, Time: time.Date(2026, 3, 1, 0, 1, 0, 0, time.UTC), Actor: "alice", Action: "oci.manifest.push",
		Target: "docker-local/app:0", Keys: []KeyJSON{
			{Op: "put", Key: []string{"oci", "tag", "docker-local", "app", "0"}},
			{Op: "delete", Key: []string{"oci", "upload", "x"}},
		}}
	if fmt.Sprint(r) != fmt.Sprint(want) {
		t.Fatalf("record = %+v\nwant     %+v", r, want)
	}

	rec := call(h, QueryPath+"?after=25", true)
	if !strings.Contains(rec.Body.String(), `"keyHex": "ff0062696e"`) {
		t.Errorf("a key that is not UTF-8 is not shown in hex: %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "secret-value") {
		t.Fatal("a value reached the API")
	}

	for _, q := range []string{"after=x", "since=yesterday", "until=2026-13-01T00:00:00Z", "limit=0", "limit=1001", "limit=many"} {
		rec := call(h, QueryPath+"?"+q, true)
		var e struct{ Error string }
		if rec.Code != 400 || json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Error == "" {
			t.Errorf("?%s = %d %s, want 400 with an error", q, rec.Code, rec.Body)
		}
	}

	// The export streams every selected record as JSON lines.
	since := url.QueryEscape(time.Date(2026, 3, 1, 0, 20, 0, 0, time.UTC).Format(time.RFC3339))
	rec = call(h, ExportPath+"?action=oci.manifest&since="+since, true)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("export = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	sc := bufio.NewScanner(rec.Body)
	var lines []RecordJSON
	for sc.Scan() {
		var r RecordJSON
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("export line %q: %v", sc.Text(), err)
		}
		lines = append(lines, r)
	}
	if len(lines) != 6 || lines[0].Seq != 20 || lines[5].Seq != 25 {
		t.Fatalf("export holds %d records: %+v", len(lines), lines)
	}
	if rec := call(h, ExportPath+"?since=x", true); rec.Code != 400 {
		t.Errorf("export with a bad parameter = %d", rec.Code)
	}
}

// TestRun checks that Run keeps the stream current in the background.
func TestRun(t *testing.T) {
	m := fsys.NewMem()
	s := openStore(t, m, nil)
	defer s.Close()
	l := openLog(t, Options{Store: s, FS: m, PollInterval: 5 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.Run(ctx); close(done) }()
	seq := commit(t, s, meta.Origin{Actor: "a"}, nil, "k")
	deadline := time.Now().Add(10 * time.Second)
	for l.Stats().Seq < seq {
		if time.Now().After(deadline) {
			t.Fatal("Run did not write the record")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
