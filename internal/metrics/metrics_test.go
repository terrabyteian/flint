package metrics

import (
	"bufio"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func expose(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	n, err := r.WriteTo(&b)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(b.Len()) {
		t.Fatalf("WriteTo returned %d bytes, wrote %d", n, b.Len())
	}
	return b.String()
}

func TestExposition(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("test_requests_total", "Requests served.\nSecond line with a \\ backslash.", "method", "code")
	c.With("GET", "200").Inc()
	c.With("GET", "200").Add(2)
	c.With("DELETE", "404").Inc()
	c.With(`we"ird`, "a\\b\nc").Add(0.5)

	g := r.Gauge("test_temperature", "A gauge without labels.")
	g.With().Set(-1.25)

	h := r.Histogram("test_duration_seconds", "Durations.", []float64{0.1, 1}, "route")
	h.With("/a").Observe(0.05)
	h.With("/a").Observe(0.1) // a bound is inclusive
	h.With("/a").Observe(0.5)
	h.With("/a").Observe(7)

	r.GaugeFunc("test_func", "Read at scrape time.", func() float64 { return math.Inf(1) })
	r.CounterFunc("test_func_total", "A counter read at scrape time.", func() float64 { return 12345678901 })

	want := `# HELP test_duration_seconds Durations.
# TYPE test_duration_seconds histogram
test_duration_seconds_bucket{route="/a",le="0.1"} 2
test_duration_seconds_bucket{route="/a",le="1"} 3
test_duration_seconds_bucket{route="/a",le="+Inf"} 4
test_duration_seconds_sum{route="/a"} 7.65
test_duration_seconds_count{route="/a"} 4
# HELP test_func Read at scrape time.
# TYPE test_func gauge
test_func +Inf
# HELP test_func_total A counter read at scrape time.
# TYPE test_func_total counter
test_func_total 1.2345678901e+10
# HELP test_requests_total Requests served.\nSecond line with a \\ backslash.
# TYPE test_requests_total counter
test_requests_total{method="DELETE",code="404"} 1
test_requests_total{method="GET",code="200"} 3
test_requests_total{method="we\"ird",code="a\\b\nc"} 0.5
# HELP test_temperature A gauge without labels.
# TYPE test_temperature gauge
test_temperature -1.25
`
	if got := expose(t, r); got != want {
		t.Errorf("exposition mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestEmptyFamilyHasHeaderOnly(t *testing.T) {
	r := NewRegistry()
	r.Counter("test_total", "Nothing yet.", "a")
	want := "# HELP test_total Nothing yet.\n# TYPE test_total counter\n"
	if got := expose(t, r); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGaugeOperations(t *testing.T) {
	r := NewRegistry()
	g := r.Gauge("test_in_flight", "In flight.").With()
	g.Inc()
	g.Inc()
	g.Dec()
	g.Add(2.5)
	if got := expose(t, r); !strings.HasSuffix(got, "test_in_flight 3.5\n") {
		t.Errorf("got %q", got)
	}
}

func TestHandler(t *testing.T) {
	r := NewRegistry()
	r.Counter("test_total", "Help.").With().Inc()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		r.Handler().ServeHTTP(rec, httptest.NewRequest(method, "/metrics", nil))
		if ct := rec.Header().Get("Content-Type"); ct != ContentType {
			t.Errorf("%s: Content-Type = %q, want %q", method, ct, ContentType)
		}
		body := rec.Body.String()
		if method == http.MethodGet && !strings.Contains(body, "test_total 1\n") {
			t.Errorf("GET body = %q", body)
		}
		if method == http.MethodHead && body != "" {
			t.Errorf("HEAD body = %q, want empty", body)
		}
	}
}

// TestConcurrentUpdates records from many goroutines while scraping, and
// checks the totals and that every scrape is well formed.
func TestConcurrentUpdates(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("test_total", "Help.", "worker")
	h := r.Histogram("test_seconds", "Help.", []float64{1, 2}, "worker")
	const workers, iters = 8, 2000
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			label := strconv.Itoa(w % 2)
			for i := range iters {
				c.With(label).Inc()
				h.With(label).Observe(float64(i % 3))
			}
		}()
	}
	scrapeErr := make(chan error, 1)
	go func() {
		for range 50 {
			var b strings.Builder
			r.WriteTo(&b)
			if err := checkWellFormed(b.String()); err != nil {
				scrapeErr <- err
				return
			}
		}
		scrapeErr <- nil
	}()
	wg.Wait()
	if err := <-scrapeErr; err != nil {
		t.Fatal(err)
	}

	out := expose(t, r)
	if err := checkWellFormed(out); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`test_total{worker="0"} 8000`,
		`test_total{worker="1"} 8000`,
		`test_seconds_count{worker="0"} 8000`,
		`test_seconds_bucket{worker="1",le="+Inf"} 8000`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing %q in\n%s", line, out)
		}
	}
}

// checkWellFormed parses the exposition loosely: comments name a family,
// samples have a name, optional labels, and a float value, and histogram
// buckets are cumulative with +Inf equal to _count.
func checkWellFormed(out string) error {
	sc := bufio.NewScanner(strings.NewReader(out))
	var lastBucket, infBucket float64
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "# ") {
			lastBucket = 0
			continue
		}
		sp := strings.LastIndexByte(line, ' ')
		if sp < 0 {
			return fmt.Errorf("malformed line %q", line)
		}
		v, err := strconv.ParseFloat(line[sp+1:], 64)
		if err != nil {
			return fmt.Errorf("bad value in %q: %v", line, err)
		}
		name := line[:sp]
		if i := strings.IndexByte(name, '{'); i >= 0 {
			if !strings.HasSuffix(name, "}") {
				return fmt.Errorf("unterminated labels in %q", line)
			}
			name = name[:i]
		}
		if !validMetricName(name) {
			return fmt.Errorf("bad metric name in %q", line)
		}
		switch {
		case strings.HasSuffix(name, "_bucket"):
			if v < lastBucket {
				return fmt.Errorf("bucket not cumulative at %q", line)
			}
			lastBucket = v
			if strings.Contains(line, `le="+Inf"`) {
				infBucket, lastBucket = v, 0
			}
		case strings.HasSuffix(name, "_seconds_count"):
			if v != infBucket {
				return fmt.Errorf("count %v != +Inf bucket %v", v, infBucket)
			}
		}
	}
	return nil
}

func TestRegistrationPanics(t *testing.T) {
	tests := []struct {
		name string
		fn   func(r *Registry)
	}{
		{"invalid name", func(r *Registry) { r.Counter("1abc", "") }},
		{"invalid func name", func(r *Registry) { r.GaugeFunc("a-b", "", func() float64 { return 0 }) }},
		{"invalid label", func(r *Registry) { r.Counter("a", "", "bad-label") }},
		{"reserved label", func(r *Registry) { r.Counter("a", "", "__x") }},
		{"repeated label", func(r *Registry) { r.Counter("a", "", "x", "x") }},
		{"duplicate", func(r *Registry) { r.Counter("a", ""); r.Gauge("a", "") }},
		{"le label", func(r *Registry) { r.Histogram("a", "", nil, "le") }},
		{"unsorted buckets", func(r *Registry) { r.Histogram("a", "", []float64{2, 1}) }},
		{"repeated buckets", func(r *Registry) { r.Histogram("a", "", []float64{1, 1}) }},
		{"infinite bucket", func(r *Registry) { r.Histogram("a", "", []float64{1, math.Inf(1)}) }},
		{"empty buckets", func(r *Registry) { r.Histogram("a", "", []float64{}) }},
		{"label count", func(r *Registry) { r.Counter("a", "", "x").With("1", "2") }},
		{"negative add", func(r *Registry) { r.Counter("a", "").With().Add(-1) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("no panic")
				}
			}()
			tt.fn(NewRegistry())
		})
	}
}

func TestRuntimeMetrics(t *testing.T) {
	r := NewRegistry()
	RegisterRuntime(r, "v1.2.3")
	out := expose(t, r)
	if err := checkWellFormed(out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`flint_build_info{version="v1.2.3",goversion="go`,
		"\ngo_goroutines ",
		"\ngo_memory_classes_heap_objects_bytes ",
		"\nprocess_start_time_seconds ",
		"\ngo_gc_cycles_total_gc_cycles_total ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "go_goroutines 0\n") {
		t.Error("go_goroutines reads 0")
	}
}
