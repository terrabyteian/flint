// Package metrics is a small, hand-written implementation of Prometheus
// metrics: counters, gauges, and histograms with labels, and the Prometheus
// text exposition format (version 0.0.4) that serves them.
//
// A Registry holds metric families. Each family has a name, a help text, a
// type, and a fixed list of label names; With picks the series for one set
// of label values, creating it on first use. Updates are lock-free atomic
// operations, so recording a metric on a request path is cheap. Families
// whose value is read at scrape time, such as a store's counters, are
// registered with GaugeFunc and CounterFunc.
//
// Registration mistakes (an invalid or duplicate name, or the wrong number
// of label values) are programming errors and panic.
package metrics

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// ContentType is the media type of the text exposition format.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// DefBuckets are histogram buckets, in seconds, suited to request latency,
// with a long tail for large blob transfers.
var DefBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300}

// Registry is a set of metric families. It is safe for concurrent use.
type Registry struct {
	mu       sync.Mutex
	families map[string]family
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{families: map[string]family{}}
}

// family is one named metric with its series.
type family interface {
	write(w *bufio.Writer)
}

// Counter is a family of monotonically increasing values.
type Counter struct {
	vec[*CounterSeries]
}

// CounterSeries is one labelled series of a counter.
type CounterSeries struct{ v atomicFloat }

// Inc adds one.
func (c *CounterSeries) Inc() { c.v.add(1) }

// Add adds v, which must not be negative.
func (c *CounterSeries) Add(v float64) {
	if v < 0 {
		panic("metrics: counter decreased")
	}
	c.v.add(v)
}

// Gauge is a family of values that can go up and down.
type Gauge struct {
	vec[*GaugeSeries]
}

// GaugeSeries is one labelled series of a gauge.
type GaugeSeries struct{ v atomicFloat }

// Set sets the gauge to v.
func (g *GaugeSeries) Set(v float64) { g.v.store(v) }

// Add adds v, which may be negative.
func (g *GaugeSeries) Add(v float64) { g.v.add(v) }

// Inc adds one.
func (g *GaugeSeries) Inc() { g.v.add(1) }

// Dec subtracts one.
func (g *GaugeSeries) Dec() { g.v.add(-1) }

// Histogram is a family of distributions counted in buckets.
type Histogram struct {
	vec[*HistogramSeries]
}

// HistogramSeries is one labelled series of a histogram.
type HistogramSeries struct {
	upper  []float64       // bucket upper bounds, ascending, without +Inf
	counts []atomic.Uint64 // per bucket, not cumulative; the last is +Inf
	sum    atomicFloat
}

// Observe records one value.
func (h *HistogramSeries) Observe(v float64) {
	i, _ := slices.BinarySearch(h.upper, v) // the first bound >= v, or +Inf
	h.counts[i].Add(1)
	h.sum.add(v)
}

// Counter registers a counter family.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	c := &Counter{newVec(name, help, "counter", labels, func() *CounterSeries { return new(CounterSeries) },
		func(w *bufio.Writer, name string, lv []string, s *CounterSeries) {
			writeSample(w, name, labels, lv, "", "", s.v.load())
		})}
	r.register(name, c)
	return c
}

// Gauge registers a gauge family.
func (r *Registry) Gauge(name, help string, labels ...string) *Gauge {
	g := &Gauge{newVec(name, help, "gauge", labels, func() *GaugeSeries { return new(GaugeSeries) },
		func(w *bufio.Writer, name string, lv []string, s *GaugeSeries) {
			writeSample(w, name, labels, lv, "", "", s.v.load())
		})}
	r.register(name, g)
	return g
}

// Histogram registers a histogram family with the given bucket upper
// bounds, which must be ascending; nil means DefBuckets.
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *Histogram {
	if buckets == nil {
		buckets = DefBuckets
	}
	for i, b := range buckets {
		if math.IsNaN(b) || math.IsInf(b, 0) || i > 0 && buckets[i-1] >= b {
			panic(fmt.Sprintf("metrics: histogram %s: buckets must be finite and strictly ascending", name))
		}
	}
	if len(buckets) == 0 {
		panic(fmt.Sprintf("metrics: histogram %s: no buckets", name))
	}
	if slices.Contains(labels, "le") {
		panic(fmt.Sprintf("metrics: histogram %s: label name le is reserved", name))
	}
	upper := slices.Clone(buckets)
	bounds := make([]string, len(upper))
	for i, b := range upper {
		bounds[i] = formatFloat(b)
	}
	h := &Histogram{newVec(name, help, "histogram", labels,
		func() *HistogramSeries {
			return &HistogramSeries{upper: upper, counts: make([]atomic.Uint64, len(upper)+1)}
		},
		func(w *bufio.Writer, name string, lv []string, s *HistogramSeries) {
			// The count is the sum of the buckets read here, so the +Inf
			// bucket always equals _count even while observations race.
			var cum uint64
			for i := range s.counts {
				cum += s.counts[i].Load()
				le := "+Inf"
				if i < len(bounds) {
					le = bounds[i]
				}
				writeSample(w, name+"_bucket", labels, lv, "le", le, float64(cum))
			}
			writeSample(w, name+"_sum", labels, lv, "", "", s.sum.load())
			writeSample(w, name+"_count", labels, lv, "", "", float64(cum))
		})}
	r.register(name, h)
	return h
}

// GaugeFunc registers an unlabelled gauge whose value fn returns at scrape time.
func (r *Registry) GaugeFunc(name, help string, fn func() float64) {
	r.register(name, &funcFamily{name: name, help: help, typ: "gauge", fn: fn})
}

// CounterFunc registers an unlabelled counter whose value fn returns at
// scrape time. fn must never return a smaller value than before.
func (r *Registry) CounterFunc(name, help string, fn func() float64) {
	r.register(name, &funcFamily{name: name, help: help, typ: "counter", fn: fn})
}

func (r *Registry) register(name string, f family) {
	if !validMetricName(name) {
		panic(fmt.Sprintf("metrics: invalid metric name %q", name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.families[name]; dup {
		panic(fmt.Sprintf("metrics: %s registered twice", name))
	}
	r.families[name] = f
}

// WriteTo writes every family in the text exposition format, sorted by name.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	names := make([]string, 0, len(r.families))
	for name := range r.families {
		names = append(names, name)
	}
	fams := make([]family, len(names))
	slices.Sort(names)
	for i, name := range names {
		fams[i] = r.families[name]
	}
	r.mu.Unlock()

	cw := &countingWriter{w: w}
	bw := bufio.NewWriter(cw)
	for _, f := range fams {
		f.write(bw)
	}
	err := bw.Flush()
	return cw.n, err
}

// Handler serves the registry in the text exposition format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Cache-Control", "no-store")
		if req.Method == http.MethodHead {
			return
		}
		r.WriteTo(w)
	})
}

// vec is the label handling shared by the labelled families.
type vec[S any] struct {
	name, help, typ string
	labels          []string
	newSeries       func() S
	writeSeries     func(w *bufio.Writer, name string, labelValues []string, s S)

	series sync.Map // joined label values -> *entry[S]
}

type entry[S any] struct {
	labelValues []string
	s           S
}

func newVec[S any](name, help, typ string, labels []string, newSeries func() S,
	writeSeries func(*bufio.Writer, string, []string, S)) vec[S] {
	for i, l := range labels {
		if !validLabelName(l) || slices.Contains(labels[:i], l) {
			panic(fmt.Sprintf("metrics: %s: invalid or repeated label name %q", name, l))
		}
	}
	return vec[S]{name: name, help: help, typ: typ, labels: slices.Clone(labels),
		newSeries: newSeries, writeSeries: writeSeries}
}

// With returns the series for the given label values, one per label name
// in registration order, creating it on first use.
func (v *vec[S]) With(labelValues ...string) S {
	if len(labelValues) != len(v.labels) {
		panic(fmt.Sprintf("metrics: %s takes %d label values, got %d", v.name, len(v.labels), len(labelValues)))
	}
	key := strings.Join(labelValues, "\xff")
	if e, ok := v.series.Load(key); ok {
		return e.(*entry[S]).s
	}
	e, _ := v.series.LoadOrStore(key, &entry[S]{labelValues: slices.Clone(labelValues), s: v.newSeries()})
	return e.(*entry[S]).s
}

func (v *vec[S]) write(w *bufio.Writer) {
	var entries []*entry[S]
	v.series.Range(func(_, e any) bool {
		entries = append(entries, e.(*entry[S]))
		return true
	})
	slices.SortFunc(entries, func(a, b *entry[S]) int { return slices.Compare(a.labelValues, b.labelValues) })
	writeHeader(w, v.name, v.help, v.typ)
	for _, e := range entries {
		v.writeSeries(w, v.name, e.labelValues, e.s)
	}
}

type funcFamily struct {
	name, help, typ string
	fn              func() float64
}

func (f *funcFamily) write(w *bufio.Writer) {
	writeHeader(w, f.name, f.help, f.typ)
	writeSample(w, f.name, nil, nil, "", "", f.fn())
}

func writeHeader(w *bufio.Writer, name, help, typ string) {
	w.WriteString("# HELP ")
	w.WriteString(name)
	w.WriteByte(' ')
	w.WriteString(helpEscaper.Replace(help))
	w.WriteString("\n# TYPE ")
	w.WriteString(name)
	w.WriteByte(' ')
	w.WriteString(typ)
	w.WriteByte('\n')
}

// writeSample writes one sample line. extraName and extraValue, if set,
// are an additional label written last, such as a histogram's le.
func writeSample(w *bufio.Writer, name string, labels, values []string, extraName, extraValue string, v float64) {
	w.WriteString(name)
	if len(labels) > 0 || extraName != "" {
		w.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				w.WriteByte(',')
			}
			writeLabel(w, l, values[i])
		}
		if extraName != "" {
			if len(labels) > 0 {
				w.WriteByte(',')
			}
			writeLabel(w, extraName, extraValue)
		}
		w.WriteByte('}')
	}
	w.WriteByte(' ')
	w.WriteString(formatFloat(v))
	w.WriteByte('\n')
}

func writeLabel(w *bufio.Writer, name, value string) {
	w.WriteString(name)
	w.WriteString(`="`)
	w.WriteString(labelEscaper.Replace(value))
	w.WriteByte('"')
}

var (
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
)

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// validMetricName reports whether s matches [a-zA-Z_:][a-zA-Z0-9_:]*.
func validMetricName(s string) bool {
	return validName(s, true)
}

// validLabelName reports whether s matches [a-zA-Z_][a-zA-Z0-9_]* and does
// not start with the reserved prefix __.
func validLabelName(s string) bool {
	return validName(s, false) && !strings.HasPrefix(s, "__")
}

func validName(s string, colon bool) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			i > 0 && c >= '0' && c <= '9' || colon && c == ':'
		if !ok {
			return false
		}
	}
	return true
}

// atomicFloat is a float64 updated with atomic operations.
type atomicFloat struct{ bits atomic.Uint64 }

func (f *atomicFloat) load() float64   { return math.Float64frombits(f.bits.Load()) }
func (f *atomicFloat) store(v float64) { f.bits.Store(math.Float64bits(v)) }

func (f *atomicFloat) add(v float64) {
	for {
		old := f.bits.Load()
		if f.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+v)) {
			return
		}
	}
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
