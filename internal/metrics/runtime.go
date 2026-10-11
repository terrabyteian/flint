package metrics

import (
	"runtime"
	rtmetrics "runtime/metrics"
	"time"
)

// RegisterRuntime registers process and Go runtime metrics, and
// flint_build_info carrying the given version.
func RegisterRuntime(r *Registry, version string) {
	r.Gauge("flint_build_info", "Always 1; the labels describe the running build.", "version", "goversion").
		With(version, runtime.Version()).Set(1)

	start := float64(time.Now().UnixNano()) / 1e9
	r.GaugeFunc("process_start_time_seconds", "Start time of the process since the Unix epoch, in seconds.",
		func() float64 { return start })
	r.GaugeFunc("go_goroutines", "Number of goroutines that currently exist.",
		func() float64 { return float64(runtime.NumGoroutine()) })

	for _, m := range []struct{ name, sample, help string }{
		{"go_memory_classes_total_bytes", "/memory/classes/total:bytes",
			"All memory mapped by the Go runtime into the current process as read-write."},
		{"go_memory_classes_heap_objects_bytes", "/memory/classes/heap/objects:bytes",
			"Memory occupied by live objects and dead objects that have not yet been freed by the garbage collector."},
		{"go_sched_gomaxprocs_threads", "/sched/gomaxprocs:threads",
			"The current runtime.GOMAXPROCS setting."},
	} {
		r.GaugeFunc(m.name, m.help, runtimeSample(m.sample))
	}
	r.CounterFunc("go_gc_cycles_total_gc_cycles_total", "Count of all completed GC cycles.",
		runtimeSample("/gc/cycles/total:gc-cycles"))
}

// runtimeSample returns a function reading one runtime/metrics sample.
func runtimeSample(name string) func() float64 {
	return func() float64 {
		s := []rtmetrics.Sample{{Name: name}}
		rtmetrics.Read(s)
		switch s[0].Value.Kind() {
		case rtmetrics.KindUint64:
			return float64(s[0].Value.Uint64())
		case rtmetrics.KindFloat64:
			return s[0].Value.Float64()
		}
		return 0
	}
}
