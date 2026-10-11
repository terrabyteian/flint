package upstream

import "github.com/terrabyteian/flint/internal/metrics"

// Results of proxy requests, for the flint_proxy_requests_total metric.
const (
	ResultHit         = "hit"         // served from the cache without asking the upstream
	ResultRevalidated = "revalidated" // served after the upstream confirmed it
	ResultFetched     = "fetched"     // fetched from the upstream and cached
	ResultPassthrough = "passthrough" // fetched from the upstream, not cached
	ResultStale       = "stale"       // served from the cache because the upstream failed
)

// Metrics are the metrics proxy repositories of every format share, by
// repository; repository names are unique across formats.
type Metrics struct {
	// Requests counts pulls, by repository and result (ResultHit and so on).
	Requests *metrics.Counter
	// UpstreamErrors counts upstream requests that failed, by repository.
	UpstreamErrors *metrics.Counter
	// UpstreamBytes counts bytes fetched from upstreams, by repository.
	UpstreamBytes *metrics.Counter
	// Evictions counts items evicted to stay within size limits, by
	// repository.
	Evictions *metrics.Counter
	// CachedBytes is the content cached by size-limited repositories, by
	// repository.
	CachedBytes *metrics.Gauge
}

// NewMetrics registers the proxy metrics on reg: the families above, the
// fetches fetcher has in flight, and, if space is not nil, the disk
// pressure it reports.
func NewMetrics(reg *metrics.Registry, fetcher *Fetcher, space *Space) *Metrics {
	m := &Metrics{
		Requests: reg.Counter("flint_proxy_requests_total",
			"Pulls from proxy repositories, by repository and result: hit (served from the cache), "+
				"revalidated (served after the upstream confirmed a tag or listing), fetched (fetched from the upstream and cached), "+
				"passthrough (fetched from the upstream without caching), stale (served from the cache because the upstream failed).",
			"repository", "result"),
		UpstreamErrors: reg.Counter("flint_proxy_upstream_errors_total",
			"Proxy requests to upstream registries that failed, by repository.", "repository"),
		UpstreamBytes: reg.Counter("flint_proxy_upstream_bytes_total",
			"Bytes proxy repositories fetched from upstream registries, by repository.", "repository"),
		Evictions: reg.Counter("flint_proxy_evictions_total",
			"Cached items proxy repositories evicted to stay within their size limits, by repository.", "repository"),
		CachedBytes: reg.Gauge("flint_proxy_cached_bytes",
			"Bytes cached by size-limited proxy repositories, by repository.", "repository"),
	}
	if fetcher != nil {
		reg.GaugeFunc("flint_proxy_fetches_in_flight", "Blobs proxy repositories are fetching from upstream registries.",
			func() float64 { return float64(fetcher.Active()) })
	}
	if space != nil {
		reg.GaugeFunc("flint_proxy_disk_pressure",
			"1 while the data directory's free space is below proxyCache.minFreeSpace and proxy repositories pass new content through without caching it, else 0.",
			func() float64 {
				if space.Pressure() {
					return 1
				}
				return 0
			})
		reg.GaugeFunc("flint_data_free_bytes", "Free bytes on the data directory's filesystem, as last measured.",
			func() float64 { return float64(space.Free()) })
	}
	return m
}
