package upstream_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/upstream"
)

// countingServer is a test server that counts the requests it gets.
func countingServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if h != nil {
			h(w, r)
			return
		}
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func hostOf(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "http://") }

func port(srv *httptest.Server) string {
	h := hostOf(srv)
	return h[strings.LastIndexByte(h, ':')+1:]
}

func fetch(c *upstream.Client, u string) error {
	resp, err := c.GetURL(ctx, u, nil)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

func TestPolicyHosts(t *testing.T) {
	up, _ := countingServer(t, nil)
	other, otherHits := countingServer(t, nil)
	for _, tc := range []struct {
		name   string
		policy upstream.Policy
		url    string
		ok     bool
	}{
		// The upstream's own host is always allowed, also at an internal
		// address, since the configuration names it.
		{"own host", upstream.Policy{}, up.URL + "/x", true},
		{"other host, no policy", upstream.Policy{}, other.URL + "/x", false},
		// A configured host may be internal.
		{"allowed host", upstream.Policy{AllowHosts: []string{hostOf(other)}}, other.URL + "/x", true},
		{"allowed host, any port", upstream.Policy{AllowHosts: []string{"127.0.0.1"}}, other.URL + "/x", true},
		{"allowed host, other port", upstream.Policy{AllowHosts: []string{"127.0.0.1:1"}}, other.URL + "/x", false},
		// A host only the format allows, or any host, must be public:
		// an internal address literal is refused before dialing...
		{"format host at an internal address", upstream.Policy{FormatHosts: []string{hostOf(other)}}, other.URL + "/x", false},
		{"any host, internal literal", upstream.Policy{AnyHost: true}, other.URL + "/x", false},
		// ...and a name that resolves to one is refused when dialed.
		{"format host resolving to loopback", upstream.Policy{FormatHosts: []string{"localhost"}},
			"http://localhost:" + port(other) + "/x", false},
		{"any host resolving to loopback", upstream.Policy{AnyHost: true}, "http://localhost:" + port(other) + "/x", false},
		{"configured name resolving to loopback", upstream.Policy{AllowHosts: []string{"localhost"}},
			"http://localhost:" + port(other) + "/x", true},
		{"wildcard does not match the domain itself", upstream.Policy{AllowHosts: []string{"*.localhost"}},
			"http://localhost:" + port(other) + "/x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newClient(t, up.URL, upstream.Options{Policy: tc.policy})
			before := otherHits.Load()
			err := fetch(c, tc.url)
			if tc.ok {
				if err != nil {
					t.Fatalf("GetURL(%s) = %v", tc.url, err)
				}
				return
			}
			if !errors.Is(err, upstream.ErrPolicy) {
				t.Fatalf("GetURL(%s) = %v, want ErrPolicy", tc.url, err)
			}
			if c.Allowed(tc.url) && !strings.Contains(tc.url, "localhost") {
				t.Errorf("Allowed(%s) = true", tc.url)
			}
			if otherHits.Load() != before {
				t.Error("the refused host got a request")
			}
			// A refusal is not an outage: the upstream stays online.
			if c.Offline() {
				t.Error("a policy refusal marked the upstream offline")
			}
		})
	}
}

func TestPolicyRedirects(t *testing.T) {
	target, targetHits := countingServer(t, nil)
	up, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-target":
			http.Redirect(w, r, target.URL+"/file", http.StatusFound)
		case "/to-localhost":
			http.Redirect(w, r, "http://localhost:"+port(target)+"/file", http.StatusFound)
		default:
			io.WriteString(w, "ok")
		}
	})
	c := newClient(t, up.URL, upstream.Options{})
	if err := fetch(c, up.URL+"/to-target"); !errors.Is(err, upstream.ErrPolicy) {
		t.Fatalf("redirect to a host not allowed: %v, want ErrPolicy", err)
	}
	if _, err := c.Do(ctx, http.MethodGet, "/to-target", nil, nil, ""); !errors.Is(err, upstream.ErrPolicy) {
		t.Fatalf("Do redirected to a host not allowed: %v, want ErrPolicy", err)
	}
	if targetHits.Load() != 0 {
		t.Fatal("the redirect target got a request")
	}
	// OCI registries redirect blobs to any public host, never to an
	// internal one.
	c = newClient(t, up.URL, upstream.Options{Policy: upstream.Policy{AnyHost: true}})
	if err := fetch(c, up.URL+"/to-localhost"); !errors.Is(err, upstream.ErrPolicy) {
		t.Fatalf("redirect to a loopback name: %v, want ErrPolicy", err)
	}
	if targetHits.Load() != 0 {
		t.Fatal("the redirect target got a request")
	}
	c = newClient(t, up.URL, upstream.Options{Policy: upstream.Policy{AllowHosts: []string{hostOf(target)}}})
	if err := fetch(c, up.URL+"/to-target"); err != nil {
		t.Fatalf("redirect to an allowed host: %v", err)
	}
	if targetHits.Load() != 1 {
		t.Fatal("the allowed redirect was not followed")
	}
}

func TestPolicyTokenRealm(t *testing.T) {
	realm, realmHits := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"token":"t"}`)
	})
	up, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm.URL+`/token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "ok")
	})
	// AnyHost allows public hosts only; the realm is on loopback.
	c := newClient(t, up.URL, upstream.Options{Policy: upstream.Policy{AnyHost: true}})
	if _, err := c.Do(ctx, http.MethodGet, "/v2/", nil, nil, ""); !errors.Is(err, upstream.ErrPolicy) {
		t.Fatalf("token realm at an internal address: %v, want ErrPolicy", err)
	}
	if realmHits.Load() != 0 {
		t.Fatal("the refused token realm got a request")
	}
	c = newClient(t, up.URL, upstream.Options{Policy: upstream.Policy{AllowHosts: []string{hostOf(realm)}}})
	resp, err := c.Do(ctx, http.MethodGet, "/v2/", nil, nil, "")
	if err != nil {
		t.Fatalf("token realm on an allowed host: %v", err)
	}
	resp.Body.Close()
}

func TestBadPolicy(t *testing.T) {
	for _, h := range []string{"", "a/b", "*", "a.*.com", "user@host", "host:99999"} {
		if _, err := upstream.New(upstream.Options{URL: "https://example.com", Policy: upstream.Policy{AllowHosts: []string{h}}}); err == nil {
			t.Errorf("allowed host %q accepted", h)
		}
	}
}

func TestMaxConcurrent(t *testing.T) {
	release := make(chan struct{})
	up, hits := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
	})
	defer close(release)
	c := newClient(t, up.URL, upstream.Options{MaxConcurrent: 2})
	var bodies []io.Closer
	for range 2 {
		resp, err := c.GetURL(ctx, up.URL+"/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, resp.Body)
	}
	// Both slots are taken until a response body is closed.
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := c.GetURL(short, up.URL+"/x", nil); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a third concurrent request: %v, want it to wait", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("%d requests reached the upstream, want 2", hits.Load())
	}
	if c.Offline() {
		t.Error("waiting for a slot marked the upstream offline")
	}
	bodies[0].Close()
	resp, err := c.GetURL(ctx, up.URL+"/x", nil)
	if err != nil {
		t.Fatalf("a request after a slot freed: %v", err)
	}
	resp.Body.Close()
	bodies[1].Close()
	// Failed requests release their slots.
	notFound, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	c = newClient(t, notFound.URL, upstream.Options{MaxConcurrent: 1})
	for range 3 {
		if _, err := c.GetURL(ctx, notFound.URL+"/x", nil); !errors.Is(err, upstream.ErrNotFound) {
			t.Fatalf("GetURL = %v, want ErrNotFound", err)
		}
	}
}

func TestGone(t *testing.T) {
	up, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGone) })
	c := newClient(t, up.URL, upstream.Options{})
	_, err := c.GetURL(ctx, up.URL+"/x", nil)
	if !errors.Is(err, upstream.ErrGone) || !errors.Is(err, upstream.ErrNotFound) || !upstream.Answered(err) {
		t.Fatalf("410: %v, want ErrGone, which is ErrNotFound", err)
	}
}
