package npm

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// upRegistry is a fake upstream npm registry under /registry/: full and
// abbreviated packuments with ETags, tarballs under /files/, signing
// keys, attestations, search, and bulk advisories.
type upRegistry struct {
	*httptest.Server
	t *testing.T

	mu       sync.Mutex
	pkgs     map[string]*upPackage
	files    map[string][]byte // path: tarball
	keys     string
	status   func(r *http.Request) int
	requests []string
	audits   []map[string]json.RawMessage // the bodies of audit requests
	auth     string                       // the Authorization header of the last request
	down     atomic.Bool
}

// upPackage is a package of the fake registry.
type upPackage struct {
	name     string
	tags     map[string]string
	versions map[string]map[string]any // manifest, with dist
	order    []string
	time     map[string]string
}

func newUpRegistry(t *testing.T) *upRegistry {
	u := &upRegistry{t: t, pkgs: map[string]*upPackage{}, files: map[string][]byte{},
		keys: `{"keys": [{"keyid": "SHA256:up", "keytype": "ecdsa-sha2-nistp256", "key": "MFkw"}]}`}
	u.Server = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.Close)
	return u
}

// tarballOf is the content of a version's tarball in the fake registry.
func tarballOf(name, version string) []byte {
	return []byte("upstream tarball of " + name + "@" + version)
}

// add publishes name@version upstream, pointing latest at it, with extra
// manifest fields; the dist's integrity is the tarball's, unless the
// manifest gives a dist of its own.
func (u *upRegistry) add(name, version string, extra map[string]any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	p := u.pkgs[name]
	if p == nil {
		p = &upPackage{name: name, tags: map[string]string{}, versions: map[string]map[string]any{},
			time: map[string]string{"created": "2020-01-01T00:00:00.000Z"}}
		u.pkgs[name] = p
	}
	body := tarballOf(name, version)
	path := "/files/" + name + "/-/" + unscoped(name) + "-" + version + ".tgz"
	u.files[path] = body
	s512, s1 := sha512.Sum512(body), sha1.Sum(body)
	m := map[string]any{"name": name, "version": version, "description": "upstream " + name,
		"dist": map[string]any{
			"integrity":  "sha512-" + base64.StdEncoding.EncodeToString(s512[:]),
			"shasum":     hex.EncodeToString(s1[:]),
			"tarball":    u.URL + path,
			"signatures": []any{map[string]any{"keyid": "SHA256:up", "sig": "sig-of-" + version}},
		}}
	for k, v := range extra {
		m[k] = v
	}
	if _, ok := p.versions[version]; !ok {
		p.order = append(p.order, version)
	}
	p.versions[version] = m
	p.tags["latest"] = version
	p.time[version] = "2021-01-01T00:00:00.000Z"
	p.time["modified"] = "2022-01-01T00:00:00.000Z"
}

// remove unpublishes a version upstream.
func (u *upRegistry) remove(name, version string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	p := u.pkgs[name]
	delete(p.versions, version)
	for i, v := range p.order {
		if v == version {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
	for t, v := range p.tags {
		if v == version {
			delete(p.tags, t)
		}
	}
}

func (u *upRegistry) setStatus(f func(r *http.Request) int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status = f
}

// count returns how many requests had a path containing substr.
func (u *upRegistry) count(substr string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, r := range u.requests {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

// packument renders a package as the registry does: the abbreviated
// form keeps fewer fields.
func (p *upPackage) packument(abbreviated bool) []byte {
	var b bytes.Buffer
	b.WriteString(`{"name":`)
	b.Write(mustJSON(p.name))
	if !abbreviated {
		b.WriteString(`,"_id":`)
		b.Write(mustJSON(p.name))
		b.WriteString(`,"_rev":"7-abc","description":"upstream package","readme":"# upstream"`)
	} else {
		b.WriteString(`,"modified":"2022-01-01T00:00:00.000Z"`)
	}
	b.WriteString(`,"dist-tags":`)
	b.Write(mustJSON(p.tags))
	b.WriteString(`,"versions":{`)
	for i, v := range p.order {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(mustJSON(v))
		b.WriteByte(':')
		m := p.versions[v]
		if abbreviated {
			m = map[string]any{"name": m["name"], "version": m["version"], "dist": m["dist"]}
		}
		b.Write(mustJSON(m))
	}
	b.WriteString(`}`)
	if !abbreviated {
		b.WriteString(`,"time":`)
		b.Write(mustJSON(p.time))
	}
	b.WriteString(`}`)
	return b.Bytes()
}

func (u *upRegistry) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.requests = append(u.requests, r.Method+" "+r.URL.Path)
	u.auth = r.Header.Get("Authorization")
	status := u.status
	u.mu.Unlock()
	if u.down.Load() {
		// As a dead host would: no answer.
		hj, ok := w.(http.Hijacker)
		if ok {
			if c, _, err := hj.Hijack(); err == nil {
				c.Close()
				return
			}
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if status != nil {
		if s := status(r); s != 0 {
			w.WriteHeader(s)
			return
		}
	}
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/files/"):
		u.mu.Lock()
		b, ok := u.files[p]
		u.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(b)
	case p == "/registry/-/npm/v1/keys":
		io.WriteString(w, u.keys)
	case strings.HasPrefix(p, "/registry/-/npm/v1/attestations/"):
		spec := strings.TrimPrefix(p, "/registry/-/npm/v1/attestations/")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"attestations": [{"predicateType": "https://slsa.dev/provenance/v1", "bundle": {"of": `+string(mustJSON(spec))+`}}]}`)
	case p == "/registry/-/v1/search":
		q := r.URL.Query()
		var objs []string
		u.mu.Lock()
		for name := range u.pkgs {
			if strings.Contains(name, q.Get("text")) {
				objs = append(objs, `{"package": {"name": `+string(mustJSON(name))+`, "version": "1.0.0"}}`)
			}
		}
		u.mu.Unlock()
		io.WriteString(w, `{"objects": [`+strings.Join(objs, ",")+`], "total": `+string(mustJSON(len(objs)))+`, "time": "now"}`)
	case p == "/registry/-/npm/v1/security/advisories/bulk" && r.Method == http.MethodPost:
		var req map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		u.mu.Lock()
		u.audits = append(u.audits, req)
		u.mu.Unlock()
		out := map[string]any{}
		for name := range req {
			out[name] = []any{map[string]any{"id": 1, "title": "a flaw in " + name, "severity": "high", "vulnerable_versions": "<9"}}
		}
		w.Write(mustJSON(out))
	case strings.HasPrefix(p, "/registry/"):
		name := strings.TrimPrefix(p, "/registry/")
		u.mu.Lock()
		pkg := u.pkgs[name]
		var body []byte
		abbreviated := strings.Contains(r.Header.Get("Accept"), mtAbbreviated)
		if pkg != nil {
			body = pkg.packument(abbreviated)
		}
		u.mu.Unlock()
		if pkg == nil {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error": "Not found"}`)
			return
		}
		sum := sha256.Sum256(body)
		etag := `"` + hex.EncodeToString(sum[:8]) + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if abbreviated {
			w.Header().Set("Content-Type", mtAbbreviated)
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.Header().Set("Last-Modified", time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat))
		w.Write(body)
	default:
		http.NotFound(w, r)
	}
}
