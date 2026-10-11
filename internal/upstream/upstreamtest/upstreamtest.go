// Package upstreamtest is a fake upstream registry for tests of flint's
// proxy repositories. It serves manifests, blobs, tag listings, and
// optionally the referrers API, behind the registry token
// authentication handshake, and lets a test count requests, require
// credentials, corrupt or stall content, and take the registry down.
package upstreamtest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Media types the fake registry uses.
const (
	MediaTypeManifest = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeIndex    = "application/vnd.oci.image.index.v1+json"
	MediaTypeConfig   = "application/vnd.oci.image.config.v1+json"
	MediaTypeLayer    = "application/vnd.oci.image.layer.v1.tar"
)

// Registry is a fake upstream registry.
type Registry struct {
	*httptest.Server

	// Username and Password, if set, are required by the token endpoint.
	Username, Password string
	// Referrers enables the referrers API; without it, referrers
	// requests get 404, as from a registry that does not support it.
	Referrers bool
	// NoHeadDigest makes HEAD manifest responses omit
	// Docker-Content-Digest.
	NoHeadDigest bool

	mu        sync.Mutex
	manifests map[string]map[string]manifest // name, then tag or digest
	blobs     map[string]map[string][]byte   // name, then digest
	corrupt   map[string]bool                // digests served with a flipped byte
	stall     map[string]chan struct{}       // digests whose last byte waits for the channel to close
	down      bool
	status    func(r *http.Request) int
	requests  []string
	tokens    map[string]bool
}

type manifest struct {
	mediaType string
	body      []byte
}

// New starts a fake registry, closed when the test ends.
func New(t testing.TB) *Registry {
	g := &Registry{
		manifests: map[string]map[string]manifest{},
		blobs:     map[string]map[string][]byte{},
		corrupt:   map[string]bool{},
		stall:     map[string]chan struct{}{},
		tokens:    map[string]bool{},
	}
	g.Server = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.Close)
	return g
}

// Digest returns the sha256 digest of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PutBlob stores a blob in repository name and returns its digest.
func (g *Registry) PutBlob(name string, b []byte) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := Digest(b)
	if g.blobs[name] == nil {
		g.blobs[name] = map[string][]byte{}
	}
	g.blobs[name][d] = b
	return d
}

// PutManifest stores a manifest in repository name, under its digest and
// under tag if tag is not empty, and returns its digest.
func (g *Registry) PutManifest(name, tag, mediaType string, body []byte) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := Digest(body)
	if g.manifests[name] == nil {
		g.manifests[name] = map[string]manifest{}
	}
	g.manifests[name][d] = manifest{mediaType, body}
	if tag != "" {
		g.manifests[name][tag] = manifest{mediaType, body}
	}
	return d
}

// DeleteTag removes a tag.
func (g *Registry) DeleteTag(name, tag string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.manifests[name], tag)
}

// Image is an image pushed with PutImage.
type Image struct {
	Digest   string   // the manifest's digest
	Manifest []byte   // the manifest
	Config   string   // the config blob's digest
	Layers   []string // the layer blobs' digests
	Blobs    map[string][]byte
}

// PutImage stores an image with the given layers and a random config, so
// every call makes a distinct manifest, and tags it.
func (g *Registry) PutImage(name, tag string, layers ...[]byte) Image {
	cfg := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","nonce":%q}`, rand.Text()))
	img := Image{Config: g.PutBlob(name, cfg), Blobs: map[string][]byte{}}
	img.Blobs[img.Config] = cfg
	type desc struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	}
	m := struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Config        desc   `json:"config"`
		Layers        []desc `json:"layers"`
	}{2, MediaTypeManifest, desc{MediaTypeConfig, img.Config, len(cfg)}, []desc{}}
	for _, l := range layers {
		d := g.PutBlob(name, l)
		img.Layers = append(img.Layers, d)
		img.Blobs[d] = l
		m.Layers = append(m.Layers, desc{MediaTypeLayer, d, len(l)})
	}
	img.Manifest, _ = json.Marshal(m)
	img.Digest = g.PutManifest(name, tag, MediaTypeManifest, img.Manifest)
	return img
}

// Corrupt makes the registry serve blob or manifest d with one byte
// changed.
func (g *Registry) Corrupt(d string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.corrupt[d] = true
}

// Stall makes the registry hold back the last byte of blob d until the
// returned function is called.
func (g *Registry) Stall(d string) (release func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ch := make(chan struct{})
	g.stall[d] = ch
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// SetDown takes the registry down, so every connection is dropped, or
// brings it back.
func (g *Registry) SetDown(down bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.down = down
}

// SetStatus makes the registry answer requests for which f returns a
// status other than 0 with that status; nil removes it.
func (g *Registry) SetStatus(f func(r *http.Request) int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.status = f
}

// Requests returns the requests served so far, as "METHOD path".
func (g *Registry) Requests() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.requests)
}

// Count returns how many requests matched method and contained substr in
// their path.
func (g *Registry) Count(method, substr string) int {
	n := 0
	for _, r := range g.Requests() {
		m, p, _ := strings.Cut(r, " ")
		if m == method && strings.Contains(p, substr) {
			n++
		}
	}
	return n
}

func (g *Registry) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.requests = append(g.requests, r.Method+" "+r.URL.Path)
	down, status := g.down, g.status
	g.mu.Unlock()
	if down {
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				c.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}
	if status != nil {
		if s := status(r); s != 0 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(s)
			return
		}
	}
	if r.URL.Path == "/token" {
		g.token(w, r)
		return
	}
	if r.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	p, ok := strings.CutPrefix(r.URL.Path, "/v2/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	name, kind, arg := split(p)
	if !g.authorized(r, name) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fake",scope="repository:%s:pull"`,
			g.URL+"/token", name))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch kind {
	case "manifests":
		g.serveManifest(w, r, name, arg)
	case "blobs":
		g.serveBlob(w, r, name, arg)
	case "tags":
		g.serveTags(w, r, name)
	case "referrers":
		g.serveReferrers(w, r, name, arg)
	default:
		http.NotFound(w, r)
	}
}

// split splits a path below /v2/ into the name, the endpoint kind, and
// its argument.
func split(p string) (name, kind, arg string) {
	segs := strings.Split(p, "/")
	n := len(segs)
	if n >= 3 && segs[n-2] == "tags" && segs[n-1] == "list" {
		return strings.Join(segs[:n-2], "/"), "tags", ""
	}
	if n >= 3 {
		return strings.Join(segs[:n-2], "/"), segs[n-2], segs[n-1]
	}
	return "", "", ""
}

// token serves the token endpoint: it checks the credentials if the
// registry requires them, and issues a token for the scope.
func (g *Registry) token(w http.ResponseWriter, r *http.Request) {
	if g.Username != "" {
		u, p, ok := r.BasicAuth()
		if !ok || u != g.Username || p != g.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	scope := r.URL.Query().Get("scope")
	tok := rand.Text()
	g.mu.Lock()
	g.tokens[tok+" "+scope] = true
	g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"token": tok, "expires_in": 300})
}

func (g *Registry) authorized(r *http.Request, name string) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tokens[tok+" repository:"+name+":pull"]
}

func (g *Registry) serveManifest(w http.ResponseWriter, r *http.Request, name, ref string) {
	g.mu.Lock()
	m, ok := g.manifests[name][ref]
	corrupt := ok && g.corrupt[Digest(m.body)]
	noHeadDigest := g.NoHeadDigest
	g.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body := m.body
	d := Digest(body)
	if corrupt {
		body = flip(body)
	}
	w.Header().Set("Content-Type", m.mediaType)
	if r.Method != http.MethodHead || !noHeadDigest {
		w.Header().Set("Docker-Content-Digest", d)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

func (g *Registry) serveBlob(w http.ResponseWriter, r *http.Request, name, d string) {
	g.mu.Lock()
	b, ok := g.blobs[name][d]
	corrupt := g.corrupt[d]
	stall := g.stall[d]
	g.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if corrupt {
		b = flip(b)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Docker-Content-Digest", d)
	if r.Method == http.MethodHead {
		return
	}
	if stall != nil && len(b) > 0 {
		w.Write(b[:len(b)-1])
		w.(http.Flusher).Flush()
		select {
		case <-stall:
		case <-r.Context().Done():
			return
		}
		b = b[len(b)-1:]
	}
	w.Write(b)
}

func (g *Registry) serveTags(w http.ResponseWriter, r *http.Request, name string) {
	g.mu.Lock()
	var tags []string
	for ref := range g.manifests[name] {
		if !strings.Contains(ref, ":") {
			tags = append(tags, ref)
		}
	}
	exists := g.manifests[name] != nil
	g.mu.Unlock()
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	slices.Sort(tags)
	if last := r.URL.Query().Get("last"); last != "" {
		i, _ := slices.BinarySearch(tags, last)
		for i < len(tags) && tags[i] <= last {
			i++
		}
		tags = tags[i:]
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("n")); err == nil && n < len(tags) {
		tags = tags[:n]
		w.Header().Set("Link", fmt.Sprintf(`</v2/%s/tags/list?last=%s&n=%d>; rel="next"`, name, tags[n-1], n))
	}
	if tags == nil {
		tags = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"name": name, "tags": tags})
}

func (g *Registry) serveReferrers(w http.ResponseWriter, r *http.Request, name, subject string) {
	g.mu.Lock()
	enabled := g.Referrers
	type desc struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	}
	refs := []desc{}
	for ref, m := range g.manifests[name] {
		var doc struct {
			Subject *struct {
				Digest string `json:"digest"`
			} `json:"subject"`
		}
		if strings.Contains(ref, ":") && json.Unmarshal(m.body, &doc) == nil && doc.Subject != nil && doc.Subject.Digest == subject {
			refs = append(refs, desc{m.mediaType, ref, len(m.body)})
		}
	}
	g.mu.Unlock()
	if !enabled {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", MediaTypeIndex)
	json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 2, "mediaType": MediaTypeIndex, "manifests": refs})
}

func flip(b []byte) []byte {
	c := slices.Clone(b)
	if len(c) > 0 {
		c[len(c)-1] ^= 0xff
	}
	return c
}
