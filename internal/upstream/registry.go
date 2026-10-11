package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
)

// ManifestAccept is the Accept header sent for manifests: every manifest
// type flint serves, so the upstream answers with the same document
// whichever client asked.
var ManifestAccept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// MaxManifestSize bounds a manifest fetched from upstream.
const MaxManifestSize = 4 << 20

// Descriptor describes upstream content.
type Descriptor struct {
	MediaType string
	Digest    blob.Digest
	Size      int64 // -1 if unknown
}

// Manifest is a manifest fetched from upstream and verified against its
// digest.
type Manifest struct {
	Descriptor
	Body []byte
}

// PullScope returns the token scope for pulling repository name.
func PullScope(name string) string { return "repository:" + name + ":pull" }

// ManifestPath returns the API path of a manifest of repository name.
func ManifestPath(name, ref string) string { return "/v2/" + name + "/manifests/" + ref }

// BlobPath returns the API path of a blob of repository name.
func BlobPath(name string, d blob.Digest) string { return "/v2/" + name + "/blobs/" + d.String() }

// GetManifest fetches manifest ref, a tag or digest, of repository name.
// The body is verified against the digest: the reference when it is a
// digest, and the Docker-Content-Digest header when the upstream sends
// one. A mismatch is ErrDigestMismatch.
func (c *Client) GetManifest(ctx context.Context, name, ref string) (*Manifest, error) {
	var want blob.Digest
	if strings.Contains(ref, ":") {
		d, err := blob.ParseDigest(ref)
		if err != nil {
			return nil, err
		}
		want = d
	}
	path := ManifestPath(name, ref)
	resp, err := c.Do(ctx, http.MethodGet, path, nil, http.Header{"Accept": {ManifestAccept}}, PullScope(name))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	op := "GET " + path
	if resp.ContentLength > MaxManifestSize {
		return nil, &Error{Op: op, Err: ErrTooLarge}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxManifestSize+1))
	if err != nil {
		return nil, &Error{Op: op, Err: fmt.Errorf("%w: reading the manifest: %v", ErrUnavailable, err)}
	}
	if len(body) > MaxManifestSize {
		return nil, &Error{Op: op, Err: ErrTooLarge}
	}
	got := blob.FromBytes(body)
	if hd := resp.Header.Get("Docker-Content-Digest"); hd != "" && want.IsZero() {
		if d, err := blob.ParseDigest(hd); err == nil {
			want = d
		}
	}
	if !want.IsZero() && got != want {
		return nil, &Error{Op: op, Err: fmt.Errorf("%w: got %s, want %s", ErrDigestMismatch, got, want)}
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return &Manifest{Descriptor: Descriptor{MediaType: mt, Digest: got, Size: int64(len(body))}, Body: body}, nil
}

// ErrNoDigest means a HEAD response did not name the manifest's digest.
var ErrNoDigest = errors.New("the upstream did not report the manifest's digest")

// HeadManifest asks for the descriptor of manifest ref of repository
// name without fetching it. Some registries, Docker Hub among them, do
// not count HEAD requests against pull rate limits. If the upstream does
// not report the digest, the error says so and the caller should GET the
// manifest instead.
func (c *Client) HeadManifest(ctx context.Context, name, ref string) (Descriptor, error) {
	path := ManifestPath(name, ref)
	resp, err := c.Do(ctx, http.MethodHead, path, nil, http.Header{"Accept": {ManifestAccept}}, PullScope(name))
	if err != nil {
		return Descriptor{}, err
	}
	resp.Body.Close()
	d, err := blob.ParseDigest(resp.Header.Get("Docker-Content-Digest"))
	if err != nil {
		return Descriptor{}, &Error{Op: "HEAD " + path, Err: ErrNoDigest}
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return Descriptor{MediaType: mt, Digest: d, Size: resp.ContentLength}, nil
}

// GetBlob starts fetching blob d of repository name and returns its
// body, which the caller must close, and its size, or -1 if the upstream
// does not say. The body is not verified; read it through NewVerifier,
// CopyVerified, or a blob store upload committed under d.
func (c *Client) GetBlob(ctx context.Context, name string, d blob.Digest) (io.ReadCloser, int64, error) {
	resp, err := c.Do(ctx, http.MethodGet, BlobPath(name, d), nil, nil, PullScope(name))
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// HeadBlob reports whether the upstream serves blob d in repository name,
// and its size, or -1 if the upstream does not say.
func (c *Client) HeadBlob(ctx context.Context, name string, d blob.Digest) (int64, error) {
	resp, err := c.Do(ctx, http.MethodHead, BlobPath(name, d), nil, nil, PullScope(name))
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	if s := resp.Header.Get("Content-Length"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n, nil
		}
	}
	return -1, nil
}

// Get fetches an API path of repository name, such as its tag list or a
// referrers index, with the query given, and returns the response for
// the caller to read and close.
func (c *Client) Get(ctx context.Context, name, path string, query url.Values) (*http.Response, error) {
	return c.Do(ctx, http.MethodGet, path, query, nil, PullScope(name))
}
