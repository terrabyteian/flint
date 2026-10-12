// Package browse defines what the web UI shows of a repository's
// contents: read-only views that each format package provides over its
// own records, in shapes common to every format.
//
// Three shapes cover the formats:
//
//   - Images, for OCI repositories: image names, their tags and
//     manifests, and each manifest's layers, platforms, and referrers.
//   - Packages, for repositories of named, versioned packages: PyPI
//     projects, npm packages, Maven artifacts, and Cargo crates, each
//     with its versions and their files.
//   - Files, for repositories that are trees of paths: hosted generic
//     files repositories, and what proxy repositories of path-addressed
//     formats have cached.
//
// The UI checks permissions before it calls a view; a view checks only
// that the repository is one of its own. Views never contact an
// upstream: a proxy repository shows what it has cached.
package browse

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrNotFound means a repository, package, image, or manifest does not
// exist, or is not one the view serves.
var ErrNotFound = errors.New("not found")

// Query selects a page of a listing.
type Query struct {
	// Filter, if set, keeps only the entries whose names contain it,
	// ignoring case.
	Filter string
	// After, if set, starts the page after the entry of this name: the
	// last name of the previous page.
	After string
	// Limit is the most entries to return.
	Limit int
}

// Match reports whether name passes q's filter.
func (q Query) Match(name string) bool {
	return q.Filter == "" || strings.Contains(strings.ToLower(name), strings.ToLower(q.Filter))
}

// Full reports whether a page of n entries is full, so that a listing
// that finds one more entry reports more.
func (q Query) Full(n int) bool { return q.Limit > 0 && n >= q.Limit }

// Package is a package in a listing.
type Package struct {
	Name string
	// Latest is the latest version, if known.
	Latest string
	// Versions is the number of versions.
	Versions int
	// Updated is when the package last changed, if known.
	Updated time.Time
	// Summary describes the package, if known.
	Summary string
}

// PackageDetail is a package with its versions.
type PackageDetail struct {
	Name    string
	Summary string
	// Tags name versions, as npm's dist-tags do.
	Tags []Tag
	// Versions are newest first.
	Versions []Version
}

// Tag is a name for a version.
type Tag struct {
	Name, Version string
}

// Version is a version of a package and its files.
type Version struct {
	Version   string
	Published time.Time
	// Notes describe the version's state, such as "yanked" or
	// "deprecated: use 2.0".
	Notes []string
	Files []File
}

// File is a file of a package version.
type File struct {
	Name string
	Size int64
	// Digest is the file's "sha256:<hex>" digest.
	Digest string
	// Time is when the file was published or cached.
	Time time.Time
	// URL is the path, from the server's root and escaped, that clients
	// download the file from, or "" if it has none of its own.
	URL string
}

// Entry is a file or directory in a Files listing.
type Entry struct {
	// Name is the entry's name within its directory; a directory's ends
	// in "/".
	Name   string
	Dir    bool
	Size   int64
	Digest string
	Time   time.Time
	// URL is the download path of a file, as for File.URL.
	URL string
}

// Image is an image name in an OCI repository.
type Image struct {
	// Name is the image name below the repository, such as "team/app".
	Name      string
	Tags      int
	Manifests int
	// Updated is when a manifest of the image was last pushed, if known.
	Updated time.Time
}

// ImageDetail is an image's tags and manifests.
type ImageDetail struct {
	Name string
	// Tags are by name.
	Tags []ImageTag
	// Manifests are every manifest stored under the image, newest first,
	// including untagged ones such as the platform manifests of an index
	// and signatures.
	Manifests []ManifestSummary
}

// ImageTag is a tag and the manifest it points at.
type ImageTag struct {
	Name, Digest string
}

// ManifestSummary describes a manifest in an image's listing.
type ManifestSummary struct {
	Digest       string
	MediaType    string
	ArtifactType string
	Size         int64
	Pushed       time.Time
	Tags         []string
	// Subject is the digest of the manifest this one refers to, such as
	// the image a signature signs, or "".
	Subject string
	// Index reports whether it is an index or manifest list.
	Index bool
}

// Manifest is one manifest with what it references.
type Manifest struct {
	ManifestSummary
	// Config is an image manifest's configuration, nil for an index.
	Config *Descriptor
	// Layers are an image manifest's layers.
	Layers []Descriptor
	// Manifests are an index's children, with their platforms.
	Manifests []Descriptor
	// Annotations are the manifest's annotations, by key.
	Annotations []Annotation
	// Referrers are the manifests that name this one as their subject,
	// such as signatures and attestations.
	Referrers []Descriptor
	// TotalSize is the size of the manifest and the blobs it
	// references: for an image manifest, its config and layers.
	TotalSize int64
}

// Descriptor names content that a manifest references.
type Descriptor struct {
	MediaType    string
	ArtifactType string
	Digest       string
	Size         int64
	// Platform is an index child's platform, such as "linux/arm64/v8".
	Platform    string
	Annotations []Annotation
	// Stored reports, for a child manifest or referrer, whether it is
	// stored under the same image, so the UI can link to it.
	Stored bool
}

// Annotation is an OCI annotation.
type Annotation struct {
	Key, Value string
}

// Images is the view of OCI repositories.
type Images interface {
	// ListImages lists the image names of repository repo in name
	// order, and reports whether there are more after the page.
	ListImages(repo string, q Query) ([]Image, bool, error)
	// Image returns an image's tags and manifests.
	Image(repo, name string) (*ImageDetail, error)
	// Manifest returns a manifest stored under an image, with what it
	// references and its referrers.
	Manifest(ctx context.Context, repo, name, digest string) (*Manifest, error)
}

// Packages is the view of repositories of named, versioned packages.
type Packages interface {
	// ListPackages lists the packages of repository repo in name order,
	// and reports whether there are more after the page.
	ListPackages(repo string, q Query) ([]Package, bool, error)
	// Package returns a package with its versions and files.
	Package(ctx context.Context, repo, name string) (*PackageDetail, error)
}

// Files is the view of repositories that are trees of paths.
type Files interface {
	// ListFiles lists the entries of directory dir, "" for the root or
	// a path ending in "/", of repository repo, directories and files
	// in name order, and reports whether there are more after the page.
	ListFiles(repo, dir string, q Query) ([]Entry, bool, error)
}
