package repo

import (
	"strings"

	"github.com/terrabyteian/flint/internal/config"
)

// Every format but OCI serves a repository at /<format>/<repo>/, such as
// /pypi/<repo>/ or /npm/<repo>/. OCI stays at /v2/<repo>/, which its
// protocol fixes. The format segment keeps repository names, which are
// one namespace across formats, from colliding with flint's own paths,
// and lets the server dispatch a request to its format's handler without
// a lookup. A format's handler serves only repositories of its format:
// any other name, including a repository of another format, is a 404.

// Reserved are the first path segments flint serves itself, which no
// format may use as its segment.
var Reserved = []string{"v2", "api", "auth", "metrics", "healthz", "readyz", ".well-known", "ui", "static"}

// Prefix returns the path prefix under which format's repositories are
// served: "/v2/" for OCI and "/<format>/" for every other format.
func Prefix(format string) string {
	if format == config.FormatOCI {
		return "/v2/"
	}
	return "/" + format + "/"
}

// Path returns the path at which repository name of format is served,
// such as "/pypi/pypi-local/".
func Path(format, name string) string { return Prefix(format) + name + "/" }

// Split splits a request path under format's prefix into the repository
// name and the rest of the path after the "/" that follows the name;
// slash reports whether that "/" is there. ok is false if the path is
// not under the prefix.
func Split(format, path string) (name, rest string, slash, ok bool) {
	after, ok := strings.CutPrefix(path, Prefix(format))
	if !ok {
		return "", "", false, false
	}
	name, rest, slash = strings.Cut(after, "/")
	return name, rest, slash, true
}
