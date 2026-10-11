package oci

import (
	"strings"
)

// endpoint identifies a /v2/<name>/... endpoint.
type endpoint int

const (
	epBlob        endpoint = iota + 1 // /v2/<name>/blobs/<digest>
	epUploadStart                     // /v2/<name>/blobs/uploads/
	epUpload                          // /v2/<name>/blobs/uploads/<id>
	epManifest                        // /v2/<name>/manifests/<reference>
	epTags                            // /v2/<name>/tags/list
	epReferrers                       // /v2/<name>/referrers/<digest>
)

// maxNameLen bounds a full repository name, as Docker clients do.
const maxNameLen = 255

// splitPath splits the part of a request path after /v2/ into the
// repository name, the endpoint, and the endpoint's argument (a digest,
// reference, or upload ID). Names may contain any path segments, so the
// endpoint is recognized from the end of the path.
func splitPath(p string) (name string, ep endpoint, arg string, ok bool) {
	segs := strings.Split(p, "/")
	n := len(segs)
	at := func(i int) string { // segment i from the end, 1-based
		if i > n {
			return ""
		}
		return segs[n-i]
	}
	join := func(drop int) string { return strings.Join(segs[:n-drop], "/") }
	switch {
	case n >= 4 && at(3) == "blobs" && at(2) == "uploads":
		if at(1) == "" {
			return join(3), epUploadStart, "", true
		}
		return join(3), epUpload, at(1), true
	case n >= 3 && at(2) == "blobs" && at(1) == "uploads":
		return join(2), epUploadStart, "", true
	case n >= 3 && at(2) == "blobs":
		return join(2), epBlob, at(1), true
	case n >= 3 && at(2) == "manifests":
		return join(2), epManifest, at(1), true
	case n >= 3 && at(2) == "tags" && at(1) == "list":
		return join(2), epTags, "", true
	case n >= 3 && at(2) == "referrers":
		return join(2), epReferrers, at(1), true
	}
	return "", 0, "", false
}

// validName reports whether s is a valid OCI repository name: path
// components of lowercase letters and digits, separated within a
// component by ".", "_", "__", or a run of "-".
func validName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for c := range strings.SplitSeq(s, "/") {
		if !validComponent(c) {
			return false
		}
	}
	return true
}

func validComponent(c string) bool {
	if c == "" || !alnum(c[0]) || !alnum(c[len(c)-1]) {
		return false
	}
	for i := 0; i < len(c); i++ {
		if alnum(c[i]) {
			continue
		}
		// A separator run: ".", "_", "__", or "-"+.
		j := i
		for j < len(c) && !alnum(c[j]) {
			j++
		}
		switch sep := c[i:j]; {
		case sep == "." || sep == "_" || sep == "__":
		case strings.Trim(sep, "-") == "":
		default:
			return false
		}
		i = j - 1
	}
	return true
}

func alnum(c byte) bool { return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' }

// validTag reports whether s matches [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}.
func validTag(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '_':
		case (c == '.' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}
