package gomod

import (
	"strings"
)

// Module paths and versions travel case-encoded in GOPROXY URLs, so that
// they stay distinct on case-insensitive file systems: every uppercase
// letter is written as "!" and the lowercase letter, such as
// "github.com/!azure/azure-sdk-for-go" for github.com/Azure/azure-sdk-for-go.
// flint keeps the encoded forms in cache keys and upstream URLs, and the
// decoded ones for the checksum database's records and member filters.

// maxPathLen bounds a module path, and maxVersionLen a version or query.
const (
	maxPathLen    = 1024
	maxVersionLen = 256
)

// unescape decodes a case-encoded module path or version: "!" and a
// lowercase letter stand for the uppercase letter. It fails on an
// uppercase letter, or a "!" that is not followed by a lowercase letter,
// so every path or version has one encoding.
func unescape(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	bang := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case bang:
			if c < 'a' || c > 'z' {
				return "", false
			}
			b.WriteByte(c - 'a' + 'A')
			bang = false
		case c == '!':
			bang = true
		case c >= 'A' && c <= 'Z':
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), !bang
}

// escape case-encodes a module path or version.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c - 'A' + 'a')
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// validPath reports whether p is a module path the go command would ask
// a module proxy for: slash-separated elements of ASCII letters, digits,
// and "-", ".", "_", and "~", none empty or starting or ending with a
// dot, the first a lowercase domain-like name with a dot in it.
func validPath(p string) bool {
	if p == "" || len(p) > maxPathLen {
		return false
	}
	for i, elem := range strings.Split(p, "/") {
		if elem == "" || elem[0] == '.' || elem[len(elem)-1] == '.' {
			return false
		}
		for j := 0; j < len(elem); j++ {
			c := elem[j]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-':
			case i > 0 && (c >= 'A' && c <= 'Z' || c == '_' || c == '~'):
			default:
				return false
			}
		}
		if i == 0 && (!strings.Contains(elem, ".") || elem[0] == '-') {
			return false
		}
	}
	return true
}

// validVersion reports whether v is a version or version query the go
// command would ask a module proxy for, such as "v1.2.3", a
// pseudo-version, "v2.0.0+incompatible", a branch name, or a commit hash:
// ASCII letters, digits, and "-", ".", "_", "~", and "+", not starting
// with a dot.
func validVersion(v string) bool {
	if v == "" || len(v) > maxVersionLen || v[0] == '.' {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~' || c == '+':
		default:
			return false
		}
	}
	return true
}

// canonical reports whether v is a canonical module version: a semantic
// version "v<major>.<minor>.<patch>", optionally with a pre-release, such
// as a pseudo-version, and optionally "+incompatible", in the one form
// the go command writes. Only canonical versions name immutable content;
// anything else is a query, whose answer can change.
func canonical(v string) bool {
	v = strings.TrimSuffix(v, "+incompatible")
	v, ok := strings.CutPrefix(v, "v")
	if !ok {
		return false
	}
	core, pre, hasPre := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if !numeric(p) {
			return false
		}
	}
	if !hasPre {
		return true
	}
	for _, id := range strings.Split(pre, ".") {
		if id == "" {
			return false
		}
		digits := true
		for i := 0; i < len(id); i++ {
			switch c := id[i]; {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				digits = false
			default:
				return false
			}
		}
		if digits && !numeric(id) {
			return false
		}
	}
	return true
}

// numeric reports whether s is a decimal number without leading zeros.
func numeric(s string) bool {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validTile reports whether p, the path after a checksum database's
// "tile/", names a tile: "<height>/<level>/<index>", or with
// "<level>" "data" for a data tile, optionally ending ".p/<width>" for a
// partial tile, where index is three-digit groups, all but the last
// prefixed with "x", such as "8/0/x123/456.p/12".
func validTile(p string) bool {
	parts := strings.Split(p, "/")
	if len(parts) < 3 || !numeric(parts[0]) || parts[1] != "data" && !numeric(parts[1]) {
		return false
	}
	idx := parts[2:]
	if n := len(idx); n >= 2 && strings.HasSuffix(idx[n-2], ".p") {
		if !numeric(idx[n-1]) || idx[n-1] == "0" {
			return false
		}
		idx = idx[:n-1]
		idx[len(idx)-1] = strings.TrimSuffix(idx[len(idx)-1], ".p")
	}
	for i, g := range idx {
		if i < len(idx)-1 {
			var ok bool
			if g, ok = strings.CutPrefix(g, "x"); !ok {
				return false
			}
		}
		if len(g) != 3 || g[0] < '0' || g[0] > '9' || g[1] < '0' || g[1] > '9' || g[2] < '0' || g[2] > '9' {
			return false
		}
	}
	return true
}
