package pypi

import (
	"bytes"
	"encoding/json"
	"errors"
	"html"
	"mime"
	"net/url"
	"strings"
	"time"
)

// upstreamAccept is the Accept header of project page requests: the JSON
// form first (PEP 691), then HTML, which every index serves.
const upstreamAccept = mtSimpleJSON + ", " + mtSimpleHTML + ";q=0.2, " + mtHTML + ";q=0.1"

// maxPageSize bounds an upstream project page. pypi.org's largest are
// tens of megabytes in HTML.
const maxPageSize = 128 << 20

// errBadPage means an upstream project page could not be read.
var errBadPage = errors.New("the upstream project page is not a valid simple API page")

// parsePage reads an upstream project page of project, served with
// Content-Type ct from base, the page's URL, which relative links
// resolve against.
func parsePage(body []byte, ct string, base *url.URL, project string) (*projectDoc, error) {
	mt, _, _ := mime.ParseMediaType(ct)
	if strings.HasSuffix(mt, "+json") || mt == "application/json" || mt == "" && bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return parseJSONPage(body, base, project)
	}
	return parseHTMLPage(body, base, project), nil
}

// parseJSONPage reads a PEP 691 JSON project page.
func parseJSONPage(body []byte, base *url.URL, project string) (*projectDoc, error) {
	var page struct {
		Meta struct {
			APIVersion string `json:"api-version"`
		} `json:"meta"`
		Versions []string `json:"versions"`
		Files    []struct {
			Filename         string            `json:"filename"`
			URL              string            `json:"url"`
			Hashes           map[string]string `json:"hashes"`
			RequiresPython   string            `json:"requires-python"`
			CoreMetadata     json.RawMessage   `json:"core-metadata"`
			DistInfoMetadata json.RawMessage   `json:"dist-info-metadata"`
			Yanked           json.RawMessage   `json:"yanked"`
			Size             *int64            `json:"size"`
			UploadTime       string            `json:"upload-time"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, errBadPage
	}
	if major, _, _ := strings.Cut(page.Meta.APIVersion, "."); major != "1" {
		return nil, errBadPage
	}
	p := &projectDoc{Format: pageFormat, Name: project, Versions: page.Versions}
	for _, pf := range page.Files {
		f := newUpstreamFile(base, pf.URL, pf.Filename, false, project)
		if f == nil {
			continue
		}
		if s := strings.ToLower(pf.Hashes["sha256"]); validSHA256(s) {
			f.SHA256 = s
		}
		if s := strings.ToLower(pf.Hashes["md5"]); len(s) == 32 {
			f.MD5 = s
		}
		if s := strings.ToLower(pf.Hashes["blake2b_256"]); len(s) == 64 {
			f.Blake2b256 = s
		}
		f.RequiresPython = pf.RequiresPython
		md := pf.CoreMetadata
		if len(md) == 0 || string(md) == "null" {
			md = pf.DistInfoMetadata
		}
		switch {
		case string(md) == "true":
			f.Metadata = true
		case len(md) > 0 && md[0] == '{':
			var h map[string]string
			if json.Unmarshal(md, &h) == nil {
				f.Metadata = true
				if s := strings.ToLower(h["sha256"]); validSHA256(s) {
					f.MetadataSHA256 = s
				}
			}
		}
		var reason string
		switch {
		case string(pf.Yanked) == "true":
			f.Yanked = true
		case len(pf.Yanked) > 0 && pf.Yanked[0] == '"' && json.Unmarshal(pf.Yanked, &reason) == nil:
			f.Yanked, f.YankedReason = true, reason
		}
		if pf.Size != nil && *pf.Size >= 0 {
			f.Size = *pf.Size
		}
		if t, err := time.Parse(time.RFC3339Nano, pf.UploadTime); err == nil {
			f.UploadTime = t.UTC()
		}
		p.Files = append(p.Files, f)
	}
	p.finish()
	return p, nil
}

// newUpstreamFile starts the entry of an upstream file from its link,
// resolved against base, and its name; nil if either is unusable, or if
// the name does not belong to project, as PyPI requires it to. A JSON
// page names the file; in an HTML page, the name is the link's last path
// component, which PEP 503 requires the anchor text to match.
func newUpstreamFile(base *url.URL, href, name string, fromLink bool, project string) *file {
	u, err := base.Parse(href)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil
	}
	u.Fragment, u.RawFragment = "", ""
	filename := name
	if fromLink {
		ep := u.EscapedPath()
		filename, err = url.PathUnescape(ep[strings.LastIndexByte(ep, '/')+1:])
		if err != nil {
			return nil
		}
	}
	if !validFilename(filename) {
		return nil
	}
	d, ok := parseFilename(filename, project)
	if !ok {
		return nil
	}
	return &file{Filename: filename, URL: u.String(), Size: -1, Version: d.Version}
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// parseHTMLPage reads a PEP 503 HTML project page: every anchor is a
// file, with its hash in the URL fragment and the PEP 592 and PEP 658
// data attributes.
func parseHTMLPage(body []byte, base *url.URL, project string) *projectDoc {
	p := &projectDoc{Format: pageFormat, Name: project}
	for _, a := range anchors(string(body)) {
		href, ok := a.attrs["href"]
		if !ok {
			continue
		}
		f := newUpstreamFile(base, href, a.text, true, project)
		if f == nil {
			continue
		}
		if u, err := base.Parse(href); err == nil {
			if algo, sum, ok := strings.Cut(u.Fragment, "="); ok && algo == "sha256" && validSHA256(strings.ToLower(sum)) {
				f.SHA256 = strings.ToLower(sum)
			}
		}
		f.RequiresPython = a.attrs["data-requires-python"]
		if reason, ok := a.attrs["data-yanked"]; ok {
			f.Yanked, f.YankedReason = true, reason
		}
		md, ok := a.attrs["data-core-metadata"]
		if !ok {
			md, ok = a.attrs["data-dist-info-metadata"]
		}
		switch {
		case !ok || md == "false":
		case strings.HasPrefix(md, "sha256="):
			f.Metadata = true
			if s := strings.ToLower(strings.TrimPrefix(md, "sha256=")); validSHA256(s) {
				f.MetadataSHA256 = s
			}
		default:
			f.Metadata = true
		}
		p.Files = append(p.Files, f)
	}
	p.finish()
	return p
}

// anchor is an <a> element: its attributes, unescaped and keyed by
// lowercased name, and its text.
type anchor struct {
	attrs map[string]string
	text  string
}

// anchors finds the <a> elements of an HTML document. It is a small
// tokenizer, enough for the simple API's pages: it skips comments,
// reads quoted and unquoted attribute values, and unescapes character
// references.
func anchors(s string) []anchor {
	var out []anchor
	for {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			return out
		}
		s = s[i:]
		if strings.HasPrefix(s, "<!--") {
			end := strings.Index(s, "-->")
			if end < 0 {
				return out
			}
			s = s[end+3:]
			continue
		}
		if len(s) < 3 || (s[1] != 'a' && s[1] != 'A') || !isSpace(s[2]) && s[2] != '>' {
			s = s[1:]
			continue
		}
		attrs, rest, ok := parseAttrs(s[2:])
		if !ok {
			return out
		}
		end := indexFold(rest, "</a")
		if end < 0 {
			return out
		}
		text := stripTags(rest[:end])
		out = append(out, anchor{attrs: attrs, text: strings.TrimSpace(html.UnescapeString(text))})
		s = rest[end:]
	}
}

// parseAttrs parses attributes up to the closing ">" of a tag.
func parseAttrs(s string) (map[string]string, string, bool) {
	attrs := map[string]string{}
	for {
		s = strings.TrimLeft(s, " \t\r\n\f/")
		if s == "" {
			return nil, "", false
		}
		if s[0] == '>' {
			return attrs, s[1:], true
		}
		n := 0
		for n < len(s) && !isSpace(s[n]) && s[n] != '=' && s[n] != '>' && s[n] != '/' {
			n++
		}
		if n == 0 {
			s = s[1:]
			continue
		}
		name := strings.ToLower(s[:n])
		s = strings.TrimLeft(s[n:], " \t\r\n\f")
		val := ""
		if strings.HasPrefix(s, "=") {
			s = strings.TrimLeft(s[1:], " \t\r\n\f")
			if s != "" && (s[0] == '"' || s[0] == '\'') {
				end := strings.IndexByte(s[1:], s[0])
				if end < 0 {
					return nil, "", false
				}
				val, s = s[1:1+end], s[2+end:]
			} else {
				m := 0
				for m < len(s) && !isSpace(s[m]) && s[m] != '>' {
					m++
				}
				val, s = s[:m], s[m:]
			}
		}
		if _, dup := attrs[name]; !dup {
			attrs[name] = html.UnescapeString(val)
		}
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

// indexFold returns the index of the first case-insensitive match of
// sub, which must be lowercase ASCII, in s, or -1.
func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}

// stripTags drops the tags in an anchor's content.
func stripTags(s string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			return b.String()
		}
		s = s[i+j+1:]
	}
}
