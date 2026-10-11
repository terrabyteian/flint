package generic

import (
	"bytes"
	"html/template"
	"net/url"
	"strings"
)

// listingPage is the HTML form of a listing: one link per entry,
// relative, so it works however flint is reached, and wget -r can follow
// it.
var listingPage = template.Must(template.New("listing").Parse(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="robots" content="noindex"><title>{{.Title}}</title></head>
<body>
<h1>{{.Title}}</h1>
<ul>
{{- if .Parent}}
<li><a href="../">../</a></li>
{{- end}}
{{- range .Entries}}
<li><a href="{{.Href}}">{{.Name}}</a></li>
{{- end}}
</ul>
</body>
</html>
`))

// renderListing renders l as HTML.
func renderListing(l listing) ([]byte, error) {
	type link struct{ Name, Href string }
	data := struct {
		Title   string
		Parent  bool
		Entries []link
	}{Title: "Index of " + l.Repository + "/" + l.Path, Parent: l.Path != ""}
	for _, e := range l.Entries {
		href := escapePath(e.Name)
		if first, _, _ := strings.Cut(href, "/"); strings.Contains(first, ":") {
			// A relative link such as "a:b" would be taken for a URL with
			// the scheme "a".
			href = "./" + href
		}
		data.Entries = append(data.Entries, link{e.Name, href})
	}
	var b bytes.Buffer
	if err := listingPage.Execute(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// escapePath escapes each segment of a path for a URL; a trailing "/"
// stays.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
