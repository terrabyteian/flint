package ui

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/auth"
	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/config"
)

// pageSize is the most entries a listing shows at once.
const pageSize = 100

// navigation entries.
const (
	navRepos   = "repos"
	navAccount = "account"
	navAdmin   = "admin"
	navSignIn  = "signin"
)

func (h *Handler) funcs() template.FuncMap {
	return template.FuncMap{
		"size":  formatSize,
		"when":  formatTime,
		"short": shortDigest,
		"join":  strings.Join,
		"inc":   func(i int) int { return i + 1 },
		"list":  func(s ...string) []string { return s },
	}
}

// formatSize formats a byte count in binary units.
func formatSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// shortDigest abbreviates a digest such as "sha256:0123..." to its
// algorithm and the first 12 hex digits.
func shortDigest(d string) string {
	alg, hex, ok := strings.Cut(d, ":")
	if !ok || len(hex) <= 12 {
		return d
	}
	return alg + ":" + hex[:12]
}

// escapePath escapes each "/"-separated segment of p for a URL path.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

func repoHref(name string) string { return "/ui/repositories/" + url.PathEscape(name) }

func packageHref(repo, name string) string {
	return repoHref(repo) + "/packages/" + escapePath(name)
}

func imageHref(repo, name string) string { return repoHref(repo) + "/images/" + escapePath(name) }

func manifestHref(repo, name, digest string) string {
	return repoHref(repo) + "/manifests/" + url.PathEscape(digest) + "/" + escapePath(name)
}

// withQuery returns href with the query parameters kv, name and value
// pairs, whose values are not empty.
func withQuery(href string, kv ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			q.Set(kv[i], kv[i+1])
		}
	}
	if len(q) == 0 {
		return href
	}
	return href + "?" + q.Encode()
}

// RepoRow is a repository in a list.
type RepoRow struct {
	// Format is the format's display name, and Key its configuration
	// name, such as "PyPI" and "pypi".
	Name, Format, Key, Type, Href, Detail string
	Anonymous                             bool
}

func (h *Handler) row(rc *config.Repository) RepoRow {
	r := RepoRow{Name: rc.Name, Format: formatName(rc.Format), Key: rc.Format, Type: rc.Type, Href: repoHref(rc.Name), Anonymous: rc.AnonymousPull}
	switch {
	case rc.Proxy != nil:
		r.Detail = "Proxy of " + rc.Proxy.URL
	case rc.Virtual != nil:
		names := make([]string, 0, len(rc.Virtual.Members))
		for _, m := range rc.Virtual.Members {
			names = append(names, m.Name)
		}
		r.Detail = "Members: " + strings.Join(names, ", ")
	}
	return r
}

// formatName is a format's display name.
func formatName(f string) string {
	switch f {
	case config.FormatOCI:
		return "OCI"
	case config.FormatPyPI:
		return "PyPI"
	case config.FormatNPM:
		return "npm"
	case config.FormatMaven:
		return "Maven"
	case config.FormatGo:
		return "Go"
	case config.FormatCargo:
		return "Cargo"
	case config.FormatGeneric:
		return "Generic"
	}
	return f
}

type homeData struct {
	Repos  []RepoRow
	Filter string
	// Hidden reports whether an anonymous client sees only some
	// repositories.
	Hidden bool
}

func (homeData) nav() string { return navRepos }

func (h *Handler) home(rq *request) {
	filter := strings.TrimSpace(rq.r.URL.Query().Get("q"))
	q := browse.Query{Filter: filter}
	d := homeData{Filter: filter}
	for i := range h.repos {
		rc := &h.repos[i]
		if !rq.canRead(rc.Name) {
			d.Hidden = d.Hidden || !rq.signedIn()
			continue
		}
		if q.Match(rc.Name) || q.Match(rc.Format) || q.Match(rc.Type) {
			d.Repos = append(d.Repos, h.row(rc))
		}
	}
	slices.SortFunc(d.Repos, func(a, b RepoRow) int { return strings.Compare(a.Name, b.Name) })
	rq.render(http.StatusOK, "home", "Repositories", d)
}

// Contents kinds of a repository page.
const (
	kindImages   = "images"
	kindPackages = "packages"
	kindFiles    = "files"
	kindMembers  = "members"
	kindNone     = "none"
)

// contentsOf returns how repository rc's contents are browsed.
func (h *Handler) contentsOf(rc *config.Repository) string {
	switch {
	case rc.Type == config.TypeVirtual:
		return kindMembers
	case rc.Format == config.FormatOCI && h.opts.Images != nil:
		return kindImages
	case rc.Type == config.TypeHosted && h.opts.Packages[rc.Format] != nil,
		rc.Format == config.FormatPyPI && h.opts.Packages[rc.Format] != nil:
		return kindPackages
	case rc.Type == config.TypeHosted && h.opts.Files[rc.Format] != nil:
		return kindFiles
	case rc.Type == config.TypeProxy && h.opts.Cache != nil:
		return kindFiles
	}
	return kindNone
}

// files returns the view of a repository whose contents are files.
func (h *Handler) files(rc *config.Repository) browse.Files {
	if rc.Type == config.TypeProxy {
		return h.opts.Cache
	}
	return h.opts.Files[rc.Format]
}

type packageRow struct {
	browse.Package
	Href string
}

type imageRow struct {
	browse.Image
	Href string
}

type entryRow struct {
	browse.Entry
	Href string
}

type memberRow struct {
	Name, Type, Href string
	Include, Exclude []string
	PublishTo        bool
}

type crumb struct {
	Name, Href string
}

type repoData struct {
	RepoRow
	Repo     *config.Repository
	Kind     string
	Snippets []snippet
	Filter   string
	// Next is the link to the next page of a listing, if there is one.
	Next     string
	Images   []imageRow
	Packages []packageRow
	Entries  []entryRow
	Members  []memberRow
	// Dir and Crumbs locate a files listing's directory.
	Dir    string
	Crumbs []crumb
	// Protected reports whether a virtual repository has
	// dependency-confusion protection.
	Protected bool
	// Cached reports whether a files listing shows a proxy cache.
	Cached bool
}

func (repoData) nav() string { return navRepos }

func (h *Handler) repository(rq *request) {
	rc := rq.readable()
	if rc == nil {
		return
	}
	query := rq.r.URL.Query()
	q := browse.Query{Filter: strings.TrimSpace(query.Get("q")), After: query.Get("after"), Limit: pageSize}
	d := repoData{RepoRow: h.row(rc), Repo: rc, Kind: h.contentsOf(rc), Snippets: h.repoSnippets(rq, rc), Filter: q.Filter}
	next := func(last string) {
		d.Next = withQuery(d.Href, "q", q.Filter, "dir", d.Dir, "after", last)
	}
	switch d.Kind {
	case kindImages:
		imgs, more, err := h.opts.Images.ListImages(rc.Name, q)
		if err != nil {
			rq.browseError(err)
			return
		}
		for _, img := range imgs {
			d.Images = append(d.Images, imageRow{Image: img, Href: imageHref(rc.Name, img.Name)})
		}
		if more {
			next(imgs[len(imgs)-1].Name)
		}
	case kindPackages:
		pkgs, more, err := h.opts.Packages[rc.Format].ListPackages(rc.Name, q)
		if err != nil {
			rq.browseError(err)
			return
		}
		for _, p := range pkgs {
			d.Packages = append(d.Packages, packageRow{Package: p, Href: packageHref(rc.Name, p.Name)})
		}
		if more {
			next(pkgs[len(pkgs)-1].Name)
		}
	case kindFiles:
		d.Dir = query.Get("dir")
		if d.Dir != "" && !strings.HasSuffix(d.Dir, "/") {
			d.Dir += "/"
		}
		d.Cached = rc.Type == config.TypeProxy
		entries, more, err := h.files(rc).ListFiles(rc.Name, d.Dir, q)
		if err != nil {
			rq.browseError(err)
			return
		}
		d.Crumbs = []crumb{{Name: rc.Name, Href: d.Href}}
		acc := ""
		for _, part := range strings.Split(strings.TrimSuffix(d.Dir, "/"), "/") {
			if part == "" {
				continue
			}
			acc += part + "/"
			d.Crumbs = append(d.Crumbs, crumb{Name: part, Href: withQuery(d.Href, "dir", acc)})
		}
		for _, e := range entries {
			row := entryRow{Entry: e, Href: e.URL}
			if e.Dir {
				row.Href = withQuery(d.Href, "dir", d.Dir+e.Name)
			}
			d.Entries = append(d.Entries, row)
		}
		if more {
			next(entries[len(entries)-1].Name)
		}
	case kindMembers:
		d.Protected = rc.Virtual.Protected()
		for _, m := range rc.Virtual.Members {
			mr := memberRow{Name: m.Name, Include: m.Include, Exclude: m.Exclude, PublishTo: m.Name == rc.Virtual.PublishTo}
			if mc := h.byName[m.Name]; mc != nil {
				mr.Type = mc.Type
				if rq.canRead(m.Name) {
					mr.Href = repoHref(m.Name)
				}
			}
			d.Members = append(d.Members, mr)
		}
	}
	rq.render(http.StatusOK, "repository", rc.Name, d)
}

type packageData struct {
	RepoRow
	Package  *browse.PackageDetail
	PkgHref  string
	Snippets []snippet
}

func (packageData) nav() string { return navRepos }

func (h *Handler) packagePage(rq *request) {
	rc := rq.readable()
	if rc == nil {
		return
	}
	if h.contentsOf(rc) != kindPackages {
		rq.notFound()
		return
	}
	p, err := h.opts.Packages[rc.Format].Package(rq.r.Context(), rc.Name, rq.r.PathValue("name"))
	if err != nil {
		rq.browseError(err)
		return
	}
	d := packageData{RepoRow: h.row(rc), Package: p, PkgHref: packageHref(rc.Name, p.Name)}
	latest := ""
	if len(p.Versions) > 0 {
		latest = p.Versions[0].Version
	}
	d.Snippets = h.packageSnippets(rq, rc, p.Name, latest)
	rq.render(http.StatusOK, "package", p.Name, d)
}

type tagRow struct {
	browse.ImageTag
	Href string
}

type manifestRow struct {
	browse.ManifestSummary
	Href string
}

type imageData struct {
	RepoRow
	Image     *browse.ImageDetail
	ImageHref string
	Tags      []tagRow
	Manifests []manifestRow
	Snippets  []snippet
}

func (imageData) nav() string { return navRepos }

func (h *Handler) imagePage(rq *request) {
	rc := rq.readable()
	if rc == nil {
		return
	}
	if h.contentsOf(rc) != kindImages {
		rq.notFound()
		return
	}
	name := rq.r.PathValue("name")
	img, err := h.opts.Images.Image(rc.Name, name)
	if err != nil {
		rq.browseError(err)
		return
	}
	d := imageData{RepoRow: h.row(rc), Image: img, ImageHref: imageHref(rc.Name, name)}
	for _, t := range img.Tags {
		d.Tags = append(d.Tags, tagRow{ImageTag: t, Href: manifestHref(rc.Name, name, t.Digest)})
	}
	for _, m := range img.Manifests {
		d.Manifests = append(d.Manifests, manifestRow{ManifestSummary: m, Href: manifestHref(rc.Name, name, m.Digest)})
	}
	ref := ""
	if len(img.Tags) > 0 {
		ref = ":" + img.Tags[0].Name
		if i := slices.IndexFunc(img.Tags, func(t browse.ImageTag) bool { return t.Name == "latest" }); i >= 0 {
			ref = ":latest"
		}
	} else if len(img.Manifests) > 0 {
		ref = "@" + img.Manifests[0].Digest
	}
	d.Snippets = h.imageSnippets(rq, rc, name, ref)
	rq.render(http.StatusOK, "image", rc.Name+"/"+name, d)
}

type descriptorRow struct {
	browse.Descriptor
	Href string
}

type manifestData struct {
	RepoRow
	Image     string
	ImageHref string
	Manifest  *browse.Manifest
	Children  []descriptorRow
	Referrers []descriptorRow
	// SubjectHref links to the manifest's subject, if stored.
	SubjectHref string
	Snippets    []snippet
}

func (manifestData) nav() string { return navRepos }

func (h *Handler) manifestPage(rq *request) {
	rc := rq.readable()
	if rc == nil {
		return
	}
	if h.contentsOf(rc) != kindImages {
		rq.notFound()
		return
	}
	name := rq.r.PathValue("name")
	m, err := h.opts.Images.Manifest(rq.r.Context(), rc.Name, name, rq.r.PathValue("digest"))
	if err != nil {
		rq.browseError(err)
		return
	}
	d := manifestData{RepoRow: h.row(rc), Image: name, ImageHref: imageHref(rc.Name, name), Manifest: m}
	for _, c := range m.Manifests {
		row := descriptorRow{Descriptor: c}
		if c.Stored {
			row.Href = manifestHref(rc.Name, name, c.Digest)
		}
		d.Children = append(d.Children, row)
	}
	for _, c := range m.Referrers {
		d.Referrers = append(d.Referrers, descriptorRow{Descriptor: c, Href: manifestHref(rc.Name, name, c.Digest)})
	}
	if m.Subject != "" {
		d.SubjectHref = manifestHref(rc.Name, name, m.Subject)
	}
	d.Snippets = h.imageSnippets(rq, rc, name, "@"+m.Digest)
	rq.render(http.StatusOK, "manifest", rc.Name+"/"+name+"@"+shortDigest(m.Digest), d)
}

type loginData struct {
	Next    string
	User    string
	Message string
}

func (loginData) nav() string { return navSignIn }

// nextPath returns the page to go to after signing in: next if it is a
// UI page, else the UI's home page.
func nextPath(next string) string {
	if strings.HasPrefix(next, Prefix) && !strings.HasPrefix(next, "//") && !strings.ContainsAny(next, "\\\r\n") {
		return next
	}
	return Prefix
}

func (h *Handler) loginPage(rq *request) {
	next := nextPath(rq.r.URL.Query().Get("next"))
	if rq.signedIn() {
		http.Redirect(rq.w, rq.r, next, http.StatusSeeOther)
		return
	}
	rq.render(http.StatusOK, "login", "Sign in", loginData{Next: next})
}

func (h *Handler) login(rq *request) {
	user := strings.TrimSpace(rq.r.PostFormValue("username"))
	next := nextPath(rq.r.PostFormValue("next"))
	secret, expires, err := h.auth.SignIn(detach(rq.r.Context()), user, rq.r.PostFormValue("password"))
	if err != nil {
		msg, ok := auth.Message(err)
		if !ok {
			h.serverError(rq, err)
			return
		}
		rq.render(http.StatusUnauthorized, "login", "Sign in", loginData{Next: next, User: user, Message: msg})
		return
	}
	h.setCookie(rq.w, rq.r, &http.Cookie{Name: sessionCookie, Value: secret}, expires)
	h.clearCookie(rq.w, rq.r, csrfCookie)
	http.Redirect(rq.w, rq.r, next, http.StatusSeeOther)
}

func (h *Handler) logout(rq *request) {
	if rq.secret != "" {
		if err := h.auth.EndSession(detach(rq.r.Context()), rq.secret); err != nil {
			h.serverError(rq, err)
			return
		}
	}
	h.clearCookie(rq.w, rq.r, sessionCookie)
	http.Redirect(rq.w, rq.r, Prefix, http.StatusSeeOther)
}

type tokenRow struct {
	auth.TokenInfo
	Scopes      []string
	RevokeHref  string
	NeverExpire bool
}

type accountData struct {
	Groups      string
	HasPassword bool
	Tokens      []tokenRow
	// Created is a token just created, shown once with its secret.
	Created       *tokenRow
	CreatedSecret string
	// PasswordMessage and TokenMessage report the result of a form.
	PasswordMessage string
	PasswordOK      bool
	TokenMessage    string
	// Form holds the token form's values after a refused submission.
	Form tokenForm
	// Expiries are the token form's expiry choices.
	Expiries []expiry
}

type tokenForm struct {
	Name, Expiry, Repositories, Role string
	Scoped, Admin                    bool
}

type expiry struct {
	Value, Label string
}

var expiries = []expiry{
	{"7d", "7 days"}, {"30d", "30 days"}, {"90d", "90 days"}, {"365d", "1 year"}, {"never", "Never"},
}

func (accountData) nav() string { return navAccount }

// accountData builds the account page's data.
func (h *Handler) accountData(rq *request) (*accountData, error) {
	d := &accountData{Groups: strings.Join(rq.p.Groups, ", "), Expiries: expiries,
		Form: tokenForm{Expiry: "90d", Role: auth.RoleRead.String()}}
	var err error
	if d.HasPassword, err = h.auth.HasPassword(rq.p.User); err != nil {
		return nil, err
	}
	tokens, err := h.auth.Tokens(rq.p)
	if err != nil {
		return nil, err
	}
	for _, t := range tokens {
		d.Tokens = append(d.Tokens, tokenRowOf(t))
	}
	return d, nil
}

func tokenRowOf(t auth.TokenInfo) tokenRow {
	r := tokenRow{TokenInfo: t, RevokeHref: "/ui/account/tokens/" + url.PathEscape(t.ID) + "/revoke", NeverExpire: t.Expires.IsZero()}
	for _, s := range t.Scopes {
		r.Scopes = append(r.Scopes, s.Role.String()+" on "+strings.Join(s.Repositories, ", "))
	}
	return r
}

func (h *Handler) account(rq *request) {
	if !rq.signedIn() {
		rq.denied()
		return
	}
	d, err := h.accountData(rq)
	if err != nil {
		h.serverError(rq, err)
		return
	}
	rq.render(http.StatusOK, "account", "Account", d)
}

func (h *Handler) changePassword(rq *request) {
	if !rq.signedIn() {
		rq.denied()
		return
	}
	f := rq.r.PostForm
	var msg string
	err := error(nil)
	switch {
	case f.Get("new") != f.Get("confirm"):
		msg = "The new passwords do not match."
	default:
		err = h.auth.ChangePassword(detach(rq.r.Context()), rq.p, f.Get("current"), f.Get("new"))
		if errors.Is(err, auth.ErrInvalidCredentials) {
			msg, err = "The current password is incorrect.", nil
		} else if m, ok := auth.Message(err); ok {
			msg, err = m, nil
		}
	}
	if err != nil {
		h.serverError(rq, err)
		return
	}
	d, err := h.accountData(rq)
	if err != nil {
		h.serverError(rq, err)
		return
	}
	status := http.StatusOK
	if msg != "" {
		d.PasswordMessage = msg
		status = http.StatusBadRequest
	} else {
		d.PasswordMessage, d.PasswordOK = "Your password was changed, and your other sessions were signed out.", true
	}
	rq.render(status, "account", "Account", d)
}

// parseExpiry reads the token form's expiry: a number of days, as "30d",
// or "never".
func parseExpiry(s string) (time.Duration, bool) {
	if s == "never" {
		return 0, true
	}
	days, ok := strings.CutSuffix(s, "d")
	var n int
	if _, err := fmt.Sscanf(days, "%d", &n); !ok || err != nil || n <= 0 || n > 3650 || fmt.Sprint(n) != days {
		return 0, false
	}
	return time.Duration(n) * 24 * time.Hour, true
}

func (h *Handler) createToken(rq *request) {
	if !rq.signedIn() {
		rq.denied()
		return
	}
	f := rq.r.PostForm
	form := tokenForm{Name: strings.TrimSpace(f.Get("name")), Expiry: f.Get("expiry"), Repositories: f.Get("repositories"),
		Role: f.Get("role"), Scoped: f.Get("scope") == "selected", Admin: f.Get("admin") == "on"}
	var msg string
	var scopes []auth.Scope
	ttl, ok := parseExpiry(form.Expiry)
	if !ok {
		msg = "Choose an expiry."
	}
	if form.Scoped && msg == "" {
		role, ok := auth.ParseRole(form.Role)
		repos := strings.FieldsFunc(form.Repositories, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' })
		switch {
		case !ok:
			msg = "Choose a role."
		case len(repos) == 0:
			msg = "Name at least one repository or pattern, such as team-a-*."
		default:
			scopes = []auth.Scope{{Repositories: repos, Role: role}}
		}
	}
	var info auth.TokenInfo
	var secret string
	if msg == "" {
		var err error
		info, secret, err = h.auth.CreateToken(detach(rq.r.Context()), rq.p, form.Name, ttl, form.Admin, scopes)
		if err != nil {
			m, ok := auth.Message(err)
			if !ok {
				h.serverError(rq, err)
				return
			}
			msg = m
		}
	}
	d, err := h.accountData(rq)
	if err != nil {
		h.serverError(rq, err)
		return
	}
	if msg != "" {
		d.TokenMessage, d.Form = msg, form
		rq.render(http.StatusBadRequest, "account", "Account", d)
		return
	}
	row := tokenRowOf(info)
	d.Created, d.CreatedSecret = &row, secret
	rq.render(http.StatusOK, "account", "Account", d)
}

func (h *Handler) revokeToken(rq *request) {
	if !rq.signedIn() {
		rq.denied()
		return
	}
	err := h.auth.RevokeToken(detach(rq.r.Context()), rq.p, rq.r.PathValue("id"))
	if _, ok := auth.Message(err); err != nil && !ok {
		h.serverError(rq, err)
		return
	}
	// Revoking a token that is gone already, as when the form is sent
	// twice, leaves the account as wanted.
	http.Redirect(rq.w, rq.r, "/ui/account#tokens", http.StatusSeeOther)
}
