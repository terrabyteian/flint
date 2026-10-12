package ui

import (
	"net/url"
	"strings"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/server"
)

// snippet is client configuration to copy, such as a command or a
// configuration file's contents.
type snippet struct {
	// Title says what it is for; File, if set, names the file it goes in.
	Title, File string
	Text        string
}

// endpoints are the URLs a client uses for a repository.
type endpoints struct {
	base string // the server's base URL, such as "https://registry.example"
	host string // its host, as image references name it
	// machine is its host name without the port, as .netrc names it.
	machine string
	url     string // the repository's URL, ending in "/"
	user    string // the signed-in user, or a placeholder
}

func (h *Handler) endpoints(rq *request, rc *config.Repository) endpoints {
	base := server.BaseURL(rq.r)
	e := endpoints{base: base, host: base, machine: base, user: rq.p.User}
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		e.host, e.machine = u.Host, u.Hostname()
	}
	e.url = base + repo.Path(rc.Format, rc.Name)
	if e.user == "" {
		e.user = "USER"
	}
	return e
}

// publishable reports whether clients publish to repository rc: it is
// hosted, or a virtual repository with a publishTo member.
func publishable(rc *config.Repository) bool {
	return rc.Type == config.TypeHosted || rc.Virtual != nil && rc.Virtual.PublishTo != ""
}

// repoSnippets returns the client configuration for repository rc.
func (h *Handler) repoSnippets(rq *request, rc *config.Repository) []snippet {
	e := h.endpoints(rq, rc)
	pub := publishable(rc)
	var s []snippet
	add := func(title, file, text string) { s = append(s, snippet{Title: title, File: file, Text: text}) }
	switch rc.Format {
	case config.FormatOCI:
		image := e.host + "/" + rc.Name + "/app:1.0"
		if p := rc.Proxy; p != nil && strings.Contains(p.URL, "docker.io") {
			image = e.host + "/" + rc.Name + "/library/alpine:latest"
		}
		add("Sign in", "", "docker login "+e.host)
		add("Pull", "", "docker pull "+image)
		if pub {
			add("Push", "", "docker tag app:1.0 "+image+"\ndocker push "+image)
		}
		if rc.HelmIndex {
			add("Push a Helm chart", "", "helm registry login "+e.host+"\nhelm push mychart-1.0.0.tgz oci://"+e.host+"/"+rc.Name)
			add("Add as a Helm chart repository", "", "helm repo add "+rc.Name+" "+e.base+"/helm/"+rc.Name+
				" --username "+e.user+" --password \"$FLINT_TOKEN\"")
		}
	case config.FormatPyPI:
		index := e.url + "simple/"
		add("Install with pip", "", "pip install --index-url "+index+" PACKAGE")
		add("Use with pip", "pip.conf", "[global]\nindex-url = "+index)
		uv := "[[tool.uv.index]]\nname = \"" + rc.Name + "\"\nurl = \"" + index + "\"\ndefault = true"
		if pub {
			uv += "\npublish-url = \"" + e.url + "legacy/\""
		}
		add("Use with uv", "pyproject.toml", uv)
		if pub {
			add("Publish with twine", "", "twine upload --repository-url "+e.url+"legacy/ \\\n  -u __token__ -p \"$FLINT_TOKEN\" dist/*")
		}
		add("Authenticate", ".netrc", "machine "+e.machine+"\nlogin __token__\npassword $FLINT_TOKEN")
	case config.FormatNPM:
		add("Use with npm, pnpm, Yarn classic, or Bun", ".npmrc",
			"registry="+e.url+"\n//"+strings.TrimPrefix(strings.TrimPrefix(e.url, "https://"), "http://")+":_authToken=${FLINT_TOKEN}")
		add("Use with Yarn Berry", ".yarnrc.yml",
			"npmRegistryServer: \""+e.url+"\"\nnpmAuthToken: \"${FLINT_TOKEN}\"\nnpmAlwaysAuth: true")
		if pub {
			add("Publish", "", "npm publish --registry "+e.url)
		}
	case config.FormatMaven:
		if pub {
			add("Deploy with Maven", "pom.xml", "<distributionManagement>\n  <repository>\n    <id>"+rc.Name+"</id>\n    <url>"+
				e.url+"</url>\n  </repository>\n</distributionManagement>")
		}
		if rc.Type != config.TypeHosted {
			add("Resolve everything through flint", "settings.xml", "<mirrors>\n  <mirror>\n    <id>"+rc.Name+
				"</id>\n    <mirrorOf>*</mirrorOf>\n    <url>"+e.url+"</url>\n  </mirror>\n</mirrors>")
		}
		add("Authenticate", "settings.xml", "<servers>\n  <server>\n    <id>"+rc.Name+"</id>\n    <username>"+e.user+
			"</username>\n    <password>${env.FLINT_TOKEN}</password>\n  </server>\n</servers>")
		add("Use with Gradle", "settings.gradle.kts", "dependencyResolutionManagement {\n    repositories {\n"+
			"        maven(\""+e.url+"\") {\n            credentials {\n                username = \""+e.user+
			"\"\n                password = System.getenv(\"FLINT_TOKEN\")\n            }\n        }\n    }\n}")
	case config.FormatGo:
		add("Use with the go command", "", "go env -w GOPROXY="+strings.TrimSuffix(e.url, "/"))
		netrc := "machine " + e.machine + "\nlogin __token__\npassword $FLINT_TOKEN"
		if e.host != e.machine {
			// Go 1.24 and later look the credentials up by host and port,
			// earlier releases by host alone.
			netrc = "machine " + e.host + "\nlogin __token__\npassword $FLINT_TOKEN\n\n" + netrc
		}
		add("Authenticate", ".netrc", netrc)
	case config.FormatCargo:
		cfg := "[registries." + rc.Name + "]\nindex = \"sparse+" + e.url + "\"\ncredential-provider = \"cargo:token\""
		if rc.Type != config.TypeHosted {
			cfg += "\n\n[source.crates-io]\nreplace-with = \"" + rc.Name + "\""
		}
		add("Use with Cargo", ".cargo/config.toml", cfg)
		add("Sign in", "", "cargo login --registry "+rc.Name)
		if pub {
			add("Publish", "", "cargo publish --registry "+rc.Name)
		}
	case config.FormatGeneric:
		add("Download", "", "curl -fsSLO -u \""+e.user+":$FLINT_TOKEN\" "+e.url+"path/to/file.tar.gz")
		if pub {
			add("Upload", "", "curl -fsS -u \""+e.user+":$FLINT_TOKEN\" -T file.tar.gz "+e.url+"path/to/file.tar.gz")
		}
	}
	return s
}

// packageSnippets returns the commands that install version of package
// name from repository rc.
func (h *Handler) packageSnippets(rq *request, rc *config.Repository, name, version string) []snippet {
	e := h.endpoints(rq, rc)
	switch rc.Format {
	case config.FormatPyPI:
		spec := name
		if version != "" {
			spec += "==" + version
		}
		return []snippet{{Title: "Install", Text: "pip install --index-url " + e.url + "simple/ " + spec}}
	case config.FormatNPM:
		return []snippet{{Title: "Install", Text: "npm install " + name + "@" + version + " --registry " + e.url}}
	case config.FormatMaven:
		g, a, _ := strings.Cut(name, ":")
		return []snippet{{Title: "Depend on it", File: "pom.xml", Text: "<dependency>\n  <groupId>" + g +
			"</groupId>\n  <artifactId>" + a + "</artifactId>\n  <version>" + version + "</version>\n</dependency>"},
			{Title: "Depend on it with Gradle", File: "build.gradle.kts",
				Text: "implementation(\"" + name + ":" + version + "\")"}}
	case config.FormatCargo:
		return []snippet{{Title: "Depend on it", Text: "cargo add " + name + "@" + version + " --registry " + rc.Name}}
	}
	return nil
}

// imageSnippets returns the commands that sign in and pull image name of
// repository rc by ref, ":<tag>" or "@<digest>", and with push, for a
// repository clients publish to, that tag and push a local build of it.
func (h *Handler) imageSnippets(rq *request, rc *config.Repository, name, ref string, push bool) []snippet {
	e := h.endpoints(rq, rc)
	image := e.host + "/" + rc.Name + "/" + name
	s := []snippet{
		{Title: "Sign in", Text: "docker login " + e.host},
		{Title: "Pull", Text: "docker pull " + image + ref},
	}
	if push && publishable(rc) {
		tag := ":latest"
		if strings.HasPrefix(ref, ":") {
			tag = ref
		}
		s = append(s, snippet{Title: "Push", Text: "docker tag " + name + tag + " " + image + tag + "\ndocker push " + image + tag})
	}
	return s
}
