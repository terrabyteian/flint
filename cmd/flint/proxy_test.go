package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/upstream/upstreamtest"
)

// TestProxyEndToEnd runs flint serve with proxy repositories of a fake
// upstream that needs credentials: an anonymous client pulls through the
// one that allows anonymous pulls with the Docker token flow, the other
// refuses it, pushes are refused, the upstream password never reaches the
// log, and after a restart with the upstream down, cached content is
// still served.
func TestProxyEndToEnd(t *testing.T) {
	up := upstreamtest.New(t)
	up.Username, up.Password = "mirror-bot", "upstream-"+strings.Repeat("x", 8)+"-secret"
	img := up.PutImage("library/app", "v1", []byte("layer content"))
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "upstream-password")
	if err := os.WriteFile(pwFile, []byte(up.Password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	proxy := map[string]any{"url": up.URL, "username": up.Username, "passwordFile": pwFile, "revalidateAfter": "1s"}
	cfgPath := writeConfig(t, map[string]any{
		"listen":  "127.0.0.1:0",
		"dataDir": filepath.Join(dir, "data"),
		"log":     map[string]any{"level": "debug"},
		"repositories": []any{
			map[string]any{"name": "mirror", "format": "oci", "type": "proxy", "anonymousPull": true, "proxy": proxy},
			map[string]any{"name": "private", "format": "oci", "type": "proxy", "proxy": proxy},
		},
	})
	p := startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("flint exited at startup:\n%s", p.output())
	}
	base := "http://" + p.addr

	// fetch sends an anonymous GET, with a bearer token if token is set.
	fetch := func(path, token string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest("GET", base+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	// pull sends an anonymous GET and, if it is challenged, retries with
	// an anonymous token, as Docker clients do.
	pull := func(path string) (int, []byte) {
		t.Helper()
		if code, b := fetch(path, ""); code != http.StatusUnauthorized {
			return code, b
		}
		repo, _, _ := strings.Cut(strings.TrimPrefix(path, "/v2/"), "/manifests/")
		repo, _, _ = strings.Cut(repo, "/blobs/")
		tokResp, err := http.Get(base + "/auth/token?service=flint&scope=" + url.QueryEscape("repository:"+repo+":pull"))
		if err != nil {
			t.Fatal(err)
		}
		var tok struct{ Token string }
		err = json.NewDecoder(tokResp.Body).Decode(&tok)
		tokResp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return fetch(path, tok.Token)
	}

	if code, b := pull("/v2/mirror/library/app/manifests/v1"); code != 200 || !bytes.Equal(b, img.Manifest) {
		t.Fatalf("anonymous pull of the manifest = %d %s", code, b)
	}
	for _, d := range append([]string{img.Config}, img.Layers...) {
		if code, b := pull("/v2/mirror/library/app/blobs/" + d); code != 200 || !bytes.Equal(b, img.Blobs[d]) {
			t.Fatalf("anonymous pull of blob %s = %d %.100s", d, code, b)
		}
	}
	if code, _ := pull("/v2/private/library/app/manifests/v1"); code != http.StatusUnauthorized {
		t.Errorf("anonymous pull from a repository without anonymous pulls = %d, want 401", code)
	}
	// A client that always fetches a token, as Docker does after the /v2/
	// challenge, gets one that admits it.
	tokResp, err := http.Get(base + "/auth/token?service=flint&scope=" + url.QueryEscape("repository:mirror/library/app:pull"))
	if err != nil {
		t.Fatal(err)
	}
	var tok struct{ Token string }
	json.NewDecoder(tokResp.Body).Decode(&tok)
	tokResp.Body.Close()
	if code, b := fetch("/v2/mirror/library/app/manifests/v1?ns=docker.io", tok.Token); code != 200 || !bytes.Equal(b, img.Manifest) {
		t.Errorf("pull with an anonymous token and containerd's ns parameter = %d %s", code, b)
	}
	resp, err := http.Post(base+"/v2/mirror/library/app/blobs/uploads/", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("push to a proxy repository = %d, want 405", resp.StatusCode)
	}
	if strings.Contains(p.output(), up.Password) {
		t.Error("the upstream password reached the log")
	}

	// Restart with the upstream down: the cached image is still served,
	// although the tag cannot be revalidated.
	p.cmd.Process.Signal(os.Interrupt)
	if code := p.wait(t); code != 0 {
		t.Fatalf("flint exited %d:\n%s", code, p.output())
	}
	up.SetDown(true)
	p = startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("flint exited at restart:\n%s", p.output())
	}
	base = "http://" + p.addr
	if code, b := pull("/v2/mirror/library/app/manifests/v1"); code != 200 || !bytes.Equal(b, img.Manifest) {
		t.Fatalf("pull with the upstream down = %d %s", code, b)
	}
	if code, b := pull("/v2/mirror/library/app/blobs/" + img.Layers[0]); code != 200 || !bytes.Equal(b, img.Blobs[img.Layers[0]]) {
		t.Fatalf("blob pull with the upstream down = %d %.100s", code, b)
	}
	if !p.hasLog("serving a cached tag the upstream could not confirm") {
		t.Errorf("no log of the stale tag:\n%s", p.output())
	}
	_, metrics := get(t, http.DefaultClient, base+"/metrics")
	if !strings.Contains(metrics, `flint_proxy_requests_total{repository="mirror",result="stale"} 1`) ||
		!strings.Contains(metrics, "flint_proxy_disk_pressure 0") {
		t.Errorf("proxy metrics missing:\n%s", metrics)
	}
}
