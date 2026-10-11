package main

import (
	"bytes"
	"crypto/rand"
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

// TestVirtualEndToEnd runs flint serve with an OCI virtual repository over
// a hosted repository and a proxy of a fake upstream: a client pushes
// through the virtual repository with the Docker token flow, asking for a
// token for the virtual repository's name as Docker clients do, and the
// image lands in the publishTo member; an anonymous client pulls both the
// pushed image and an upstream image through the one name; and after a
// restart with the upstream down, both are still served.
func TestVirtualEndToEnd(t *testing.T) {
	up := upstreamtest.New(t)
	upstreamImg := up.PutImage("library/app", "v1", []byte("upstream layer"))
	dir := t.TempDir()
	adminPassword := "admin-" + rand.Text()
	pwFile := filepath.Join(dir, "admin-password")
	if err := os.WriteFile(pwFile, []byte(adminPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeConfig(t, map[string]any{
		"listen":  "127.0.0.1:0",
		"dataDir": filepath.Join(dir, "data"),
		"repositories": []any{
			map[string]any{"name": "docker-local", "format": "oci", "type": "hosted"},
			map[string]any{"name": "dockerhub", "format": "oci", "type": "proxy", "proxy": map[string]any{"url": up.URL}},
			map[string]any{"name": "docker", "format": "oci", "type": "virtual", "anonymousPull": true,
				"virtual": map[string]any{"members": []string{"docker-local", "dockerhub"}, "publishTo": "docker-local"}},
		},
		"auth": map[string]any{
			"bootstrapAdmin": map[string]any{"passwordFile": pwFile},
			"permissions": []any{
				map[string]any{"repositories": []string{"docker-local"}, "role": "write", "groups": []string{"ci"}},
			},
		},
	})
	p := startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("flint exited at startup:\n%s", p.output())
	}
	base := "http://" + p.addr
	if code := apiCall(t, "POST", base+"/api/v1/users", "admin", adminPassword,
		`{"name": "ci-bot", "password": "ci-bot-password", "groups": ["ci"]}`, nil); code != 201 {
		t.Fatalf("create user: %d", code)
	}

	// do sends a request with a bearer token, if token is set.
	do := func(method, path, token string, body []byte, contentType string) (int, []byte, http.Header) {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b, resp.Header
	}
	anonymousToken := func(repo string) string {
		t.Helper()
		resp, err := http.Get(base + "/auth/token?service=flint&scope=" + url.QueryEscape("repository:"+repo+":pull"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var tok struct{ Token string }
		json.NewDecoder(resp.Body).Decode(&tok)
		return tok.Token
	}

	// The push is challenged for the virtual repository's name, and a
	// token for that name, granted for ci-bot's write on the publishTo
	// member, admits it.
	img := newTestImage("docker/team/app:1.0", []byte("first-party layer"))
	code, _, hdr := do("POST", "/v2/docker/team/app/blobs/uploads/", "", nil, "")
	if code != http.StatusUnauthorized || !strings.Contains(hdr.Get("WWW-Authenticate"), `scope="repository:docker/team/app:pull,push"`) {
		t.Fatalf("anonymous push = %d, challenge %q", code, hdr.Get("WWW-Authenticate"))
	}
	code, token := fetchToken(t, base, "ci-bot", "ci-bot-password", "repository:docker/team/app:pull,push")
	if code != 200 {
		t.Fatalf("token for a push through the virtual repository: %d", code)
	}
	for _, b := range img.blobs {
		if code, body, _ := do("POST", "/v2/docker/team/app/blobs/uploads/?digest="+digestOf(b), token, b, ""); code != http.StatusCreated {
			t.Fatalf("pushing a blob through the virtual repository: %d %s", code, body)
		}
	}
	code, body, hdr := do("PUT", "/v2/docker/team/app/manifests/1.0", token, img.manifest, mtOCIManifest)
	if code != http.StatusCreated || hdr.Get("Location") != "/v2/docker/team/app/manifests/"+digestOf(img.manifest) {
		t.Fatalf("pushing the manifest through the virtual repository: %d %s, Location %q", code, body, hdr.Get("Location"))
	}
	if code := img.pull(t, base, "admin", adminPassword); code != http.StatusOK {
		t.Errorf("pull through the virtual repository: %d", code)
	}
	if code := (testImage{ref: "docker-local/team/app:1.0", manifest: img.manifest, blobs: img.blobs}).pull(t, base, "admin", adminPassword); code != http.StatusOK {
		t.Errorf("the push did not land in the publishTo member: %d", code)
	}

	pullAll := func() {
		t.Helper()
		tok := anonymousToken("docker/team/app")
		if code, b, _ := do("GET", "/v2/docker/team/app/manifests/1.0", tok, nil, ""); code != 200 || !bytes.Equal(b, img.manifest) {
			t.Errorf("anonymous pull of the pushed image = %d %.200s", code, b)
		}
		tok = anonymousToken("docker/library/app")
		if code, b, _ := do("GET", "/v2/docker/library/app/manifests/v1", tok, nil, ""); code != 200 || !bytes.Equal(b, upstreamImg.Manifest) {
			t.Fatalf("anonymous pull of the upstream image = %d %.200s", code, b)
		}
		for _, d := range append([]string{upstreamImg.Config}, upstreamImg.Layers...) {
			if code, b, _ := do("GET", "/v2/docker/library/app/blobs/"+d, tok, nil, ""); code != 200 || !bytes.Equal(b, upstreamImg.Blobs[d]) {
				t.Fatalf("anonymous pull of upstream blob %s = %d", d, code)
			}
		}
	}
	pullAll()
	if code, _, _ := do("GET", "/v2/docker/library/app/manifests/v1", "", nil, ""); code != 200 {
		t.Errorf("anonymous pull without a token = %d", code)
	}
	// Reading through the virtual repository is not reading the member.
	if code, _, _ := do("GET", "/v2/docker-local/team/app/manifests/1.0", anonymousToken("docker-local/team/app"), nil, ""); code != http.StatusUnauthorized {
		t.Errorf("anonymous pull from the hosted member = %d, want 401", code)
	}

	// After a restart with the upstream down, both are still served.
	p.cmd.Process.Signal(os.Interrupt)
	if code := p.wait(t); code != 0 {
		t.Fatalf("flint exited %d:\n%s", code, p.output())
	}
	up.SetDown(true)
	p = startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("restart failed:\n%s", p.output())
	}
	base = "http://" + p.addr
	pullAll()
}
