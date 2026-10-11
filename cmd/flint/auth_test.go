package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// apiCall makes an admin API request with basic credentials and decodes a
// JSON response into out.
func apiCall(t *testing.T, method, url, user, pass, body string, out any) int {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(user, pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: decoding %q: %v", method, url, b, err)
		}
	}
	return resp.StatusCode
}

// tokenKid returns the key ID in a JWT's header.
func tokenKid(t *testing.T, tok string) string {
	t.Helper()
	h, _, _ := strings.Cut(tok, ".")
	b, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	var hdr struct{ Kid string }
	json.Unmarshal(b, &hdr)
	return hdr.Kid
}

// fetchToken gets a bearer token from flint's Docker token endpoint.
func fetchToken(t *testing.T, base, user, pass, scope string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/auth/token?service=flint&scope="+url.QueryEscape(scope), nil)
	req.SetBasicAuth(user, pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.Token
}

// TestAuthEndToEnd runs flint serve with a bootstrap administrator: the
// administrator creates a user and an API token through the admin API, the
// token works at the Docker token endpoint, no secret reaches the log, and
// a restart keeps the administrator and the signing key. When crane or
// docker is installed, a real client also logs in with the token and pushes
// and pulls an image through the authenticated registry API.
func TestAuthEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	adminPassword := "admin-" + rand.Text()
	pwFile := filepath.Join(dir, "admin-password")
	if err := os.WriteFile(pwFile, []byte(adminPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeConfig(t, map[string]any{
		"listen":  "127.0.0.1:0",
		"dataDir": dataDir,
		"log":     map[string]any{"level": "debug"},
		"repositories": []any{
			map[string]any{"name": "docker-local", "format": "oci", "type": "hosted"},
		},
		"auth": map[string]any{
			"bootstrapAdmin": map[string]any{"passwordFile": pwFile},
			"permissions": []any{
				map[string]any{"repositories": []string{"docker-*"}, "role": "write", "groups": []string{"ci"}},
			},
		},
	})
	p := startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("flint exited at startup:\n%s", p.output())
	}
	base := "http://" + p.addr
	if !p.hasLog("created the bootstrap administrator") || !p.hasLog("generated the token-signing key") {
		t.Errorf("missing bootstrap logs:\n%s", p.output())
	}
	if info, err := os.Stat(filepath.Join(dataDir, "auth", "token-signing.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("signing key: %v, %v", info, err)
	}

	var user struct{ Name string }
	if code := apiCall(t, "POST", base+"/api/v1/users", "admin", adminPassword,
		`{"name": "ci-bot", "password": "ci-bot-password", "groups": ["ci"]}`, &user); code != 201 {
		t.Fatalf("create user: %d", code)
	}
	var tok struct{ ID, Token string }
	if code := apiCall(t, "POST", base+"/api/v1/tokens", "ci-bot", "ci-bot-password", `{"name": "e2e", "expiresIn": "1h"}`, &tok); code != 201 {
		t.Fatalf("create token: %d", code)
	}

	code, jwt := fetchToken(t, base, "ci-bot", tok.Token, "repository:docker-local/e2e:pull,push")
	if code != 200 || jwt == "" {
		t.Fatalf("token endpoint with an API token: %d", code)
	}
	if code, _ := fetchToken(t, base, "ci-bot", "wrong-password", ""); code != 401 {
		t.Errorf("token endpoint with a wrong password: %d", code)
	}
	if code, _ := fetchToken(t, base, "__token__", tok.Token, ""); code != 200 {
		t.Errorf("token endpoint with __token__: %d", code)
	}
	kid := tokenKid(t, jwt)

	t.Run("registry client", func(t *testing.T) {
		registryClient(t, p.addr, "ci-bot", tok.Token)
	})

	code, metrics := get(t, http.DefaultClient, base+"/metrics")
	if code != 200 || !strings.Contains(metrics, `flint_auth_attempts_total{method="token",result="success"}`) {
		t.Errorf("auth metrics missing")
	}

	p.cmd.Process.Signal(syscall.SIGTERM)
	if code := p.wait(t); code != 0 {
		t.Fatalf("exit code %d:\n%s", code, p.output())
	}
	out := p.output()
	for _, secret := range []string{adminPassword, "ci-bot-password", tok.Token, tok.Token[len("flint_")+17:], jwt} {
		if strings.Contains(out, secret) {
			t.Errorf("the log contains a secret %q", secret)
		}
	}

	// After a restart, the bootstrap is skipped even without its password
	// file, the administrator keeps the password, and tokens are signed
	// with the same key.
	os.Remove(pwFile)
	p = startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("restart failed:\n%s", p.output())
	}
	base = "http://" + p.addr
	if p.hasLog("created the bootstrap administrator") || p.hasLog("generated the token-signing key") {
		t.Errorf("the restart bootstrapped again:\n%s", p.output())
	}
	if code := apiCall(t, "GET", base+"/api/v1/user", "admin", adminPassword, "", nil); code != 200 {
		t.Errorf("admin after restart: %d", code)
	}
	if _, jwt := fetchToken(t, base, "__token__", tok.Token, ""); tokenKid(t, jwt) != kid {
		t.Error("the signing key changed across a restart")
	}
}

// registryClient pushes and pulls an image with a real client, logged in
// with an API token, after checking that an anonymous client cannot push.
// It prefers crane, falls back to docker, and skips if neither is
// installed.
func registryClient(t *testing.T, addr, user, token string) {
	resp, err := http.Get("http://" + addr + "/v2/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer ") {
		t.Fatalf("GET /v2/ without credentials = %d %q, want a 401 Bearer challenge", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	dir := t.TempDir()
	layer := filepath.Join(dir, "layer.tar")
	writeLayer(t, layer)
	ref := addr + "/docker-local/e2e:" + strings.ToLower(rand.Text()[:8])
	env := append(os.Environ(), "DOCKER_CONFIG="+filepath.Join(dir, "docker"))
	exe := func(stdin string, name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	run := func(stdin string, name string, args ...string) string {
		t.Helper()
		out, err := exe(stdin, name, args...)
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return out
	}

	if crane, err := exec.LookPath("crane"); err == nil {
		if out, err := exe("", crane, "append", "--insecure", "-f", layer, "-t", ref); err == nil {
			t.Fatalf("an anonymous crane push succeeded:\n%s", out)
		}
		run(token, crane, "auth", "login", addr, "-u", user, "--password-stdin")
		run("", crane, "append", "--insecure", "-f", layer, "-t", ref)
		run("", crane, "pull", "--insecure", ref, filepath.Join(dir, "pulled.tar"))
		if out := run("", crane, "catalog", "--insecure", addr); !strings.Contains(out, "docker-local/e2e\n") {
			t.Errorf("crane catalog lacks docker-local/e2e:\n%s", out)
		}
		return
	}
	docker, err := exec.LookPath("docker")
	if err != nil || exec.Command(docker, "info").Run() != nil {
		t.Skip("neither crane nor a working docker is installed")
	}
	run(token, docker, "login", addr, "-u", user, "--password-stdin")
	run("", docker, "import", layer, ref)
	run("", docker, "push", ref)
	run("", docker, "rmi", ref)
	run("", docker, "pull", ref)
	run("", docker, "rmi", ref)
}

// writeLayer writes a one-file tar archive.
func writeLayer(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := "hello from flint\n"
	tw.WriteHeader(&tar.Header{Name: "hello.txt", Mode: 0o644, Size: int64(len(content)), ModTime: time.Unix(0, 0)})
	io.WriteString(tw, content)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
