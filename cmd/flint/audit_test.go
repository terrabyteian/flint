package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// auditRecord is a record as the audit API shows it.
type auditRecord struct {
	Seq    uint64
	Actor  string
	Action string
	Target string
	Client string
	Keys   []struct {
		Op  string
		Key []string
	}
}

// TestAuditEndToEnd runs flint serve, pushes and deletes an image with an
// API token and an administrator's password, and checks through the
// audit API that each change is recorded with the right actor, that only
// administrators may read the audit log, that no secret reaches the
// stream, and that the audit log survives a restart.
func TestAuditEndToEnd(t *testing.T) {
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
		"repositories": []any{
			map[string]any{"name": "docker-local", "format": "oci", "type": "hosted"},
		},
		"auth": map[string]any{
			"bootstrapAdmin": map[string]any{"passwordFile": pwFile},
			"permissions": []any{
				map[string]any{"repositories": []string{"docker-local"}, "role": "write", "users": []string{"ci-bot"}},
			},
		},
		"audit": map[string]any{"retention": map[string]any{"maxSize": "1GiB"}},
	})
	p := startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("flint exited at startup:\n%s", p.output())
	}
	base := "http://" + p.addr

	if code := apiCall(t, "POST", base+"/api/v1/users", "admin", adminPassword,
		`{"name": "ci-bot", "password": "ci-bot-password"}`, nil); code != 201 {
		t.Fatalf("create user: %d", code)
	}
	var tok struct{ ID, Token string }
	if code := apiCall(t, "POST", base+"/api/v1/tokens", "ci-bot", "ci-bot-password", `{"name": "push"}`, &tok); code != 201 {
		t.Fatalf("create token: %d", code)
	}

	registry := func(method, path, user, pass, contentType string, body []byte) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
		req.SetBasicAuth(user, pass)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	digest := func(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer := []byte("audited layer " + rand.Text())
	for _, b := range [][]byte{config, layer} {
		if resp := registry("POST", "/v2/docker-local/app/blobs/uploads/?digest="+digest(b), "ci-bot", tok.Token, "", b); resp.StatusCode != 201 {
			t.Fatalf("blob push: %d", resp.StatusCode)
		}
	}
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},`+
		`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":%q,"size":%d}]}`,
		digest(config), len(config), digest(layer), len(layer)))
	const manifestType = "application/vnd.oci.image.manifest.v1+json"
	if resp := registry("PUT", "/v2/docker-local/app/manifests/v1", "ci-bot", tok.Token, manifestType, manifest); resp.StatusCode != 201 {
		t.Fatalf("manifest push: %d", resp.StatusCode)
	}
	if resp := registry("DELETE", "/v2/docker-local/app/manifests/"+digest(manifest), "admin", adminPassword, "", nil); resp.StatusCode != 202 {
		t.Fatalf("manifest delete: %d", resp.StatusCode)
	}

	// Only administrators read the audit log.
	if code := apiCall(t, "GET", base+"/api/v1/audit", "ci-bot", "ci-bot-password", "", nil); code != 403 {
		t.Errorf("audit query as a non-administrator: %d, want 403", code)
	}
	if code := apiCall(t, "GET", base+"/api/v1/audit/export", "ci-bot", tok.Token, "", nil); code != 403 {
		t.Errorf("audit export with a non-administrator's token: %d, want 403", code)
	}
	req, _ := http.NewRequest("GET", base+"/api/v1/audit", nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 401 {
		t.Errorf("audit query without credentials: %v %v, want 401", resp.StatusCode, err)
	}

	query := func(params string) []auditRecord {
		t.Helper()
		var page struct{ Records []auditRecord }
		if code := apiCall(t, "GET", base+"/api/v1/audit?"+params, "admin", adminPassword, "", &page); code != 200 {
			t.Fatalf("audit query ?%s: %d", params, code)
		}
		return page.Records
	}
	tokenActor := "ci-bot (token " + tok.ID + ")"
	find := func(recs []auditRecord, action, target string) *auditRecord {
		for i := range recs {
			if recs[i].Action == action && recs[i].Target == target {
				return &recs[i]
			}
		}
		return nil
	}
	all := query("limit=1000")
	for _, want := range []struct{ action, target, actor string }{
		{"auth.user.create", "user admin", "system"},
		{"auth.user.create", "user ci-bot", "admin"},
		{"auth.token.create", "token " + tok.ID + " of user ci-bot", "ci-bot"},
		{"oci.blob.push", "docker-local/app@" + digest(layer), tokenActor},
		{"oci.manifest.push", "docker-local/app:v1@" + digest(manifest), tokenActor},
		{"oci.manifest.delete", "docker-local/app@" + digest(manifest), "admin"},
	} {
		r := find(all, want.action, want.target)
		switch {
		case r == nil:
			t.Errorf("no %s record for %s in %+v", want.action, want.target, all)
		case r.Actor != want.actor:
			t.Errorf("%s %s: actor %q, want %q", want.action, want.target, r.Actor, want.actor)
		case want.actor != "system" && r.Client != "127.0.0.1":
			t.Errorf("%s %s: client %q, want 127.0.0.1", want.action, want.target, r.Client)
		}
	}
	if r := find(all, "oci.manifest.push", "docker-local/app:v1@"+digest(manifest)); r != nil {
		var keys []string
		for _, k := range r.Keys {
			keys = append(keys, k.Op+" "+strings.Join(k.Key, "/"))
		}
		if want := "put oci/tag/docker-local/app/v1"; !strings.Contains(strings.Join(keys, "\n"), want) {
			t.Errorf("manifest push keys %q lack %q", keys, want)
		}
	}
	if recs := query("actor=ci-bot&action=oci"); len(recs) != 3 {
		t.Errorf("ci-bot's OCI changes: %d records, want 3 (two blobs and a manifest): %+v", len(recs), recs)
	}
	if recs := query("target=" + url.QueryEscape("docker-local/app:")); len(recs) != 1 || recs[0].Action != "oci.manifest.push" {
		t.Errorf("records by target prefix: %+v", recs)
	}

	// The export has the same records, one JSON object per line.
	req, _ = http.NewRequest("GET", base+"/api/v1/audit/export", nil)
	req.SetBasicAuth("admin", adminPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(resp.Body)
	lines := 0
	for sc.Scan() {
		var r auditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("export line %q: %v", sc.Text(), err)
		}
		lines++
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || lines != len(all) {
		t.Errorf("export: %d with %d lines, want %d", resp.StatusCode, lines, len(all))
	}

	p.cmd.Process.Signal(syscall.SIGTERM)
	if code := p.wait(t); code != 0 {
		t.Fatalf("exit code %d:\n%s", code, p.output())
	}
	stream := readDir(t, filepath.Join(dataDir, "audit"))
	for _, secret := range []string{adminPassword, "ci-bot-password", tok.Token, tok.Token[len("flint_")+17:]} {
		if strings.Contains(stream, secret) {
			t.Errorf("the audit stream contains a secret %q", secret)
		}
	}
	if sum := sha256.Sum256([]byte(tok.Token)); strings.Contains(stream, string(sum[:])) {
		t.Error("the audit stream contains the token's hash")
	}

	// After a restart the records are still there, and new ones follow.
	p = startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("restart failed:\n%s", p.output())
	}
	base = "http://" + p.addr
	if code := apiCall(t, "DELETE", base+"/api/v1/tokens/"+tok.ID, "ci-bot", "ci-bot-password", "", nil); code != 204 {
		t.Fatalf("revoke token: %d", code)
	}
	after := query("limit=1000")
	if len(after) != len(all)+1 || after[len(after)-1].Action != "auth.token.revoke" || after[len(after)-1].Actor != "ci-bot" {
		t.Errorf("after a restart: %d records ending %+v, want %d ending with the revocation", len(after), after[len(after)-1], len(all)+1)
	}
	for i := range after[1:] {
		if after[i+1].Seq <= after[i].Seq {
			t.Fatalf("records out of order or repeated: %d after %d", after[i+1].Seq, after[i].Seq)
		}
	}
}

// readDir returns the contents of every file in dir.
func readDir(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range ents {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
	}
	if b.Len() == 0 {
		t.Fatal("the audit stream is empty")
	}
	return b.String()
}
