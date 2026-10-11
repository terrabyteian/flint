package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/auth"
	"github.com/terrabyteian/flint/internal/backup"
)

const mtOCIManifest = "application/vnd.oci.image.manifest.v1+json"

// testImage is an OCI image pushed through the registry API.
type testImage struct {
	ref      string // repository name and tag, such as docker-local/app:1
	manifest []byte
	blobs    [][]byte
}

func digestOf(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }

// newTestImage builds an image with the given layers and a unique config.
func newTestImage(ref string, layers ...[]byte) testImage {
	cfg := []byte(`{"architecture":"amd64","os":"linux","ref":"` + ref + `"}`)
	desc := func(mt string, b []byte) map[string]any {
		return map[string]any{"mediaType": mt, "digest": digestOf(b), "size": len(b)}
	}
	var ls []any
	for _, l := range layers {
		ls = append(ls, desc("application/vnd.oci.image.layer.v1.tar", l))
	}
	m, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config": desc("application/vnd.oci.image.config.v1+json", cfg), "layers": ls,
	})
	return testImage{ref: ref, manifest: m, blobs: append([][]byte{cfg}, layers...)}
}

// registryDo makes a registry API request with basic credentials.
func registryDo(t *testing.T, method, url, user, pass string, body []byte, contentType string) (int, []byte, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(user, pass)
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

func (img testImage) push(t *testing.T, base, user, pass string) {
	t.Helper()
	name, tag, _ := strings.Cut(img.ref, ":")
	for _, b := range img.blobs {
		if code, body, _ := registryDo(t, "POST", base+"/v2/"+name+"/blobs/uploads/?digest="+digestOf(b), user, pass, b, ""); code != http.StatusCreated {
			t.Fatalf("pushing a blob of %s: %d %s", img.ref, code, body)
		}
	}
	if code, body, _ := registryDo(t, "PUT", base+"/v2/"+name+"/manifests/"+tag, user, pass, img.manifest, mtOCIManifest); code != http.StatusCreated {
		t.Fatalf("pushing %s: %d %s", img.ref, code, body)
	}
}

// pull pulls img by tag and checks every byte; it returns the status of
// the manifest request.
func (img testImage) pull(t *testing.T, base, user, pass string) int {
	t.Helper()
	name, tag, _ := strings.Cut(img.ref, ":")
	code, body, hdr := registryDo(t, "GET", base+"/v2/"+name+"/manifests/"+tag, user, pass, nil, "")
	if code != http.StatusOK {
		return code
	}
	if !bytes.Equal(body, img.manifest) || hdr.Get("Docker-Content-Digest") != digestOf(img.manifest) {
		t.Fatalf("pulled a different manifest for %s", img.ref)
	}
	for _, b := range img.blobs {
		code, got, _ := registryDo(t, "GET", base+"/v2/"+name+"/blobs/"+digestOf(b), user, pass, nil, "")
		if code != http.StatusOK || !bytes.Equal(got, b) {
			t.Fatalf("pulling blob %s of %s: %d, %d bytes, want %d", digestOf(b), img.ref, code, len(got), len(b))
		}
	}
	return code
}

// runCLI runs a flint command in-process.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestBackupEndToEnd pushes images, backs up through flint backup, pushes
// more, backs up again incrementally, restores both backups into fresh
// data directories, and pulls every image from servers on them.
func TestBackupEndToEnd(t *testing.T) {
	defer func(d time.Duration) { backupPollInterval = d }(backupPollInterval)
	backupPollInterval = 20 * time.Millisecond

	dir := t.TempDir()
	dataDir, backupDir := filepath.Join(dir, "data"), filepath.Join(dir, "backups")
	adminPassword := "admin-" + rand.Text()
	pwFile := filepath.Join(dir, "admin-password")
	os.WriteFile(pwFile, []byte(adminPassword+"\n"), 0o600)
	serveConfig := func(dataDir, backupDir string) string {
		return writeConfig(t, map[string]any{
			"listen":  "127.0.0.1:0",
			"dataDir": dataDir,
			"backup":  map[string]any{"directory": backupDir},
			"repositories": []any{
				map[string]any{"name": "docker-local", "format": "oci", "type": "hosted"},
				map[string]any{"name": "releases", "format": "oci", "type": "hosted", "immutableTags": true},
			},
			"auth": map[string]any{"bootstrapAdmin": map[string]any{"passwordFile": pwFile}},
		})
	}
	p := startFlint(t, "serve", "-config", serveConfig(dataDir, backupDir))
	if p.addr == "" {
		t.Fatalf("flint exited at startup:\n%s", p.output())
	}
	base := "http://" + p.addr

	// flint backup authenticates with an admin API token.
	var tok struct{ Token string }
	if code := apiCall(t, "POST", base+"/api/v1/tokens", "admin", adminPassword, `{"name": "backup", "admin": true}`, &tok); code != 201 {
		t.Fatalf("creating the backup token: %d", code)
	}
	tokenFile := filepath.Join(dir, "backup-token")
	os.WriteFile(tokenFile, []byte(tok.Token+"\n"), 0o600)
	backupNow := func() string {
		t.Helper()
		code, out, errOut := runCLI(t, "backup", "-url", base, "-password-file", tokenFile)
		if code != 0 {
			t.Fatalf("flint backup = %d\n%s%s\nserver log:\n%s", code, out, errOut, p.output())
		}
		return out
	}

	shared := []byte("a layer two images share " + rand.Text())
	big := bytes.Repeat([]byte(rand.Text()), 1<<16)
	first := []testImage{
		newTestImage("docker-local/app:1", shared, []byte("app 1 layer")),
		newTestImage("docker-local/team/tool:latest", shared, big),
		newTestImage("releases/app:1.0", []byte("release layer")),
	}
	for _, img := range first {
		img.push(t, base, "admin", adminPassword)
	}
	out1 := backupNow()
	// 3 configs and 4 distinct layers, plus 3 manifests.
	if !regexp.MustCompile(`succeeded in .*: \d+ records, 10 blobs .*, 10 copied`).MatchString(out1) {
		t.Fatalf("first backup: %s", out1)
	}
	id1 := strings.Fields(out1)[1]

	second := []testImage{
		newTestImage("docker-local/app:2", shared, []byte("app 2 layer")),
		newTestImage("docker-local/new:1", []byte("new layer")),
	}
	for _, img := range second {
		img.push(t, base, "admin", adminPassword)
	}
	out2 := backupNow()
	// Only the new configs, layers, and manifests are copied.
	if !regexp.MustCompile(`: \d+ records, 16 blobs .*, 6 copied`).MatchString(out2) {
		t.Fatalf("incremental backup: %s", out2)
	}
	id2 := strings.Fields(out2)[1]

	var st backup.Status
	if code := apiCall(t, "GET", base+backup.APIPath, "admin", adminPassword, "", &st); code != 200 ||
		st.LastSuccess == nil || st.LastSuccess.ID != id2 || st.LastSuccess.CopiedBlobs != 6 {
		t.Fatalf("backup status = %d %+v", code, st.LastSuccess)
	}
	if _, m := get(t, http.DefaultClient, base+"/metrics"); !strings.Contains(m, `flint_backup_runs_total{result="success"} 2`) ||
		!strings.Contains(m, "flint_backup_last_success_copied_blobs 6\n") {
		t.Errorf("backup metrics missing:\n%s", m)
	}
	if !p.hasLog("backup finished") {
		t.Errorf("no backup log:\n%s", p.output())
	}

	if code, out, _ := runCLI(t, "backup", "list", backupDir); code != 0 ||
		!strings.Contains(out, id1+"  complete") || !strings.Contains(out, id2+"  complete") {
		t.Fatalf("flint backup list = %d\n%s", code, out)
	}
	if code, out, errOut := runCLI(t, "backup", "verify", backupDir); code != 0 || !strings.Contains(out, "backup "+id2+" is ok") {
		t.Fatalf("flint backup verify = %d\n%s%s", code, out, errOut)
	}

	p.cmd.Process.Signal(syscall.SIGTERM)
	if code := p.wait(t); code != 0 {
		t.Fatalf("exit code %d:\n%s", code, p.output())
	}

	restore := func(id, to string) {
		t.Helper()
		code, out, errOut := runCLI(t, "restore", "-backup", id, backupDir, to)
		if code != 0 || !strings.Contains(out, "restored backup "+id) {
			t.Fatalf("flint restore = %d\n%s%s", code, out, errOut)
		}
	}
	restored := filepath.Join(dir, "restored")
	restore(id2, restored)
	if code, _, errOut := runCLI(t, "restore", backupDir, restored); code != 1 || !strings.Contains(errOut, "not empty") {
		t.Fatalf("restore into a non-empty directory = %d %s", code, errOut)
	}

	// Pull every image from a server on the restored data directory. The
	// administrator and the API token come back with the metadata.
	p = startFlint(t, "serve", "-config", serveConfig(restored, filepath.Join(dir, "backups-2")))
	if p.addr == "" {
		t.Fatalf("flint on the restored data directory exited:\n%s", p.output())
	}
	base = "http://" + p.addr
	for _, img := range append(first, second...) {
		if code := img.pull(t, base, "admin", adminPassword); code != http.StatusOK {
			t.Fatalf("pulling %s from the restored server: %d", img.ref, code)
		}
	}
	if code := apiCall(t, "GET", base+"/api/v1/user", auth.TokenUser, tok.Token, "", nil); code != 200 {
		t.Errorf("the API token after a restore: %d", code)
	}
	// Pushing continues after the restored log, and the immutable tag held.
	newTestImage("docker-local/after:1", []byte("after restore")).push(t, base, "admin", adminPassword)
	if code, _, _ := registryDo(t, "PUT", base+"/v2/releases/app/manifests/1.0", "admin", adminPassword,
		second[1].manifest, mtOCIManifest); code == http.StatusCreated {
		t.Error("the restored immutable tag moved")
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	p.wait(t)

	// The first backup restores the state it was taken at.
	older := filepath.Join(dir, "restored-older")
	restore(id1, older)
	p = startFlint(t, "serve", "-config", serveConfig(older, filepath.Join(dir, "backups-3")))
	if p.addr == "" {
		t.Fatalf("flint on the older restore exited:\n%s", p.output())
	}
	base = "http://" + p.addr
	for _, img := range first {
		if code := img.pull(t, base, "admin", adminPassword); code != http.StatusOK {
			t.Fatalf("pulling %s from the older restore: %d", img.ref, code)
		}
	}
	for _, img := range second {
		if code := img.pull(t, base, "admin", adminPassword); code != http.StatusNotFound {
			t.Fatalf("pulling %s, pushed after the first backup, from its restore: %d", img.ref, code)
		}
	}
}

// TestBackupChecksFormatBlobs checks that a backup fails when a blob a
// PyPI or Cargo repository links is missing from the data directory.
func TestBackupChecksFormatBlobs(t *testing.T) {
	defer func(d time.Duration) { backupPollInterval = d }(backupPollInterval)
	backupPollInterval = 20 * time.Millisecond

	for _, tc := range []struct {
		format string
		// publish publishes to repository <format>-local and returns the
		// bytes of a blob it links.
		publish func(t *testing.T, base, adminPassword string) []byte
	}{
		{"pypi", func(t *testing.T, base, adminPassword string) []byte {
			var whl bytes.Buffer
			zw := zip.NewWriter(&whl)
			w, _ := zw.Create("pkg-1.0.dist-info/METADATA")
			io.WriteString(w, "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n\n"+rand.Text())
			zw.Close()
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			for k, v := range map[string]string{":action": "file_upload", "name": "pkg", "version": "1.0", "filetype": "bdist_wheel"} {
				mw.WriteField(k, v)
			}
			fw, _ := mw.CreateFormFile("content", "pkg-1.0-py3-none-any.whl")
			fw.Write(whl.Bytes())
			mw.Close()
			if code, out, _ := registryDo(t, "POST", base+"/pypi/pypi-local/legacy/", "admin", adminPassword, body.Bytes(), mw.FormDataContentType()); code != http.StatusOK {
				t.Fatalf("upload: %d %s", code, out)
			}
			return whl.Bytes()
		}},
		{"cargo", func(t *testing.T, base, adminPassword string) []byte {
			crate, body := cargoCrate("1.0.0")
			if code, out, _ := registryDo(t, "PUT", base+"/cargo/cargo-local/api/v1/crates/new", "admin", adminPassword, body, ""); code != http.StatusOK {
				t.Fatalf("publish: %d %s", code, out)
			}
			return crate
		}},
	} {
		t.Run(tc.format, func(t *testing.T) {
			dir := t.TempDir()
			dataDir, backupDir := filepath.Join(dir, "data"), filepath.Join(dir, "backups")
			adminPassword := "admin-" + rand.Text()
			pwFile := filepath.Join(dir, "admin-password")
			os.WriteFile(pwFile, []byte(adminPassword+"\n"), 0o600)
			p := startFlint(t, "serve", "-config", writeConfig(t, map[string]any{
				"listen":       "127.0.0.1:0",
				"dataDir":      dataDir,
				"backup":       map[string]any{"directory": backupDir},
				"repositories": []any{map[string]any{"name": tc.format + "-local", "format": tc.format, "type": "hosted"}},
				"auth":         map[string]any{"bootstrapAdmin": map[string]any{"passwordFile": pwFile}},
			}))
			if p.addr == "" {
				t.Fatalf("flint exited at startup:\n%s", p.output())
			}
			base := "http://" + p.addr
			linked := tc.publish(t, base, adminPassword)

			var tok struct{ Token string }
			if code := apiCall(t, "POST", base+"/api/v1/tokens", "admin", adminPassword, `{"name": "backup", "admin": true}`, &tok); code != 201 {
				t.Fatalf("creating the backup token: %d", code)
			}
			tokenFile := filepath.Join(dir, "backup-token")
			os.WriteFile(tokenFile, []byte(tok.Token+"\n"), 0o600)

			lost := digestOf(linked)
			hex := strings.TrimPrefix(lost, "sha256:")
			removed := false
			filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() && d.Name() == hex {
					removed = os.Remove(path) == nil
				}
				return nil
			})
			if !removed {
				t.Fatal("the linked blob is not in the data directory")
			}
			code, out, errOut := runCLI(t, "backup", "-url", base, "-password-file", tokenFile)
			if code == 0 || !strings.Contains(out+errOut, lost) {
				t.Fatalf("flint backup with a %s blob missing = %d\n%s%s", tc.format, code, out, errOut)
			}
		})
	}
}

// TestServeRefusesInterruptedRestore checks that a data directory an
// interrupted restore left is never served.
func TestServeRefusesInterruptedRestore(t *testing.T) {
	dataDir := t.TempDir()
	os.WriteFile(filepath.Join(dataDir, backup.RestoreMarker), nil, 0o644)
	path := writeConfig(t, map[string]any{"listen": "127.0.0.1:0", "dataDir": dataDir})
	var stderr strings.Builder
	if code := serve(context.Background(), []string{"-config", path}, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "restore that did not finish") {
		t.Fatalf("serve = %d, %s", code, stderr.String())
	}
}

func TestBackupCLIErrors(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	os.WriteFile(pw, []byte("secret"), 0o600)
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"backup"}, 2, "-password-file is required"},
		{[]string{"backup", "extra"}, 2, "unexpected arguments"},
		{[]string{"backup", "-password-file", pw, "-url", "http://127.0.0.1:1"}, 1, "flint backup:"},
		{[]string{"backup", "list"}, 2, "usage:"},
		{[]string{"backup", "list", filepath.Join(dir, "missing")}, 1, "no such file"},
		{[]string{"backup", "verify", dir}, 1, "no complete backup"},
		{[]string{"backup", "verify", "-backup", "../etc", dir}, 1, "is not a backup ID"},
		{[]string{"restore", dir}, 2, "usage:"},
		{[]string{"restore", dir, filepath.Join(dir, "data")}, 1, "no complete backup"},
	} {
		code, _, errOut := runCLI(t, tc.args...)
		if code != tc.code || !strings.Contains(errOut, tc.want) {
			t.Errorf("flint %s = %d %q, want %d and %q", strings.Join(tc.args, " "), code, errOut, tc.code, tc.want)
		}
	}
}
