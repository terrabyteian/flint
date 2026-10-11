package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/gc"
)

// registryImage is an image pushed through the registry API.
type registryImage struct {
	manifest []byte
	blobs    [][]byte // config, then layers
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newRegistryImage(seed string, layers ...string) registryImage {
	img := registryImage{blobs: [][]byte{[]byte(`{"architecture":"amd64","os":"linux","seed":"` + seed + `"}`)}}
	descs := []map[string]any{}
	for _, l := range layers {
		img.blobs = append(img.blobs, []byte(l))
		descs = append(descs, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": sha([]byte(l)), "size": len(l)})
	}
	img.manifest, _ = json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(img.blobs[0]), "size": len(img.blobs[0])},
		"layers":        descs,
	})
	return img
}

// registryCall makes a registry API request with basic credentials and
// returns the status and body.
func registryCall(t *testing.T, method, url, user, pass string, body []byte, contentType string) (int, []byte) {
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
	return resp.StatusCode, b
}

// TestGCEndToEnd runs flint serve, pushes images, deletes one and some
// blob links, ages the stored blobs past the grace period, and runs
// flint gc against the server: a dry run reports what a run deletes and
// deletes nothing, the run deletes exactly the unreferenced blobs past
// the grace period, and every image still referenced pulls.
func TestGCEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	pwFile := filepath.Join(dir, "admin-password")
	if err := os.WriteFile(pwFile, []byte("admin-password-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeConfig(t, map[string]any{
		"listen":       "127.0.0.1:0",
		"dataDir":      dataDir,
		"repositories": []any{map[string]any{"name": "docker-local", "format": "oci", "type": "hosted"}},
		"auth":         map[string]any{"bootstrapAdmin": map[string]any{"username": "admin", "passwordFile": pwFile}},
		"gc":           map[string]any{"gracePeriod": "2h"},
	})
	p := startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("flint exited at startup:\n%s", p.output())
	}
	base := "http://" + p.addr
	const user, pass = "admin", "admin-password-123"
	call := func(method, path string, body []byte, contentType string) (int, []byte) {
		t.Helper()
		return registryCall(t, method, base+path, user, pass, body, contentType)
	}
	push := func(name, tag string, img registryImage) {
		t.Helper()
		for _, b := range img.blobs {
			if code, out := call("POST", "/v2/"+name+"/blobs/uploads/?digest="+sha(b), b, ""); code != http.StatusCreated {
				t.Fatalf("blob push = %d %s", code, out)
			}
		}
		if code, out := call("PUT", "/v2/"+name+"/manifests/"+tag, img.manifest, "application/vnd.oci.image.manifest.v1+json"); code != http.StatusCreated {
			t.Fatalf("manifest push = %d %s", code, out)
		}
	}
	pull := func(name, tag string, img registryImage) {
		t.Helper()
		if code, b := call("GET", "/v2/"+name+"/manifests/"+tag, nil, ""); code != http.StatusOK || !bytes.Equal(b, img.manifest) {
			t.Fatalf("manifest pull of %s:%s = %d %s", name, tag, code, b)
		}
		for _, want := range img.blobs {
			if code, b := call("GET", "/v2/"+name+"/blobs/"+sha(want), nil, ""); code != http.StatusOK || !bytes.Equal(b, want) {
				t.Fatalf("blob pull of %s:%s = %d %.100s", name, tag, code, b)
			}
		}
	}
	blobPath := func(d string) string {
		h := strings.TrimPrefix(d, "sha256:")
		return filepath.Join(dataDir, "blobs", "sha256", h[:2], h)
	}

	keep := newRegistryImage("keep", "shared layer", "keep layer")
	drop := newRegistryImage("drop", "shared layer", "drop layer")
	push("docker-local/app", "keep", keep)
	push("docker-local/app", "drop", drop)
	// Delete image drop and the links of the blobs only it uses; the
	// shared layer stays linked and referenced by keep.
	if code, out := call("DELETE", "/v2/docker-local/app/manifests/"+sha(drop.manifest), nil, ""); code != http.StatusAccepted {
		t.Fatalf("manifest delete = %d %s", code, out)
	}
	for _, b := range [][]byte{drop.blobs[0], drop.blobs[2]} {
		if code, out := call("DELETE", "/v2/docker-local/app/blobs/"+sha(b), nil, ""); code != http.StatusAccepted {
			t.Fatalf("blob delete = %d %s", code, out)
		}
	}
	// Age every stored blob past the grace period, then add a young
	// unreferenced one.
	old := time.Now().Add(-3 * time.Hour)
	filepath.Walk(filepath.Join(dataDir, "blobs"), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			os.Chtimes(path, old, old)
		}
		return err
	})
	young := []byte("young and unreferenced")
	call("POST", "/v2/docker-local/app/blobs/uploads/?digest="+sha(young), young, "")
	call("DELETE", "/v2/docker-local/app/blobs/"+sha(young), nil, "")
	garbage := []string{sha(drop.manifest), sha(drop.blobs[0]), sha(drop.blobs[2])}

	gcRun := func(args ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := gcCmd(context.Background(), args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	auth := []string{"-url", base, "-user", user, "-password-file", pwFile}

	code, out, errOut := gcRun(append([]string{"run", "-dry-run"}, auth...)...)
	if code != 0 || !strings.Contains(out, "would delete:    3 blobs") || !strings.Contains(out, "succeeded (dry run)") {
		t.Fatalf("flint gc run -dry-run = %d\n%s%s", code, out, errOut)
	}
	for _, d := range garbage {
		if !strings.Contains(out, d) {
			t.Errorf("the dry run does not list %s:\n%s", d, out)
		}
		if _, err := os.Stat(blobPath(d)); err != nil {
			t.Errorf("the dry run deleted %s: %v", d, err)
		}
	}

	code, out, errOut = gcRun(append([]string{"run", "-json"}, auth...)...)
	var rep gc.Report
	if err := json.Unmarshal([]byte(out), &rep); code != 0 || err != nil {
		t.Fatalf("flint gc run -json = %d %v\n%s%s", code, err, out, errOut)
	}
	if rep.State != gc.StateSucceeded || rep.DryRun || rep.Actor != "admin" || rep.Deleted.Blobs != 3 || rep.InGracePeriod.Blobs != 1 ||
		rep.GracePeriod != "2h0m0s" {
		t.Errorf("report = %+v", rep)
	}
	for _, d := range garbage {
		if _, err := os.Stat(blobPath(d)); err == nil {
			t.Errorf("blob %s survived", d)
		}
	}
	if _, err := os.Stat(blobPath(sha(young))); err != nil {
		t.Errorf("the young blob was deleted: %v", err)
	}
	pull("docker-local/app", "keep", keep)
	if code, _ := call("GET", "/v2/docker-local/app/manifests/drop", nil, ""); code != http.StatusNotFound {
		t.Errorf("deleted image pull = %d", code)
	}
	for _, msg := range []string{"garbage collection started", "garbage collection deleted a blob", "garbage collection finished"} {
		if !p.hasLog(msg) {
			t.Errorf("no log %q:\n%s", msg, p.output())
		}
	}
	_, metricsOut := get(t, http.DefaultClient, base+"/metrics")
	for _, want := range []string{"flint_gc_reclaimed_blobs_total 3", `flint_gc_runs_total{mode="sweep",result="succeeded"} 1`,
		`flint_gc_runs_total{mode="dry_run",result="succeeded"} 1`} {
		if !strings.Contains(metricsOut, want+"\n") {
			t.Errorf("metrics lack %q", want)
		}
	}

	// A run that is started and left, then the status.
	code, out, errOut = gcRun(append([]string{"run", "-detach"}, auth...)...)
	if code != 0 || !strings.Contains(out, "garbage collection started") {
		t.Fatalf("flint gc run -detach = %d\n%s%s", code, out, errOut)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, out, errOut = gcRun(append([]string{"status"}, auth...)...)
		if code != 0 {
			t.Fatalf("flint gc status = %d\n%s%s", code, out, errOut)
		}
		if !strings.Contains(out, "running:") || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(out, "last run:") || !strings.Contains(out, "succeeded") || !strings.Contains(out, "grace period: 2h0m0s") ||
		!strings.Contains(out, "schedule:     none") {
		t.Errorf("flint gc status:\n%s", out)
	}

	// Failures: wrong credentials, and none.
	wrongFile := filepath.Join(dir, "wrong-password")
	if err := os.WriteFile(wrongFile, []byte("wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := gcRun("status", "-url", base, "-user", user, "-password-file", wrongFile); code != 1 || !strings.Contains(errOut, "401") {
		t.Errorf("flint gc status with a wrong password = %d %s", code, errOut)
	}
	if code, _, errOut := gcRun("status", "-url", base); code != 2 || !strings.Contains(errOut, "-password-file is required") {
		t.Errorf("flint gc status without credentials = %d %s", code, errOut)
	}
	t.Setenv("FLINT_URL", base)
	if code, out, errOut := gcRun("status", "-json", "-user", user, "-password-file", pwFile); code != 0 ||
		!strings.Contains(out, `"gracePeriod": "2h0m0s"`) {
		t.Errorf("flint gc status with FLINT_URL = %d\n%s%s", code, out, errOut)
	}

	// The report survives a restart.
	p.cmd.Process.Signal(os.Interrupt)
	if code := p.wait(t); code != 0 {
		t.Fatalf("flint exited %d:\n%s", code, p.output())
	}
	p = startFlint(t, "serve", "-config", cfgPath)
	t.Setenv("FLINT_URL", "http://"+p.addr)
	if code, out, errOut := gcRun("status", "-user", user, "-password-file", pwFile); code != 0 || !strings.Contains(out, "last run:") {
		t.Errorf("flint gc status after a restart = %d\n%s%s", code, out, errOut)
	}
}

func TestGCUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"sweep"}, {"run", "extra"}, {"status", "-dry-run"}, {"run", "-nope"}} {
		var stdout, stderr bytes.Buffer
		if code := gcCmd(context.Background(), args, &stdout, &stderr); code != 2 ||
			!strings.Contains(stderr.String(), "usage: flint gc") && !strings.Contains(stderr.String(), "unexpected arguments") {
			t.Errorf("flint gc %q = %d\n%s", args, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"gc"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "-password-file") {
		t.Errorf("flint gc = %d\n%s", code, stderr.String())
	}
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 30: "5.0 GiB", 3 << 50: "3.0 PiB",
		1 << 62: "4.0 EiB"} {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
