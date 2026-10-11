package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	dir := t.TempDir()
	writeConfig := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := writeConfig("valid.json", `{"dataDir": "/var/lib/flint"}`)
	unknown := writeConfig("unknown.json", `{"dataDir": "relative", "bogus": 1}`)
	invalid := writeConfig("invalid.json", `{"dataDir": "relative"}`)
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"version"}, wantCode: 0, wantStdout: "flint dev\n"},
		{name: "no args", args: nil, wantCode: 2, wantStderr: "usage: flint"},
		{name: "unknown", args: []string{"bogus"}, wantCode: 2, wantStderr: `unknown command "bogus"`},
		{name: "serve bad flag", args: []string{"serve", "-nope"}, wantCode: 2, wantStderr: "flag provided but not defined"},
		{name: "serve extra args", args: []string{"serve", "x"}, wantCode: 2, wantStderr: "unexpected arguments"},
		{name: "config check example", args: []string{"config", "check", "../../docs/flint.example.json"}, wantCode: 0, wantStdout: "../../docs/flint.example.json: ok\n"},
		{name: "config check valid", args: []string{"config", "check", valid}, wantCode: 0, wantStdout: valid + ": ok\n"},
		{name: "config check unknown field", args: []string{"config", "check", unknown}, wantCode: 1, wantStderr: "config " + unknown + `: unknown field "bogus"`},
		{name: "config check invalid value", args: []string{"config", "check", invalid}, wantCode: 1, wantStderr: "dataDir"},
		{name: "config check missing file", args: []string{"config", "check", "/nonexistent/flint.json"}, wantCode: 1, wantStderr: "/nonexistent/flint.json"},
		{name: "config no subcommand", args: []string{"config"}, wantCode: 2, wantStderr: "usage: flint config check"},
		{name: "config unknown subcommand", args: []string{"config", "lint", "x"}, wantCode: 2, wantStderr: "usage: flint config check"},
		{name: "config check extra args", args: []string{"config", "check", "a", "b"}, wantCode: 2, wantStderr: "usage: flint config check"},
		{name: "serve missing config", args: []string{"serve", "-config", "/nonexistent/flint.json"}, wantCode: 1, wantStderr: "/nonexistent/flint.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) || (tt.wantStdout == "" && stdout.Len() != 0) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) || (tt.wantStderr == "" && stderr.Len() != 0) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
