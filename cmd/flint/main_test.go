package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		stdin      string
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
		{name: "config check stdin", args: []string{"config", "check", "-"}, stdin: `{"dataDir": "/var/lib/flint"}`, wantCode: 0, wantStdout: "-: ok\n"},
		{name: "config check invalid stdin", args: []string{"config", "check", "-"}, stdin: `{"dataDir": "relative", "bogus": 1}`, wantCode: 1, wantStderr: `config <stdin>: unknown field "bogus"`},
		{name: "config check invalid value", args: []string{"config", "check", "-"}, stdin: `{"dataDir": "relative"}`, wantCode: 1, wantStderr: "dataDir"},
		{name: "config check missing file", args: []string{"config", "check", "/nonexistent/flint.json"}, wantCode: 1, wantStderr: "/nonexistent/flint.json"},
		{name: "config no subcommand", args: []string{"config"}, wantCode: 2, wantStderr: "usage: flint config check"},
		{name: "config unknown subcommand", args: []string{"config", "lint", "x"}, wantCode: 2, wantStderr: "usage: flint config check"},
		{name: "config check extra args", args: []string{"config", "check", "a", "b"}, wantCode: 2, wantStderr: "usage: flint config check"},
		{name: "serve missing config", args: []string{"serve", "-config", "/nonexistent/flint.json"}, wantCode: 1, wantStderr: "/nonexistent/flint.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(tt.stdin), &stdout, &stderr)
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
