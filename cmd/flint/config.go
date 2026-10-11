package main

import (
	"fmt"
	"io"

	"github.com/terrabyteian/flint/internal/config"
)

const configUsage = `usage: flint config check <file>

Checks a configuration file the way flint serve does, without starting the
server.
`

// configCmd runs the config subcommands and returns the process exit code.
func configCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "check" {
		fmt.Fprint(stderr, configUsage)
		return 2
	}
	path := args[1]
	if _, err := config.Load(path); err != nil {
		fmt.Fprintf(stderr, "flint: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: ok\n", path)
	return 0
}
