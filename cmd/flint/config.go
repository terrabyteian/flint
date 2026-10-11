package main

import (
	"fmt"
	"io"

	"github.com/terrabyteian/flint/internal/config"
)

const configUsage = `usage: flint config check <file>

Checks a configuration file the way flint serve does, without starting the
server. A file of "-" reads standard input.
`

// configCmd runs the config subcommands and returns the process exit code.
func configCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "check" {
		fmt.Fprint(stderr, configUsage)
		return 2
	}
	path := args[1]
	var err error
	if path == "-" {
		err = checkStdin(stdin)
	} else {
		_, err = config.Load(path)
	}
	if err != nil {
		fmt.Fprintf(stderr, "flint: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: ok\n", path)
	return 0
}

// checkStdin checks a configuration read from stdin.
func checkStdin(stdin io.Reader) error {
	b, err := io.ReadAll(stdin)
	if err == nil {
		_, err = config.Parse(b)
	}
	if err != nil {
		return fmt.Errorf("config <stdin>: %w", err)
	}
	return nil
}
