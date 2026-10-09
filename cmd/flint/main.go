// Command flint is the flint artifact registry server and admin tool.
//
// Only the version subcommand exists so far; every other subcommand
// reports that it is not implemented yet.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is the release version, injected at build time with
// -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `usage: flint <command>

commands:
  version    print the flint version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the subcommand named by args and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "flint %s\n", version)
		return 0
	default:
		fmt.Fprintf(stderr, "flint: subcommand %q is not implemented\n\n%s", args[0], usage)
		return 2
	}
}
