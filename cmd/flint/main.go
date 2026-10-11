// Command flint is the flint artifact registry server and admin tool.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version is the release version, injected at build time with
// -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `usage: flint <command> [flags]

commands:
  serve      run the registry server (flint serve -config <file>)
  config     check a configuration file (flint config check <file>)
  version    print the flint version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes the subcommand named by args and returns the process exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		// The first SIGINT or SIGTERM starts a graceful shutdown; once it
		// has, the default handling is restored, so a second one kills
		// the process at once.
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		context.AfterFunc(ctx, stop)
		return serve(ctx, args[1:], stderr)
	case "config":
		return configCmd(args[1:], stdin, stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "flint %s\n", version)
		return 0
	default:
		fmt.Fprintf(stderr, "flint: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
