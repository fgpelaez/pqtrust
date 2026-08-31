// Command pqtrustd is the pqtrust certificate authority daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fgpelaez/pqtrust/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pqtrustd:", err)
		os.Exit(1)
	}
}

func usage() string {
	return `usage: pqtrustd <command> [flags]

commands:
  serve                 run the certificate authority API server
  token create -name X  mint an API token (printed once)
  version               print the pqtrust version

flags:
  -config path          configuration file (default: none, built-in defaults)
`
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage())
		return fmt.Errorf("a command is required")
	}
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		configPath := fs.String("config", "", "path to config.yaml")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serve(ctx, *configPath)

	case "token":
		if len(args) < 2 || args[1] != "create" {
			return fmt.Errorf("usage: pqtrustd token create -name <name>")
		}
		fs := flag.NewFlagSet("token create", flag.ContinueOnError)
		configPath := fs.String("config", "", "path to config.yaml")
		name := fs.String("name", "", "human-readable token name")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		return runTokenCreate(*configPath, *name, os.Stdout)

	case "version":
		fmt.Println(version.Version)
		return nil

	default:
		fmt.Print(usage())
		return fmt.Errorf("unknown command %q", args[0])
	}
}
