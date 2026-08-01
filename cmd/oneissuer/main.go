// Command oneissuer runs the single-issuer service and operational subcommands.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/oneissuer/oneissuer/internal/app"
	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/observability"
)

var (
	version   = "development"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	build := observability.NewBuildInfo(version, commit, buildTime)
	exitCode := app.Execute(ctx, os.Args[1:], config.LookupEnv(os.LookupEnv), os.Stdout, os.Stderr, build)
	os.Exit(exitCode)
}
