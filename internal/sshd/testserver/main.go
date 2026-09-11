// Command testserver runs the embedded SSH server headless for the interop
// tests. It is built by internal/sshd/interop_test.go and is not shipped.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"syscall"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/sshd"
	"github.com/nokku-sh/nokkud/internal/state"
	"github.com/nokku-sh/nokkud/internal/util"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	configDir := flag.String(
		"config-dir", "",
		"state directory holding cache.json, the host key and the trusted CA pubkey",
	)
	allowNonRoot := flag.Bool("allow-nonroot", false, "run as non-root, sessions restricted to this account")
	flag.Parse()

	// Mirror the daemon's sftp-server entrypoint, which the embedded server
	// re-execs as the target user for SFTP sessions.
	if flag.Arg(0) == "sftp-server" {
		if flag.NArg() != 2 {
			fail("usage: testserver sftp-server <home>")
		}
		if err := sshd.ServeSFTP(flag.Arg(1)); err != nil {
			fail(err.Error())
		}
		return
	}

	if *configDir == "" {
		fail("config-dir is required")
	}
	if !*allowNonRoot {
		if err := util.IsRoot(); err != nil {
			fail(err.Error())
		}
	}
	if err := os.Setenv("NOKKUD_DATA_DIR", *configDir); err != nil {
		fail(err.Error())
	}
	if err := paths.Verify(); err != nil {
		fail(err.Error())
	}

	cache := state.NewCache()
	if err := cache.Load(); err != nil {
		fail(err.Error())
	}

	opts := sshd.OptionsFrom(cache, false)
	if *allowNonRoot {
		// Without privilege dropping every session runs as this account, so
		// only this account may log in.
		self, err := user.Current()
		if err != nil {
			fail(err.Error())
		}
		opts.Principals = func(username string) []string {
			if username != self.Username {
				return nil
			}
			return cache.GetUUIDs(username)
		}
	}

	srv, err := sshd.New(opts)
	if err != nil {
		fail(err.Error())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bound, err := srv.ListenAndServe(ctx, *addr)
	if err != nil {
		fail(err.Error())
	}
	fmt.Println(bound.String())

	<-ctx.Done()
	_ = srv.Shutdown()
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
