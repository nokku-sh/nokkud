// Command nokkud enrolls this host with the backend and serves certificate-authenticated SSH.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/nokku-sh/mon/tpm"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/nokku-sh/nokkud/internal/client"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/sshd"
	"github.com/nokku-sh/nokkud/internal/state"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

func main() {
	cmd := &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "nokkud",
		Usage:                 "zero-trust SSH access",
		Description: `nokkud enrolls this server with Nokku and runs an embedded SSH server beside
the host sshd (on :4022 by default) that authenticates users via short-lived
SSH certificates. The host sshd on port 22 is never touched.`,
		Version: buildinfo.String(),
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logx.Init(cmd.Bool("debug"))

			// The sftp-server harness subcommand runs against a caller-supplied
			// home, so keep it away from the default data dir.
			if cmd.Args().First() != "sftp-server" {
				if err := paths.Verify(); err != nil {
					return nil, err
				}
			}
			return ctx, nil
		},
		Action: run,
		Commands: []*cli.Command{
			{
				Name:   "sftp-server",
				Usage:  "Serve the SFTP protocol over stdin/stdout (spawned by the embedded SSH server)",
				Hidden: true,
				Action: func(_ context.Context, cmd *cli.Command) error {
					args := cmd.Args().Slice()
					if len(args) != 1 {
						return errors.New("usage: nokkud sftp-server <home>")
					}
					return sshd.ServeSFTP(args[0])
				},
			},
			{
				Name:  "enroll",
				Usage: "Enroll this host with Nokku, then exit",
				Description: `Prompts for the enrollment token from the Nokku web app, or reads
NOKKUD_ENROLL_TOKEN for unattended installs. The token never goes on the command line.
Run it again to move the host to another workspace. Restart the service afterwards.`,
				Action: enroll,
			},
			{
				Name:        "reset",
				Usage:       "Cleanup application state and delete this daemon",
				Description: `Cleans up all local certificates, principal caches, and enrollment data. Use this to decommission this machine or before re-enrolling.`,
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if err := sysutil.IsRoot(); err != nil {
						return err
					}
					// Local state goes even when the backend or the signing
					// key is gone, else a broken identity could never be reset.
					defer paths.Cleanup()
					cache, cfg, err := loadState(cmd)
					if err != nil {
						slog.Warn("load local state, removing it anyway", "error", err)
						return nil
					}
					cl, err := newDaemonClient(ctx, cmd, "", cache, cfg)
					if err == nil {
						err = cl.Unenroll(ctx)
					}
					if err != nil {
						slog.Warn("delete daemon from backend failed, local state removed", "error", err)
					}
					return nil
				},
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "debug",
				Usage:   "Enable debug logging",
				Sources: cli.EnvVars("NOKKUD_DEBUG"),
			},
			&cli.BoolFlag{
				Name:    "insecure",
				Usage:   "Disable TLS verification (only use for testing)",
				Sources: cli.EnvVars("NOKKUD_INSECURE"),
			},
			&cli.BoolFlag{
				Name:    "require-tpm",
				Usage:   "Require a TPM 2.0 for request signing, refuse the software fallback key",
				Sources: cli.EnvVars("NOKKUD_REQUIRE_TPM"),
			},
			&cli.StringFlag{
				Name:    "ssh-addr",
				Usage:   "listen address for the embedded SSH server",
				Value:   ":4022",
				Sources: cli.EnvVars("NOKKUD_SSH_ADDR"),
			},
			&cli.StringFlag{
				Name:    "api",
				Usage:   "Nokku API URL",
				Sources: cli.EnvVars("NOKKUD_API_URL"),
			},
		},
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd.Name, err)
		os.Exit(1)
	}
}

// errNotEnrolled exits with EX_CONFIG, which the unit file does not restart.
var errNotEnrolled = cli.Exit("nokkud: this host is not enrolled, run: sudo nokkud enroll", 78)

func run(ctx context.Context, cmd *cli.Command) error {
	if err := sysutil.IsRoot(); err != nil {
		return err
	}
	cache, cfg, err := loadState(cmd)
	if err != nil {
		return err
	}
	if cfg.DaemonID == "" {
		return errNotEnrolled
	}
	cl, err := newDaemonClient(ctx, cmd, "", cache, cfg)
	if err != nil {
		return err
	}

	srv, err := sshd.New(sshd.Options{
		Principals:    cache.CertPrincipals,
		Policy:        sshd.PolicyFrom(cache.DaemonConfig()),
		RecordingSink: cl.RecordingSink,
	})
	if err != nil {
		return err
	}
	srv.SetTrust(cache.CAs())
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", cmd.String("ssh-addr"))
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cmd.String("ssh-addr"), err)
	}
	slog.Info("starting nokkud", "version", buildinfo.Version, "ssh_addr", l.Addr())

	// Serve stops with ctx, so a client exit (rejection) must cancel it too.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() { srv.Serve(ctx, l) })
	addr, err := netip.ParseAddrPort(l.Addr().String())
	if err != nil {
		return err
	}
	err = cl.Run(ctx, srv, addr)
	cancel()
	wg.Wait()
	return err
}

func enroll(ctx context.Context, cmd *cli.Command) error {
	if err := sysutil.IsRoot(); err != nil {
		return err
	}
	cache, cfg, err := loadState(cmd)
	if err != nil {
		return err
	}
	token, err := enrollToken()
	if err != nil {
		return err
	}
	if _, err = newDaemonClient(ctx, cmd, token, cache, cfg); err != nil {
		return err
	}
	fmt.Println("Enrolled. Start the daemon with: sudo systemctl restart nokkud")
	return nil
}

// loadState reads the persisted state. The API URL is bound to the
// enrollment, so it is persisted, and the flag only wins when given.
func loadState(cmd *cli.Command) (*state.Cache, *state.Config, error) {
	cache := state.NewCache()
	if err := cache.Load(); err != nil {
		return nil, nil, err
	}
	cfg := new(state.Config)
	if err := cfg.Load(); err != nil {
		return nil, nil, err
	}
	if cmd.IsSet("api") {
		cfg.APIURL = strings.TrimRight(cmd.String("api"), "/")
	}
	if cfg.APIURL == "" {
		cfg.APIURL = state.DefaultAPIURL
	}
	return cache, cfg, cfg.Save()
}

// enrollToken reads the token from the env, or prompts on a terminal. Tokens
// never go on argv, where any local user could read them.
func enrollToken() (string, error) {
	if token := os.Getenv("NOKKUD_ENROLL_TOKEN"); token != "" {
		return token, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no enrollment token: set NOKKUD_ENROLL_TOKEN or run on a terminal")
	}
	fmt.Fprint(os.Stderr, "Enrollment token: ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read enrollment token: %w", err)
	}
	return strings.TrimSpace(string(secret)), nil
}

func newDaemonClient(
	ctx context.Context,
	cmd *cli.Command,
	token string,
	cache *state.Cache,
	cfg *state.Config,
) (*client.Client, error) {
	cl, err := client.New(ctx, cache, cfg, client.Options{
		Insecure:    cmd.Bool("insecure"),
		RequireTPM:  cmd.Bool("require-tpm"),
		EnrollToken: token,
	})
	if errors.Is(err, tpm.ErrIdentityChanged) {
		return nil, fmt.Errorf(
			"the daemon signing key no longer matches this machine, re-enroll with `sudo nokkud enroll`: %w",
			err,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("initialize daemon client: %w", err)
	}
	return cl, nil
}
