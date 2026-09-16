// Command nokkud enrolls this host with the backend and serves certificate-authenticated SSH.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

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
	"github.com/nokku-sh/nokkud/internal/util"
)

func main() {
	cmd := &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "nokkud",
		Usage:                 "zero-trust SSH access - certificate-authenticated and fully recorded",
		Description: `nokkud enrolls this server with Nokku and replaces the host sshd with an
embedded SSH server that authenticates users via short-lived SSH certificates.`,
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
		Action: func(ctx context.Context, cmd *cli.Command) error {
			cache := state.NewCache()
			if err := cache.Load(); err != nil {
				return err
			}

			// Apply env/flag overrides only when one was explicitly provided,
			// so a bare default cannot clobber a value from config.json.
			cfg := state.NewConfig()
			if err := cfg.Load(); err != nil {
				return err
			}
			if cmd.IsSet("api") {
				cfg.APIURL = strings.TrimRight(cmd.String("api"), "/")
			} else if cfg.APIURL == "" {
				cfg.APIURL = state.DefaultAPIURL
			}
			if cmd.IsSet("ssh-addr") {
				cfg.SSHAddr = cmd.String("ssh-addr")
			} else if cfg.SSHAddr == "" {
				cfg.SSHAddr = state.DefaultSSHAddr
			}
			if err := cfg.Save(); err != nil {
				return err
			}

			// The client wires the recording sink before the server accepts a
			// session. Deferred Shutdown is idempotent and always runs.
			var sshSrv *sshd.Server
			if cfg.SSHAddr != "" {
				if err := util.IsRoot(); err != nil {
					return err
				}
				srv, err := sshd.New(sshd.OptionsFrom(cache, true))
				if err != nil {
					return err
				}
				sshSrv = srv
			}
			defer func() {
				if sshSrv != nil {
					_ = sshSrv.Shutdown()
				}
			}()

			// Tokens never go on argv: read the env, or prompt when --enroll
			// runs on a terminal.
			token := os.Getenv("NOKKUD_ENROLL_TOKEN")
			if cmd.Bool("enroll") && token == "" {
				if !term.IsTerminal(int(os.Stdin.Fd())) {
					return errors.New("no enrollment token: set NOKKUD_ENROLL_TOKEN or run --enroll on a terminal")
				}
				fmt.Fprint(os.Stderr, "Enrollment token: ")
				secret, err := term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return fmt.Errorf("read enrollment token: %w", err)
				}
				fmt.Fprintln(os.Stderr)
				token = strings.TrimSpace(string(secret))
			}

			cl, err := newDaemonClient(ctx, cmd, token, cache, cfg, sshSrv)
			if err != nil {
				return err
			}

			if sshSrv != nil {
				if _, listenErr := sshSrv.ListenAndServe(ctx, cfg.SSHAddr); listenErr != nil {
					return fmt.Errorf("listen on %s: %w", cfg.SSHAddr, listenErr)
				}
			}

			slog.Info("starting nokkud", "version", buildinfo.Version)
			return cl.Run(ctx)
		},
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
				Name:        "reset",
				Usage:       "Cleanup application state and delete this daemon",
				Description: `Cleans up all local certificates, principal caches, and enrollment data. Use this to decommission this machine or before re-enrolling.`,
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if err := util.IsRoot(); err != nil {
						return err
					}
					cache := state.NewCache()
					if err := cache.Load(); err != nil {
						return err
					}
					cfg := state.NewConfig()
					if err := cfg.Load(); err != nil {
						return err
					}
					cl, err := newDaemonClient(ctx, cmd, "", cache, cfg, nil)
					if err != nil {
						return err
					}
					if err = cl.DeleteDaemon(ctx); err != nil {
						slog.Warn("delete daemon from backend failed, local state removed", "error", err)
					}
					paths.Cleanup()
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
				Name:  "insecure",
				Usage: "Disable TLS verification (only use for testing)",
			},
			&cli.BoolFlag{
				Name:    "require-tpm",
				Usage:   "Require a TPM 2.0 for request signing, refuse the software fallback key",
				Sources: cli.EnvVars("NOKKUD_REQUIRE_TPM"),
			},
			&cli.StringFlag{
				Name:    "ssh-addr",
				Usage:   "listen address for the embedded SSH server (set to empty to disable)",
				Sources: cli.EnvVars("NOKKUD_SSH_ADDR"),
			},
			&cli.StringFlag{
				Name:    "api",
				Usage:   "Nokku API URL",
				Sources: cli.EnvVars("NOKKUD_API_URL"),
			},
			&cli.StringFlag{
				Name:    "ca",
				Usage:   "SSH certificate authority uuid",
				Sources: cli.EnvVars("NOKKUD_CA_ID"),
			},
			&cli.BoolFlag{
				Name:  "enroll",
				Usage: "Enroll this host. Prompts for the token unless NOKKUD_ENROLL_TOKEN is set",
			},
		},
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd.Name, err)
		os.Exit(1)
	}
}

func newDaemonClient(
	ctx context.Context,
	cmd *cli.Command,
	token string,
	cache *state.Cache,
	cfg *state.Config,
	sshSrv *sshd.Server,
) (*client.Client, error) {
	cl, err := client.New(ctx, cache, cfg, client.Options{
		Insecure:    cmd.Bool("insecure"),
		RequireTPM:  cmd.Bool("require-tpm"),
		EnrollToken: token,
		CAID:        cmd.String("ca"),
	}, sshSrv)
	if err != nil {
		if errors.Is(err, tpm.ErrIdentityChanged) {
			return nil, fmt.Errorf(
				"the daemon signing key no longer matches this machine, re-enroll with `sudo nokkud --enroll`: %w",
				err,
			)
		}
		return nil, fmt.Errorf("initialize daemon client: %w", err)
	}
	return cl, nil
}
