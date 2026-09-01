// Command nokkud is the Nokku daemon. It enrolls this host with the backend
// and serves SSH through an embedded certificate-authenticated server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokkud/internal/client"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/sshd"
	"github.com/nokku-sh/nokkud/internal/state"
	"github.com/nokku-sh/nokkud/internal/util"
)

func main() {
	p := paths.Default()

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

			// The sshd-server and sftp-server harness subcommands run against
			// caller-supplied state, so skip the default dir to keep
			// non-root test runs away from /var/lib/nokkud.
			if first := cmd.Args().First(); first != "sshd-server" && first != "sftp-server" {
				if err := p.Verify(); err != nil {
					return nil, err
				}
			}
			return ctx, nil
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			cache := state.NewCache(p)
			if err := cache.Load(); err != nil {
				return err
			}

			// Load the persisted config, then apply env/flag overrides only
			// when one was explicitly provided. This keeps a bare default
			// from clobbering a value the user already configured in
			// config.json.
			cfg := state.NewConfig(p)
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

			// Build the SSH server (when enabled) and then the client, so the
			// client wires the recording sink before the server ever accepts a
			// session. Shutdown is deferred because it is idempotent and also
			// covers exits that did not go through a context cancellation
			// (e.g. the daemon being rejected by the backend). The single ctx
			// flowing into ListenAndServe and Run drives the cancel; the
			// server drains against its own internal grace window.
			var sshSrv *sshd.Server
			if cfg.SSHAddr != "" {
				if err := util.IsRoot(); err != nil {
					return err
				}
				srv, err := sshd.New(sshd.OptionsFrom(p, cache, true))
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

			cli, err := client.New(p, cache, cfg, client.Options{
				Insecure:    cmd.Bool("insecure"),
				RequireTPM:  cmd.Bool("require-tpm"),
				EnrollToken: cmd.String("enroll"),
				CAID:        cmd.String("ca"),
			}, sshSrv)
			if err != nil {
				return fmt.Errorf("failed to initialize configuration: %w", err)
			}

			if sshSrv != nil {
				if _, listenErr := sshSrv.ListenAndServe(ctx, cfg.SSHAddr); listenErr != nil {
					return fmt.Errorf("listen on %s: %w", cfg.SSHAddr, listenErr)
				}
			}

			slog.Info("Starting nokkud", "version", buildinfo.Version)
			return cli.Run(ctx)
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
				Name:   "sshd-server",
				Usage:  "Run the embedded SSH server headless (CI interop harness)",
				Hidden: true,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "addr", Usage: "listen address", Value: "127.0.0.1:0"},
					&cli.StringFlag{
						Name:     "config-dir",
						Usage:    "state directory holding cache.json, the host key and the trusted CA pubkey",
						Required: true,
					},
					&cli.BoolFlag{
						Name:   "allow-nonroot",
						Usage:  "run as non-root; sessions restricted to the daemon's own account (tests only)",
						Hidden: true,
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					// Root is required to drop sessions to the target user's
					// privileges. --allow-nonroot is the test-harness escape
					// hatch. Without privilege dropping every session runs as
					// the daemon's own OS user, so the server is restricted
					// to that user's account only.
					nonRoot := cmd.Bool("allow-nonroot")
					if !nonRoot {
						if err := util.IsRoot(); err != nil {
							return err
						}
					}
					hp := paths.Paths{
						ConfigDir:  cmd.String("config-dir"),
						RecordsDir: filepath.Join(cmd.String("config-dir"), "recordings"),
						AuditDir:   filepath.Join(cmd.String("config-dir"), "audit"),
					}
					if err := hp.Verify(); err != nil {
						return err
					}

					cache := state.NewCache(hp)
					if err := cache.Load(); err != nil {
						return err
					}

					opts := sshd.OptionsFrom(hp, cache, false)
					if nonRoot {
						self, err := user.Current()
						if err != nil {
							return fmt.Errorf("resolve current user: %w", err)
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
						return fmt.Errorf("init ssh server: %w", err)
					}

					addr, err := srv.ListenAndServe(ctx, cmd.String("addr"))
					if err != nil {
						return fmt.Errorf("listen on %s: %w", cmd.String("addr"), err)
					}
					fmt.Println(addr.String())

					<-ctx.Done()
					return srv.Shutdown()
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
					cache := state.NewCache(p)
					if err := cache.Load(); err != nil {
						return err
					}
					cfg := state.NewConfig(p)
					if err := cfg.Load(); err != nil {
						return err
					}
					cli, err := client.New(p, cache, cfg, client.Options{
						Insecure:    cmd.Bool("insecure"),
						RequireTPM:  cmd.Bool("require-tpm"),
						EnrollToken: cmd.String("enroll"),
						CAID:        cmd.String("ca"),
					}, nil)
					if err != nil {
						return fmt.Errorf("failed to initialize configuration: %w", err)
					}
					if err = cli.DeleteDaemon(ctx); err != nil {
						slog.Warn(
							"failed to delete daemon from backend; local state is still removed",
							"error", err,
						)
					}
					p.Cleanup()
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
				Usage: "Disable TLS verification (only use for local testing)",
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
			&cli.StringFlag{
				Name:    "enroll",
				Aliases: []string{"e"},
				Usage:   "Enrollment token (first-time setup only)",
				Sources: cli.EnvVars("NOKKUD_ENROLL_TOKEN"),
			},
		},
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd.Name, err)
		os.Exit(1)
	}
}
