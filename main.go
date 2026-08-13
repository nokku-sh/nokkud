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

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	altsrc "github.com/urfave/cli-altsrc/v3"
	json "github.com/urfave/cli-altsrc/v3/json"
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

			// Update config
			cfg := state.NewConfig(p)
			if err := cfg.Load(); err != nil {
				return err
			}
			cfg.APIURL = cmd.String("api")
			cfg.SSHAddr = cmd.String("ssh-addr")
			if err := cfg.Save(); err != nil {
				return err
			}

			// Embedded SSH server, on by default. Set --ssh-addr to empty to
			// disable.
			var sshSrv *sshd.Server
			if cfg.SSHAddr != "" {
				srv, err := startSSHServer(ctx, p, cfg.SSHAddr, cache)
				if err != nil {
					return err
				}
				sshSrv = srv
			}
			defer func() {
				if sshSrv != nil {
					_ = sshSrv.Close()
				}
			}()

			cli, err := client.New(ctx, cmd, p, cache, cfg, sshSrv)
			if err != nil {
				return fmt.Errorf("failed to initialize configuration: %w", err)
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
						opts.Principals = func(username string) ([]string, bool) {
							if username != self.Username {
								return nil, false
							}
							return cache.GetUUIDs(username), true
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
					return nil
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
					cli, err := client.New(ctx, cmd, p, cache, cfg, nil)
					if err != nil {
						return fmt.Errorf("failed to initialize configuration: %w", err)
					}
					_ = cli.DeleteDaemon(ctx)
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
				Name:  "ssh-addr",
				Usage: "listen address for the embedded SSH server (set to empty to disable)",
				Value: ":4022",
				Sources: cli.NewValueSourceChain(
					cli.EnvVar("NOKKUD_SSH_ADDR"),
					json.JSON("ssh_addr", altsrc.NewStringPtrSourcer(new(p.ConfigFile()))),
				),
			},
			&cli.StringFlag{
				Name:  "api",
				Usage: "Nokku API URL",
				Value: "https://app.nokku.sh",
				Sources: cli.NewValueSourceChain(
					cli.EnvVar("NOKKUD_API_URL"),
					json.JSON("api_url", altsrc.NewStringPtrSourcer(new(p.ConfigFile()))),
				),
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

// startSSHServer runs the embedded SSH server on addr and returns it.
func startSSHServer(
	ctx context.Context,
	p paths.Paths,
	addr string,
	cache *state.Cache,
) (*sshd.Server, error) {
	if err := util.IsRoot(); err != nil {
		return nil, err
	}
	srv, err := sshd.New(sshd.OptionsFrom(p, cache, true))
	if err != nil {
		return nil, fmt.Errorf("init ssh server: %w", err)
	}
	if _, err = srv.ListenAndServe(ctx, addr); err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	return srv, nil
}
