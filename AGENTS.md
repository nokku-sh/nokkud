# nokkud

nokkud is the Nokku edge daemon: it enrolls a host with the backend, replaces
the host's SSH surface with an embedded certificate-authenticated server on
:4022, records sessions, and serves from cache when the backend is down. The
ecosystem is five sibling repos: `nokku` (backend), `nokkud` (this one),
`nk` (CLI), `mon` (shared primitives), and `protos` (proto source). Read
`../nokku/docs/PRODUCT.md` before cross-repo work.

## Commands

```bash
task build    # CGO_ENABLED=0 build, installs to /usr/local/bin (sudo)
task gen      # buf generate
task lint     # tidy, fmt, vet, govulncheck, test -race, golangci-lint
task fuzz     # every Fuzz target, FUZZTIME=30s default
task selinux  # build the SELinux policy package
```

Plain `go test ./...` works.

## Layout

- `main.go` - CLI: flags, enrollment token resolution, the `reset` command.
- `internal/client` - backend connection: DPoP client, enrollment, the
  control stream, uploads.
- `internal/sshd` - the embedded SSH server on :4022. Cert auth, sessions,
  sftp.
- `internal/state` - persisted config and the synced cache under
  `/var/lib/nokkud`.
- `internal/recording` - asciicast v3 recording and chunk upload.
- `internal/hostcerts` - host key and host certificate handling.
- `internal/ptysession` - pty plumbing for sessions.
- `internal/audit`, `internal/sysutil`, `internal/util`, `internal/paths`,
  `internal/leaktest` - support code.
- `packaging/` - SELinux policy and packaging files.
- `internal/gen` - generated proto code. Never hand-edit.

## Conventions

- Enrollment reads the token from `NOKKUD_ENROLL_TOKEN` or the `--enroll`
  no-echo prompt. Never argv.
- System sshd on port 22 is never touched. nokkud owns :4022 only.
- The principal cache must survive a backend outage. Auth decisions read the
  cache, the cache is never traded for freshness.
- The daemon's on-disk state lives only under `/var/lib/nokkud`. It never
  writes under `/etc/ssh`.
- Packaging files live under `packaging/`.
- Machine identity uses the `nokku-daemon` and `nokku-daemon-host` salts from
  the registry in `../mon/README.md`.

## Danger points

- Never write outside `/var/lib/nokkud`.
