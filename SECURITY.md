# Security Policy

## Supported Versions

Only the latest release of `nokkud` is supported for security fixes. Older
releases are not patched; if you are affected by a vulnerability, upgrade to
the newest tagged release.

## Reporting a Vulnerability

Please **do not** open a public issue for a suspected security vulnerability.
Use GitHub's private vulnerability reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Provide as much of the following as you can:

   - Affected `nokkud` version and platform/distribution
   - A description of the issue and its security impact
   - Steps to reproduce, or a minimal patch/poc
   - Any supporting logs (redact secrets)

Reports are handled confidentially. We will acknowledge receipt, and if you
would like to be credited in the release advisory or changelog, let us know;
this is optional but appreciated.

### Response timeline

- **Acknowledge** the report: within 48 hours
- **Triage** and classify severity: within 5 business days
- **Fix / mitigation / response**: we aim to provide a fix or clear guidance
  within 30 days, depending on the complexity and impact.

## Scope

The following are in scope for security reports:

- The `nokkud` daemon binary itself: enrollment token handling, generation
  and renewal of SSH host certificates, the embedded SSH server's
  certificate authentication and session handling, and the authenticated
  outbound control stream to the backend.
- Local state and configuration it writes, all under `/var/lib/nokkud/`:
  `config.json`, `cache.json`, `state.json`, the SSH host key, host
  certificate and trusted CA public key, `recordings/` and `audit/`.

### Out of scope

- The Nokku **backend** and web application (separate repositories).
- The SSH protocol itself and vulnerabilities in OpenSSH / `sshd`.
- OS/distribution and package-manager issues.
- The infrastructure hosting the Nokku backend.

## Security Notes / Threat Model

`nokkud` is a privileged daemon that holds an enrollment token and serves
SSH on its own port (`:4022` by default) via an embedded SSH server.
System sshd on `:22` is left untouched as the admin break-glass path and is
out of nokkud's security scope. The daemon keeps an authenticated outbound
control stream to the backend.

- Enrollment state and cached principals live under `/var/lib/nokkud/` and are
  protected by the daemon's privileges; treat this directory as sensitive.
- Principal checks fall back to the last local cache when the backend is
  unreachable; new policy updates and certificate renewals require a
  reconnect.
- **Session recordings** are written unredacted to `recordings/` and streamed to
  the backend, which scrubs credentials server-side after the upload
  completes. The daemon performs no redaction of its own, so anyone with
  access to the recordings directory or the backend's storage can read
  whatever was on the terminal. Password prompts are exempt: input is only
  recorded while the PTY has echo enabled.
- Releases are built via GoReleaser and signed/checksummed. Verify downloads
  against the published checksums and signatures.

### Embedded SSH server

- **Certificate-only authentication.** No passwords, no keyboard-interactive,
  no PAM. A login requires a user certificate signed by the workspace CA whose
  principal is mapped to the requested local user in the daemon's cache.
- **Offline window is bounded by certificate lifetime.** When the backend is
  unreachable, authentication still works against the cached CA key and
  principal map, but user certificates expire (backend-clamped TTL), so stale
  access grants can never outlive the cert. Revocation of a user while
  offline takes effect at the latest when that user's certificate expires.
- **Client environment is whitelisted.** Sessions accept only locale/terminal
  variables (`TERM`, `LANG`, `LC_*`, `TZ`, ...) from clients, never
  shell/loader-affecting variables (`PATH`, `LD_*`, `BASH_ENV`, `ENV`) or
  connection metadata (`SSH_*`). Certificates carrying a `force-command`
  critical option refuse all client-supplied environment.
- **Remote forwards are loopback-only by default** (OpenSSH's
  `GatewayPorts=no`), so an authorized user cannot expose services on the
  server's external interfaces. Direct (outbound `-L`) forwards are logged to
  the audit log with their destination.
- **Sessions run as the target OS user.** The daemon must run as root so it
  can drop privileges; it refuses to serve SSH unprivileged rather than
  silently running sessions as the wrong user.
- **Audit and recording are local-first.** Security events (auth, session,
  command, forward) are appended as rotated JSONL under
  `/var/lib/nokkud/audit/`; interactive sessions are recorded as gzipped
  asciicast under `/var/lib/nokkud/recordings/`, correlated to audit events
  via `session_id`. Non-interactive `exec` sessions are captured as `command`
  audit events (command line, user, exit code) but not byte-recorded. Both
  stores have size- and age-based retention; shipping them to the backend
  when connected is planned and reads the same files.
