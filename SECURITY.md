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
  `config.json`, `cache.json`, `state.json`, `ssh_host_signer.json` (the
  TPM-backed or machine-wrapped host identity), the SSH host public key,
  host certificate and trusted CA public key, `recordings/` and `audit/`.

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
- **Session recordings** are written unredacted to `recordings/` and uploaded
  to the backend, which scrubs credential patterns server-side after the
  upload completes. Scrubbing is best effort: a failure leaves the upload
  as-is and raises a `recording.scrub_failed` audit event rather than
  retrying. The daemon performs no redaction of its own, so anyone with
  access to the recordings directory or the backend's storage can read
  whatever was on the terminal. Both interactive and non-interactive
  sessions are byte-recorded. Interactive input is recorded only while the
  PTY has echo enabled, so password prompts are exempt; a non-interactive
  `exec` session has no echo signal, so only its output is captured.
- **Machine identity.** Every signing identity is ECDSA P-256, TPM-resident
  or a software key wrapped to the machine fingerprint. With a TPM, the
  private key never leaves the device. The TPM primary is created without an
  auth value or PCR policy, so any process that can open `/dev/tpmrm0` can use
  the identity. Restrict the device to the daemon's uid. Without a TPM, the
  software key is wrapped with a key derived from the machine's public
  fingerprint: that only stops copying the state file to a different machine,
  not reading it on the machine itself.
- Releases are built via GoReleaser. Each release publishes
  `nokkud_checksums.txt`, a cosign signature bundle for it
  (`nokkud_checksums.txt.sigstore.json`), and a CycloneDX SBOM per archive.
  `install.sh` verifies the SHA-256 of the tarball against the manifest,
  verifies the manifest with cosign when it is available, and stops on a
  mismatch. The manifest can also be checked by hand with `cosign verify-blob`
  against the bundle and the GitHub Actions OIDC issuer.

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
- **Per-connection channel cap.** Sessions plus port and agent forwards count
  against `MaxChannels` for the life of each channel, so one authorized
  connection cannot exhaust the daemon's file descriptors or goroutines.
- **Retired CA grace window.** After a CA rollover the previous CA stays
  trusted for a grace window so certificates it signed keep working. The
  backend can set `drop_retired_ca` to stop trusting it immediately.
- **`/etc/nologin` is honored.** When the file exists, logins are refused for
  every user except root, matching OpenSSH, so a machine can be put into
  maintenance.
- **Account lock and expiry are the OS's job.** Sessions never go through PAM,
  so `pam_limits`, `pam_access`, locked accounts, and password expiry are not
  enforced by the daemon. The login shell from the password database is used
  verbatim, so a `nologin` or `false` shell still ends the session. A granted
  user runs with their own OS privileges and no session resource cap; bound
  them with systemd slices or per-user limits if that matters for your threat
  model.
- **Audit and recording are local-first.** Security events (auth, session,
  command, forward) are appended as rotated JSONL under
  `/var/lib/nokkud/audit/`; interactive sessions are recorded as gzipped
  asciicast under `/var/lib/nokkud/recordings/`, correlated to audit events
  via `session_id`. Non-interactive `exec` sessions are captured both as
  `command` audit events (command line, user, exit code) and as recordings
  (output only). Recordings are uploaded to the backend when connected.
  Both stores have size- and age-based retention.
