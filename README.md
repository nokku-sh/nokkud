<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="./.github/logo_dark.svg">
    <source media="(prefers-color-scheme: dark)" srcset="./.github/logo_light.svg">
    <img src="./.github/logo_light.svg" width="80" alt="nokkud">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nokkud/releases"><img src="https://img.shields.io/github/v/tag/nokku-sh/nokkud?label=Version" alt="Version"></a>
  <a href="https://github.com/nokku-sh/nokkud/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nokkud/ci.yaml?branch=main&label=Build" alt="Build"></a>
  <a href="https://github.com/nokku-sh/nokkud/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nokku-sh/nokkud?label=License" alt="License"></a>
</p>

# nokkud

`nokkud` is the Nokku daemon for your servers. It runs its own small SSH server on port 4022, next to your normal `sshd`. It checks Nokku certificates, keeps the list of who may log in up to date and renews the host certificate.

- **No proxy in the path.** Every server serves its own SSH connections.
- **Works when the core is down.** Logins are checked against the last synced access list.
- **Your `sshd` stays yours.** It is never touched and stays on port 22 as your way back in.

`nokkud` is one of three parts. [`nokku`](https://github.com/nokku-sh/nokku) is the core that decides who may log in where. [`nk`](https://github.com/nokku-sh/nk) is the CLI on your own machine.

## Quick start

Install it. The installer also sets up the systemd or OpenRC service:

```bash
curl -fsSL https://get.nokku.sh/nokkud | sudo sh
```

Create an enrollment token in the Nokku web app, under **Infrastructure, Daemons**. Then enroll the server and start the daemon:

```bash
sudo nokkud enroll
sudo systemctl restart nokkud
```

`nokkud enroll` asks for the token and does not echo it.

On a self-hosted core, point the daemon at it:

```bash
sudo nokkud --api https://nokku.example.com enroll
```

The server shows up in the web app. Unless the token approves it automatically, someone has to approve it there before it serves logins.

## Network

Sessions reach the server in one of two ways, and `nk` tries both at once.

**Directly on port 4022.** This is the fastest path. Open the port for the networks your users connect from:

```bash
sudo ufw allow nokkud                                # Debian, Ubuntu
sudo firewall-cmd --permanent --add-service=nokkud   # Fedora, RHEL
sudo firewall-cmd --reload
```

On a cloud server, also allow TCP 4022 in the provider's firewall or security group.

**Through the relay.** The daemon keeps an outbound connection to the core, and sessions can travel over it. Nothing has to be opened, and the session stays encrypted end to end.

## Enrollment

- **Unattended installs:** set `NOKKUD_ENROLL_TOKEN` instead of answering the prompt. The token is never taken from the command line, where any local user could read it from the process list.
- **Before enrollment** the service exits with a clear error, and systemd does not restart it.
- **Enrolling again** is safe. With a token from another workspace it moves the server there and drops everything the old one trusted.

Everything `nokkud` owns lives under `/var/lib/nokkud/`.

## Install options

The installer adds the Cloudsmith repository and installs your distro's package (deb, rpm or apk). Other distros and pinned versions get the release tarball from GitHub. Pin a version with `--version <x.y.z>` or `NOKKUD_VERSION=<x.y.z>`.

Prefer to add the package repository yourself? The [package repository](https://broadcasts.cloudsmith.com/nokku/nokkud) has the apt, dnf and apk instructions.

<details>
<summary><b>Manual install from the tarball</b></summary>

Download the tarball for your architecture from [Releases](https://github.com/nokku-sh/nokkud/releases), then run the bundled installer:

```bash
tar -xzf nokkud_linux_amd64.tar.gz
sudo ./install.sh
```

Prefer to place things yourself? Copy [packaging/systemd/nokkud.service](packaging/systemd/nokkud.service) to `/etc/systemd/system/nokkud.service`, then register and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nokkud
```

On OpenRC or another init system, use [packaging/openrc/nokkud.openrc](packaging/openrc/nokkud.openrc) as a starting point.

</details>

## Configuration

| Flag            | Environment          | Purpose                                             |
| --------------- | -------------------- | --------------------------------------------------- |
| `--api`         | `NOKKUD_API_URL`     | Address of the core                                 |
| `--ssh-addr`    | `NOKKUD_SSH_ADDR`    | Where the SSH server listens. Default `:4022`       |
| `--require-tpm` | `NOKKUD_REQUIRE_TPM` | Require a TPM 2.0 and refuse the software key       |
| `--insecure`    | `NOKKUD_INSECURE`    | Turn off TLS verification. For testing only         |
| `--debug`       | `NOKKUD_DEBUG`       | Debug logging                                       |

Session rules like recording and port forwarding are set in the web app, per daemon or as a workspace default.

## Operations

```bash
sudo systemctl status nokkud
sudo journalctl -u nokkud -f
```

When the core is unreachable, logins keep working from the last synced access list. Access changes and certificate renewals resume once the daemon reconnects.

A restart or a package upgrade ends the sessions that are open on the daemon.

## Uninstall

Reset the daemon first. This removes the server from Nokku and deletes all local state, so Nokku access to the server stops:

```bash
sudo nokkud reset
```

Then remove the package (`apt remove nokkud`, `dnf remove nokkud` or `apk del nokkud`). After a manual install, stop the service and remove the binary instead:

```bash
sudo systemctl disable --now nokkud
sudo rm -f /usr/bin/nokkud
```

## More

- [Documentation](https://nokku.sh/docs), with the guide for [adding a server](https://nokku.sh/docs/guides/add-server-daemon)
- [SECURITY.md](./SECURITY.md), for how the daemon protects its key, how its SSH server behaves, and for reporting a vulnerability
- [CONTRIBUTING.md](./CONTRIBUTING.md), for building from source

## Hosting

<img alt="Static Badge" src="https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=flat-square&link=https%3A%2F%2Fcloudsmith.com"></img>

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com).
