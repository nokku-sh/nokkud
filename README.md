<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="./.github/logo_dark.svg">
    <source media="(prefers-color-scheme: dark)" srcset="./.github/logo_light.svg">
    <img src="./.github/logo_light.svg" width="80" alt="nokkud">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nokkud/releases"><img src="https://img.shields.io/github/v/tag/nokku-sh/nokkud?label=Version" alt="Version"></a>
  <a href="https://github.com/nokku-sh/nokkud/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nokkud/test.yaml?branch=main&label=Build" alt="Build"></a>
  <a href="https://github.com/nokku-sh/nokkud/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nokku-sh/nokkud?label=License" alt="License"></a>
</p>

# nokkud: The Edge Daemon

`nokkud` is the Nokku daemon for your servers. It serves as an embedded SSH server that automatically renews host certificates and strictly enforces access policies synced from the Nokku backend.

## Why `nokkud`?

- **Zero Bottlenecks:** Every enrolled server serves its own SSH connections directly. No central proxy means lower latency and no single point of failure for data-plane traffic.
- **Offline Resiliency:** If the backend control plane is unavailable, principal checks use the last local cache. You are never locked out.
- **Break-Glass Safety:** Your system `sshd` is never touched. It stays safely on port 22 as a fallback, while Nokku traffic runs on port 4022.
- **TPM 2.0**: machines with a TPM (or a vTPM on AWS, GCP, Azure, Proxmox, ...) sign with a key generated inside the TPM that never leaves it. The key is derived deterministically, so it survives reboots without storing anything.
- **Software fallback**: machines without a TPM use a software key encrypted at rest with a key derived from the machine's identity (`/etc/machine-id` and friends).

## Install & Firewall

Install the binary, it will setup the systemd/OpenRC service, and load the AppArmor/SELinux policy:

```bash
curl -fsSL https://get.nokku.sh/nokkud | sudo sh
```

The installer prefers your distro's package (deb/rpm/apk) via the Cloudsmith
repository and falls back to the GitHub release tarball.

Prefer manual packages? See the [package repository](https://broadcasts.cloudsmith.com/nokku/nokkud) for apt/dnf/apk install instructions.

Open port 4022 on your firewall (nokkud serves SSH directly):

```bash
sudo ufw allow nokkud # 4022/tcp
# OR
sudo firewall-cmd --permanent --add-service=nokkud # 4022/tcp
sudo firewall-cmd --reload
```

## Enroll the Server

Generate an enrollment token in the Nokku web app, then run:

```bash
sudo systemctl stop nokkud
sudo nokkud --enroll <TOKEN>
sudo systemctl start nokkud
```

Everything `nokkud` owns lives securely under `/var/lib/nokkud/`. No long-lived secrets live on the machine; it proves possession of its TPM or encrypted software key with DPoP.

### Manual install

Download the latest binary from [Releases](https://github.com/nokku-sh/nokkud/releases).

Create the systemd unit at `/etc/systemd/system/nokkud.service` (also shipped at [packaging/systemd/nokkud.service](packaging/systemd/nokkud.service)).
Then register and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nokkud
```

Running OpenRC or another init system? Use [packaging/openrc/nokkud.openrc](packaging/openrc/nokkud.openrc) as a starting point.

## Configuration

| Flag            | Environment           | Purpose                                              |
| --------------- | --------------------- | ---------------------------------------------------- |
| `--api`         | `NOKKUD_API_URL`      | Backend URL                                          |
| `--enroll`      | `NOKKUD_ENROLL_TOKEN` | Enrollment token                                     |
| `--ca`          | `NOKKUD_CA_ID`        | Certificate authority UUID                           |
| `--ssh-addr`    | `NOKKUD_SSH_ADDR`     | Embedded SSH server listen address (default `:4022`) |
| `--debug`       | `NOKKUD_DEBUG`        | Debug logging                                        |
| `--insecure`    | none                  | Disable TLS verification (insecure!)                 |
| `--require-tpm` | `NOKKUD_REQUIRE_TPM`  | Require a TPM and refuse software fallback           |

## Operations

```bash
sudo systemctl status nokkud
sudo journalctl -u nokkud -f
```

> [!NOTE]
> If the backend is unavailable, principal checks use the last local cache. Policy updates and certificate renewals resume once the daemon reconnects.

## Uninstall

Reset the daemon first to remove its backend registration and all local state (this stops Nokku access. The trusted CA, host certificate, and principal cache go with it):

```bash
sudo nokkud reset
```

Then stop and disable the service and remove the binary:

```bash
sudo systemctl disable --now nokkud
rm -f /usr/bin/nokkud
```

## Hosting

<img alt="Static Badge" src="https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=flat-square&link=https%3A%2F%2Fcloudsmith.com"></img>

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com).
