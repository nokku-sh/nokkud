#!/bin/sh
set -e

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Upgrades call this too (Debian passes "upgrade", RPM passes 1). Stopping
# then would leave the host without nokkud until someone starts it again.
# RPM passes 0, Debian passes "remove". Alpine runs this exclusively on uninstalls.
if [ "$1" != "0" ] && [ "$1" != "remove" ] && [ ! -f /etc/alpine-release ]; then
	exit 0
fi

# --- systemd ---
if has_cmd systemctl && [ -f /usr/lib/systemd/system/nokkud.service ]; then
	systemctl disable --now nokkud.service >/dev/null 2>&1 || true
fi

# --- OpenRC ---
if has_cmd rc-update && [ -f /etc/init.d/nokkud ]; then
	rc-service nokkud stop >/dev/null 2>&1 || true
	rc-update del nokkud default >/dev/null 2>&1 || true
fi
