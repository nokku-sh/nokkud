#!/bin/sh
set -e

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# --- systemd ---
if has_cmd systemctl && [ -d /run/systemd/system ]; then
   systemctl daemon-reload >/dev/null 2>&1 || true
   systemctl reset-failed >/dev/null 2>&1 || true
fi

# Remove files created by maintainer scripts only on full removal.
# RPM passes 0 on erase and 1 on upgrade. Debian passes remove/purge.
# Alpine runs this exclusively on uninstalls.
if [ "$1" = "0" ] || [ "$1" = "remove" ] || [ "$1" = "purge" ] || [ -f /etc/alpine-release ]; then
   rm -f /usr/lib/systemd/system/nokkud.service
   rm -f /etc/init.d/nokkud
   rm -f /etc/apparmor.d/usr.bin.nokkud
   rm -f /etc/ufw/applications.d/nokkud
   rm -f /usr/lib/firewalld/services/nokkud.xml
fi

