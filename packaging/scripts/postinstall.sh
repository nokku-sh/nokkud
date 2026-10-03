#!/bin/sh
set -e

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# --- Firewall profiles ---
# Ship the definitions only; opening the port stays the admin's call.
if [ -d /etc/ufw/applications.d ]; then
   echo "Installing ufw application profile..."
   install -m 0644 /usr/share/nokkud/ufw/nokkud /etc/ufw/applications.d/nokkud
   if has_cmd ufw; then
      ufw app update >/dev/null 2>&1 || true
   fi
fi

if [ -d /usr/lib/firewalld/services ]; then
   echo "Installing firewalld service definition..."
   install -m 0644 /usr/share/nokkud/firewalld/nokkud.xml /usr/lib/firewalld/services/nokkud.xml
   if has_cmd firewall-cmd && systemctl is-active -q firewalld 2>/dev/null; then
      firewall-cmd --reload >/dev/null 2>&1 || true
   fi
fi

# --- systemd ---
if [ -d /usr/lib/systemd/system ] && has_cmd systemctl; then
   echo "Installing systemd service..."
   install -m 0644 /usr/share/nokkud/systemd/nokkud.service /usr/lib/systemd/system/nokkud.service
   systemctl daemon-reload >/dev/null 2>&1 || true
   systemctl enable nokkud.service >/dev/null 2>&1 || true
   # Upgrades pick up the new binary. Live connections end with the restart.
   systemctl try-restart nokkud.service >/dev/null 2>&1 || true
fi

# --- OpenRC ---
if [ -d /etc/init.d ]; then
   echo "Installing OpenRC/SysV init script..."
   install -m 0755 /usr/share/nokkud/openrc/nokkud.openrc /etc/init.d/nokkud
   if [ -d /run/openrc ] && has_cmd rc-update; then
      rc-update add nokkud default >/dev/null 2>&1 || true
   fi
fi

