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
fi

# --- OpenRC ---
if [ -d /etc/init.d ]; then
   echo "Installing OpenRC/SysV init script..."
   install -m 0755 /usr/share/nokkud/openrc/nokkud.openrc /etc/init.d/nokkud
   if [ -d /run/openrc ] && has_cmd rc-update; then
      rc-update add nokkud default >/dev/null 2>&1 || true
   fi
fi

# --- AppArmor ---
if [ -d /etc/apparmor.d ] && has_cmd apparmor_parser; then
   echo "Installing AppArmor profile..."
   install -m 0644 /usr/share/nokkud/apparmor/usr.bin.nokkud /etc/apparmor.d/usr.bin.nokkud
   if has_cmd aa-status && aa-status --enabled >/dev/null 2>&1; then
      echo "Loading AppArmor profile..."
      apparmor_parser -r -T -W /etc/apparmor.d/usr.bin.nokkud || true
   fi
fi

# --- SELinux ---
if has_cmd semodule; then
   echo "Installing SELinux policy..."
   semodule -i /usr/share/nokkud/selinux/nokkud.pp || true

   # Apply contexts to binary and data directory
   if has_cmd restorecon; then
      restorecon -R -v /usr/bin/nokkud /var/lib/nokkud || true
   fi
fi

