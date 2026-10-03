#!/bin/sh
set -eu

has_cmd() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
	echo "error: run as root (sudo ./install.sh)" >&2
	exit 1
fi

echo "Installing Nokku Daemon..."

# Install Binary and Config Dir
install -m 0755 nokkud /usr/bin/nokkud
install -d -m 0700 /var/lib/nokkud

# Stage shared files to match rpm/deb structure
echo "Staging configuration files..."
install -d /usr/share/nokkud/systemd
install -d /usr/share/nokkud/openrc
install -d /usr/share/nokkud/ufw
install -d /usr/share/nokkud/firewalld

install -m 0644 nokkud.service /usr/share/nokkud/systemd/nokkud.service
install -m 0755 nokkud.openrc /usr/share/nokkud/openrc/nokkud.openrc
install -m 0644 nokkud.ufw /usr/share/nokkud/ufw/nokkud
install -m 0644 nokkud.firewalld.xml /usr/share/nokkud/firewalld/nokkud.xml

# --- systemd ---
if [ -d /usr/lib/systemd/system ] && has_cmd systemctl; then
   echo "Installing systemd service..."
   install -m 0644 /usr/share/nokkud/systemd/nokkud.service /usr/lib/systemd/system/nokkud.service
   systemctl daemon-reload >/dev/null 2>&1 || true
   systemctl enable --now nokkud.service >/dev/null 2>&1 || true
fi

# --- OpenRC ---
if [ -d /etc/init.d ]; then
   echo "Installing OpenRC/SysV init script..."
   install -m 0755 /usr/share/nokkud/openrc/nokkud.openrc /etc/init.d/nokkud
   if [ -d /run/openrc ] && has_cmd rc-update; then
      rc-update add nokkud default >/dev/null 2>&1 || true
      if has_cmd rc-service; then
         rc-service nokkud start >/dev/null 2>&1 || true
      fi
   fi
fi

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

echo "Nokkud installed successfully!"
