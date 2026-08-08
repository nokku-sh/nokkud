#!/bin/sh
set -e

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# --- systemd ---
if has_cmd systemctl && [ -f /usr/lib/systemd/system/nokkud.service ]; then
	systemctl stop nokkud.service >/dev/null 2>&1 || true
	systemctl disable nokkud.service >/dev/null 2>&1 || true
fi

# --- OpenRC ---
if has_cmd rc-update && [ -f /etc/init.d/nokkud ]; then
	rc-update del nokkud default >/dev/null 2>&1 || true
fi

# Remove SELinux policy and AppArmor profile on uninstall
# RPM passes 0, Debian passes "remove". Alpine runs this exclusively on uninstalls.
if [ "$1" = "0" ] || [ "$1" = "remove" ] || [ -f /etc/alpine-release ]; then
	if has_cmd semodule; then
		if semodule -l | grep -q "^nokkud$"; then
			echo "Removing SELinux policy..."
			semodule -r nokkud || true
		fi
	fi

	if has_cmd apparmor_parser && [ -f /etc/apparmor.d/usr.bin.nokkud ]; then
		echo "Unloading AppArmor profile..."
		apparmor_parser -R /etc/apparmor.d/usr.bin.nokkud || true
	fi
fi