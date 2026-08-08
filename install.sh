#!/bin/sh
set -eu

REPO="nokku-sh/nokkud"

VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$VERSION" ]; then
   echo "Error: Could not fetch latest version from GitHub." >&2
   exit 1
fi

detect_arch() {
   case "$(uname -m)" in
   x86_64 | amd64) echo "amd64" ;;
   aarch64 | arm64) echo "arm64" ;;
   riscv64) echo "riscv64" ;;
   *) echo "unsupported" ;;
   esac
}

ARCH=$(detect_arch)
if [ "$ARCH" = "unsupported" ]; then
   echo "Error: Unsupported architecture: $(uname -m)" >&2
   exit 1
fi

echo "Installing nokkud ${VERSION} for linux/${ARCH}..."

TMP_DIR=$(mktemp -d)
TAR_URL="https://github.com/${REPO}/releases/download/${VERSION}/nokkud_linux_${ARCH}.tar.gz"

echo "Downloading release archive from GitHub..."
if ! curl -fsSL "$TAR_URL" -o "${TMP_DIR}/nokkud.tar.gz"; then
   echo "Error: Failed to download archive." >&2
   rm -rf "$TMP_DIR"
   exit 1
fi

tar -xzf "${TMP_DIR}/nokkud.tar.gz" -C "$TMP_DIR"

echo "Running bundled installer..."
cd "$TMP_DIR"
if [ "$(id -u)" -ne 0 ]; then
   sudo ./install.sh
else
   ./install.sh
fi

cd - >/dev/null
rm -rf "$TMP_DIR"
