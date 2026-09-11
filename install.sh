#!/bin/sh
set -eu

# nokkud - Nokku Edge Daemon installer
#
# Preferred: sets up the Cloudsmith repository for your distro's package
# manager and installs the nokkud package (deb/rpm/apk).
# Fallback: downloads the release tarball from GitHub and runs the bundled
# installer (used while the Cloudsmith repo is not live).

BINARY_NAME="nokkud"
GH_REPO="nokku-sh/nokkud"
CS_OWNER="nokku"
CS_REPO="nokkud"

# Checksum manifest and cosign bundle, named by GoReleaser.
CHECKSUM_FILE="${BINARY_NAME}_checksums.txt"

VERSION="${NOKKUD_VERSION:-}"

usage() {
	cat <<EOF
Usage: $0 [--version <x.y.z>]

  --version <ver>   Pin a specific version; forces the binary fallback
  -h, --help        Show this help

Equivalent environment variable: NOKKUD_VERSION
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--version)
		[ "$#" -ge 2 ] || {
			echo "error: --version requires a value" >&2
			exit 1
		}
		VERSION="$2"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown option: $1" >&2
		usage
		exit 1
		;;
	esac
	shift
done

# Accept both v1.2.3 and 1.2.3.
VERSION="${VERSION#v}"

have() { command -v "$1" >/dev/null 2>&1; }

if ! have curl; then
	echo "error: curl is required but was not found on PATH" >&2
	exit 1
fi

as_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	else
		command sudo -E "$@"
	fi
}

# Install via the distro package manager from Cloudsmith.
# Returns 0 only if the binary is found on PATH afterwards.
install_package() {
	# Packages are published for Linux only; other systems use the tarball.
	[ "$(uname -s)" = "Linux" ] || return 1
	[ -z "$VERSION" ] || return 1

	case " $(command -v apt-get dnf yum zypper apk) " in
	*apt-get*) PM=deb ;;
	*dnf* | *yum* | *zypper*) PM=rpm ;;
	*apk*) PM=alpine ;;
	*) return 1 ;;
	esac

	TMP_DIR=$(mktemp -d)

	if ! curl -fsSL "https://dl.cloudsmith.io/public/${CS_OWNER}/${CS_REPO}/setup.${PM}.sh" -o "${TMP_DIR}/setup.sh"; then
		echo "warning: Cloudsmith repository is not available yet; falling back to the GitHub binary." >&2
		rm -rf "$TMP_DIR"
		return 1
	fi

	if have bash; then
		if ! as_root bash "${TMP_DIR}/setup.sh"; then
			echo "warning: could not configure the Cloudsmith repository; falling back to the GitHub binary." >&2
			rm -rf "$TMP_DIR"
			return 1
		fi
	else
		if ! as_root sh "${TMP_DIR}/setup.sh"; then
			echo "warning: could not configure the Cloudsmith repository; falling back to the GitHub binary." >&2
			rm -rf "$TMP_DIR"
			return 1
		fi
	fi

	# Cloudsmith's repo config pins sslcacert=/etc/pki/tls/certs/ca-bundle.crt,
	# which Fedora 44+ no longer ships; drop it so dnf uses its default CA store.
	if [ "$PM" = rpm ]; then
		for repo in /etc/yum.repos.d/nokku-*.repo; do
			[ -f "$repo" ] || continue
			ssl_ca=$(sed -n 's/^sslcacert=//p' "$repo" | head -n 1)
			if [ -n "$ssl_ca" ] && [ ! -e "$ssl_ca" ]; then
				echo "note: $repo pins a CA bundle that does not exist; removing sslcacert."
				as_root sed -i '/^sslcacert=/d' "$repo"
			fi
		done
	fi

	case "$PM" in
	deb)
		as_root apt-get install -y "$BINARY_NAME"
		;;
	rpm)
		if have dnf; then
			as_root dnf install -y "$BINARY_NAME"
		elif have yum; then
			as_root yum install -y "$BINARY_NAME"
		else
			as_root zypper install -y "$BINARY_NAME"
		fi
		;;
	alpine)
		as_root apk add "$BINARY_NAME"
		;;
	esac

	pkg_installed=false
	case "$PM" in
	deb) dpkg -s "$BINARY_NAME" >/dev/null 2>&1 && pkg_installed=true ;;
	rpm) rpm -q "$BINARY_NAME" >/dev/null 2>&1 && pkg_installed=true ;;
	alpine) apk info -e "$BINARY_NAME" >/dev/null 2>&1 && pkg_installed=true ;;
	esac

	if [ "$pkg_installed" != true ] || ! have "$BINARY_NAME"; then
		echo "warning: '${BINARY_NAME}' is not on PATH after the package install; falling back to the GitHub binary." >&2
		rm -rf "$TMP_DIR"
		return 1
	fi

	rm -rf "$TMP_DIR"
	echo "Installed ${BINARY_NAME} from the Cloudsmith repository."
	return 0
}

# sha256 prints the SHA-256 of a file using whichever tool is available.
sha256() {
	if have sha256sum; then
		sha256sum "$1" | awk '{print $1}'
	elif have shasum; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif have openssl; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		echo "error: no SHA-256 tool found (need sha256sum, shasum, or openssl)" >&2
		return 1
	fi
}

# Download the release tarball from GitHub, verify it, then run the bundled
# installer. Nothing from the download is executed before the checksum and, when
# cosign is available, the signature on the checksum manifest are verified.
install_binary() {
	if [ "$(uname -s)" != "Linux" ]; then
		echo "error: prebuilt tarballs are published for Linux only" >&2
		echo "See https://github.com/${GH_REPO}/releases/latest for the package list." >&2
		exit 1
	fi

	ARCH=$(uname -m)
	case "$ARCH" in
	x86_64 | amd64) GOARCH=amd64 ;;
	arm64 | aarch64) GOARCH=arm64 ;;
	riscv64) GOARCH=riscv64 ;;
	*)
		echo "error: unsupported architecture: $ARCH" >&2
		exit 1
		;;
	esac

	if [ -n "$VERSION" ]; then
		REL_BASE="https://github.com/${GH_REPO}/releases/download/v${VERSION}"
	else
		REL_BASE="https://github.com/${GH_REPO}/releases/latest/download"
	fi

	TARBALL="${BINARY_NAME}_linux_${GOARCH}.tar.gz"

	TMP_DIR=$(mktemp -d) || {
		echo "error: cannot create a temporary directory (check TMPDIR)" >&2
		exit 1
	}
	trap 'rm -rf "$TMP_DIR"' EXIT

	echo "Downloading ${BINARY_NAME} (linux/${GOARCH}) from GitHub..."
	curl -fsSL -o "${TMP_DIR}/${TARBALL}" "${REL_BASE}/${TARBALL}"

	# The checksum manifest is the root of trust. Verify its cosign signature
	# when possible, then verify the tarball against it.
	curl -fsSL -o "${TMP_DIR}/${CHECKSUM_FILE}" "${REL_BASE}/${CHECKSUM_FILE}"
	if have cosign; then
		curl -fsSL -o "${TMP_DIR}/${CHECKSUM_FILE}.sigstore.json" \
			"${REL_BASE}/${CHECKSUM_FILE}.sigstore.json"
		echo "Verifying ${CHECKSUM_FILE} signature with cosign..."
		if ! cosign verify-blob \
			--bundle "${TMP_DIR}/${CHECKSUM_FILE}.sigstore.json" \
			--certificate-identity-regexp \
			'https://github.com/nokku-sh/nokkud/\.github/workflows/.*' \
			--certificate-oidc-issuer https://token.actions.githubusercontent.com \
			"${TMP_DIR}/${CHECKSUM_FILE}"; then
			echo "error: ${CHECKSUM_FILE} signature verification failed" >&2
			exit 1
		fi
	else
		echo "warning: cosign not found; the checksum is verified but the checksum manifest itself is not authenticated." >&2
	fi

	WANT=$(awk -v name="$TARBALL" '$2 == name { print $1 }' "${TMP_DIR}/${CHECKSUM_FILE}")
	if [ -z "$WANT" ]; then
		echo "error: ${TARBALL} is not listed in ${CHECKSUM_FILE}" >&2
		exit 1
	fi

	GOT=$(sha256 "${TMP_DIR}/${TARBALL}") || exit 1
	if [ "${WANT}" != "${GOT}" ]; then
		echo "error: checksum mismatch for ${TARBALL}" >&2
		echo "  expected ${WANT}" >&2
		echo "  got      ${GOT}" >&2
		exit 1
	fi

	tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"

	cd "$TMP_DIR"
	as_root sh ./install.sh
}

if install_package; then
	exit 0
fi

install_binary
