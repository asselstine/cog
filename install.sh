#!/bin/sh
set -eu

COG_REPO=${COG_REPO:-asselstine/cog}
COG_VERSION=${COG_VERSION:-latest}
COG_INSTALL_DIR=${COG_INSTALL_DIR:-}

fail() {
    printf 'cog installer: %s\n' "$*" >&2
    exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

case "$(uname -s)" in
    Linux) os=unknown-linux-gnu ;;
    Darwin) os=apple-darwin ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
esac

case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    arm64|aarch64) arch=aarch64 ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac

archive="cog-${arch}-${os}.tar.gz"
if [ "$COG_VERSION" = latest ]; then
    base_url="https://github.com/${COG_REPO}/releases/latest/download"
else
    case "$COG_VERSION" in
        v*) tag=$COG_VERSION ;;
        *) tag=v$COG_VERSION ;;
    esac
    base_url="https://github.com/${COG_REPO}/releases/download/${tag}"
fi

tmp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t cog-install)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

curl -fL --retry 3 --proto '=https' --tlsv1.2 \
    "$base_url/$archive" -o "$tmp_dir/$archive"
curl -fL --retry 3 --proto '=https' --tlsv1.2 \
    "$base_url/SHA256SUMS" -o "$tmp_dir/SHA256SUMS"

expected=$(awk -v name="$archive" '$2 == name { print $1 }' "$tmp_dir/SHA256SUMS")
[ -n "$expected" ] || fail "release checksum does not contain $archive"
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp_dir/$archive" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp_dir/$archive" | awk '{ print $1 }')
else
    fail "sha256sum or shasum is required"
fi
[ "$actual" = "$expected" ] || fail "checksum verification failed"

tar -xzf "$tmp_dir/$archive" -C "$tmp_dir"

if [ -z "$COG_INSTALL_DIR" ]; then
    if [ -w /usr/local/bin ]; then
        COG_INSTALL_DIR=/usr/local/bin
    else
        COG_INSTALL_DIR=${HOME:?}/.local/bin
    fi
fi
mkdir -p "$COG_INSTALL_DIR"
install -m 0755 "$tmp_dir/cog" "$COG_INSTALL_DIR/cog"

printf 'Installed cog to %s/cog\n' "$COG_INSTALL_DIR"
case ":$PATH:" in
    *:"$COG_INSTALL_DIR":*) ;;
    *) printf 'Add %s to PATH to run cog.\n' "$COG_INSTALL_DIR" ;;
esac
