#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work/bin" "$work/release"

cat >"$work/bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' "$MOCK_OS" ;;
  -m) printf '%s\n' "$MOCK_ARCH" ;;
esac
EOF
cat >"$work/bin/curl" <<'EOF'
#!/bin/sh
url=
out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
cp "$MOCK_RELEASE/${url##*/}" "$out"
EOF
chmod +x "$work/bin/uname" "$work/bin/curl"

make_release() {
    archive=$1
    stage="$work/stage"
    rm -rf "$stage"
    mkdir -p "$stage"
    printf '#!/bin/sh\nprintf "cog 0.1.0\\n"\n' >"$stage/cog"
    chmod +x "$stage/cog"
    tar -C "$stage" -czf "$work/release/$archive" cog
    (cd "$work/release" && sha256sum "$archive" >SHA256SUMS)
}

run_case() {
    os=$1
    arch=$2
    archive=$3
    make_release "$archive"
    install_dir="$work/install path/$os-$arch"
    PATH="$work/bin:$PATH" MOCK_OS=$os MOCK_ARCH=$arch MOCK_RELEASE="$work/release" \
        COG_INSTALL_DIR="$install_dir" COG_REPO=example/cog \
        sh "$root/install.sh" >/dev/null
    test -x "$install_dir/cog"
    test "$("$install_dir/cog")" = "cog 0.1.0"
}

run_case Linux x86_64 cog-x86_64-unknown-linux-gnu.tar.gz
run_case Linux aarch64 cog-aarch64-unknown-linux-gnu.tar.gz
run_case Darwin x86_64 cog-x86_64-apple-darwin.tar.gz
run_case Darwin arm64 cog-aarch64-apple-darwin.tar.gz

if PATH="$work/bin:$PATH" MOCK_OS=Plan9 MOCK_ARCH=x86_64 MOCK_RELEASE="$work/release" \
    COG_INSTALL_DIR="$work/nope" sh "$root/install.sh" >/dev/null 2>&1; then
    echo "unsupported OS was accepted" >&2
    exit 1
fi

make_release cog-x86_64-unknown-linux-gnu.tar.gz
printf '%064d  cog-x86_64-unknown-linux-gnu.tar.gz\n' 0 >"$work/release/SHA256SUMS"
if PATH="$work/bin:$PATH" MOCK_OS=Linux MOCK_ARCH=x86_64 MOCK_RELEASE="$work/release" \
    COG_INSTALL_DIR="$work/nope" sh "$root/install.sh" >/dev/null 2>&1; then
    echo "invalid checksum was accepted" >&2
    exit 1
fi

grep -q 'cog-x86_64-pc-windows-msvc.zip' "$root/install.ps1"
grep -q 'Join-Path.*"cog.exe"' "$root/install.ps1"
printf 'installer tests passed\n'
