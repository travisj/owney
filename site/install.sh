#!/bin/sh
# Owney installer — https://travisj.github.io/owney/
#
# Downloads the latest owneyd build for this platform from GitHub Releases,
# verifies its sha256, and installs:
#   - the owneyd binary into an executable directory
#   - the bundled web UI into <prefix>/share/owney/static
#
# Usage:
#   curl -fsSL https://travisj.github.io/owney/install.sh | sh
#
# Environment overrides:
#   OWNEY_INSTALL_DIR  install dir for the binary (default: /usr/local/bin
#                      if writable, else ~/.local/bin)
#   OWNEY_TAG          release tag to install (default: latest — the rolling
#                      build from main; use e.g. v0.1.0 for a pinned version)
set -eu

REPO="travisj/owney"
TAG="${OWNEY_TAG:-latest}"

say() { printf '\033[1;36mowney:\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31mowney: error:\033[0m %s\n' "$1" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

# --- Detect platform -------------------------------------------------------
case "$(uname -s)" in
    Linux)  os="linux" ;;
    Darwin) os="macos" ;;
    *) fail "unsupported OS: $(uname -s) (Linux and macOS builds are available)" ;;
esac

case "$(uname -m)" in
    x86_64|amd64)  arch="x86_64" ;;
    arm64|aarch64) arch="aarch64" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac

artifact="owneyd-${os}-${arch}"
url="https://github.com/${REPO}/releases/download/${TAG}/${artifact}.tar.gz"

# --- Pick install locations ------------------------------------------------
if [ -n "${OWNEY_INSTALL_DIR:-}" ]; then
    bin_dir="$OWNEY_INSTALL_DIR"
    share_dir="$OWNEY_INSTALL_DIR/../share/owney"
elif [ -w /usr/local/bin ]; then
    bin_dir="/usr/local/bin"
    share_dir="/usr/local/share/owney"
else
    bin_dir="$HOME/.local/bin"
    share_dir="$HOME/.local/share/owney"
fi

# --- Download & verify -----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading ${artifact}.tar.gz (${TAG})"
curl -fsSL "$url" -o "$tmp/${artifact}.tar.gz" \
    || fail "download failed: $url"
curl -fsSL "${url}.sha256" -o "$tmp/${artifact}.tar.gz.sha256" \
    || fail "checksum download failed: ${url}.sha256"

say "verifying checksum"
(
    cd "$tmp"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "${artifact}.tar.gz.sha256" >/dev/null
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "${artifact}.tar.gz.sha256" >/dev/null
    else
        fail "need sha256sum or shasum to verify the download"
    fi
) || fail "checksum verification FAILED — not installing"

tar -xzf "$tmp/${artifact}.tar.gz" -C "$tmp"

# --- Install ---------------------------------------------------------------
mkdir -p "$bin_dir" "$share_dir"
install -m 755 "$tmp/$artifact/owneyd" "$bin_dir/owneyd"
rm -rf "$share_dir/static"
cp -R "$tmp/$artifact/static" "$share_dir/static"

say "installed owneyd to $bin_dir/owneyd"
say "installed web UI to $share_dir/static"
"$bin_dir/owneyd" --version

case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) say "note: $bin_dir is not on your PATH — add it to your shell profile" ;;
esac

printf '\n'
say "get started:"
printf '    owneyd setup     # first-run wizard: config, keys, DNS records\n'
printf '    UI_STATIC_DIR=%s owneyd serve\n' "$share_dir/static"
