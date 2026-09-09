#!/bin/sh
# polinrider-hunter installer for Linux and macOS.
#
# One-liner:
#
#     curl -fsSL https://raw.githubusercontent.com/OWNER/polinrider-hunter/main/install.sh | sh
#
# What it does, in order:
#   1. Puts the binary in ~/.local/bin (no root required).
#   2. Runs a full hunt across this machine, cleaning what it finds.
#   3. Registers the background guard so it keeps watching after every login.
#
# Prefers a published release binary; falls back to building from source with
# cargo. Set POLINRIDER_REPO to point at a fork.

set -eu

REPO="${POLINRIDER_REPO:-OWNER/polinrider-hunter}"
INSTALL_DIR="${POLINRIDER_BIN:-$HOME/.local/bin}"
EXE="$INSTALL_DIR/polinrider-hunter"

if [ -t 1 ]; then
    C_CYAN='\033[36m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_RED='\033[31m'; C_OFF='\033[0m'
else
    C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_OFF=''
fi
step() { printf '\n%b%s%b\n' "$C_CYAN" "$1" "$C_OFF"; }
info() { printf '  %s\n' "$1"; }
ok()   { printf '  %b%s%b\n' "$C_GREEN" "$1" "$C_OFF"; }
warn() { printf '  %b%s%b\n' "$C_YELLOW" "$1" "$C_OFF"; }
die()  { printf '\n%b%s%b\n' "$C_RED" "$1" "$C_OFF" >&2; exit 1; }

echo "polinrider-hunter installer"
mkdir -p "$INSTALL_DIR"

# ---------------------------------------------------------------------------
# Identify the platform, for picking a release asset
# ---------------------------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
    Linux)  os_tag='linux'  ;;
    Darwin) os_tag='darwin' ;;
    *) die "unsupported operating system: $os. Build from source: cargo build --release" ;;
esac
case "$arch" in
    x86_64|amd64)  arch_tag='x86_64'  ;;
    aarch64|arm64) arch_tag='aarch64' ;;
    *) arch_tag="$arch" ;;
esac

fetch() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
    else return 1
    fi
}
fetch_stdout() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then wget -qO- "$1"
    else return 1
    fi
}

# ---------------------------------------------------------------------------
# 1. Obtain a binary
# ---------------------------------------------------------------------------
step 'Fetching polinrider-hunter'
got=0

# A published release asset needs no toolchain. Parsed with grep/sed rather
# than jq, which is not installed as often as people assume.
if url="$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | grep -o '"browser_download_url": *"[^"]*"' \
        | sed 's/.*"\(https[^"]*\)"/\1/' \
        | grep -- "$os_tag" | grep -- "$arch_tag" | head -n 1)" && [ -n "$url" ]; then
    info "release asset: $(basename "$url")"
    if fetch "$url" "$EXE.tmp"; then
        mv "$EXE.tmp" "$EXE"
        chmod +x "$EXE"
        got=1
        ok "installed to $EXE"
    else
        warn 'download failed'
        rm -f "$EXE.tmp"
    fi
else
    warn "no release binary for $os_tag/$arch_tag"
fi

# Otherwise build it. Zero dependencies, so this needs only a Rust toolchain
# and no access to a package registry.
if [ "$got" -eq 0 ]; then
    step 'Building from source'
    command -v cargo >/dev/null 2>&1 || die "Need either a published release or a Rust toolchain, and found neither.

Install Rust (a few minutes, no root required):
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Then re-run this installer."
    command -v git >/dev/null 2>&1 || die 'git is required to fetch the source. Install it and re-run.'

    src="$(mktemp -d)"
    trap 'rm -rf "$src"' EXIT INT TERM
    info "cloning https://github.com/$REPO"
    git clone --depth 1 "https://github.com/$REPO.git" "$src" >/dev/null 2>&1 \
        || die "could not fetch the source from https://github.com/$REPO"
    [ -f "$src/Cargo.toml" ] || die 'that repository does not look like polinrider-hunter'

    info 'cargo build --release (this takes a minute)'
    ( cd "$src" && cargo build --release 2>&1 | grep -E '^error' || true )
    [ -f "$src/target/release/polinrider-hunter" ] || die 'build failed'
    cp "$src/target/release/polinrider-hunter" "$EXE"
    chmod +x "$EXE"
    ok "installed to $EXE"
fi

# ---------------------------------------------------------------------------
# 2. PATH
# ---------------------------------------------------------------------------
step 'Checking PATH'
case ":$PATH:" in
    *":$INSTALL_DIR:"*) info 'already on PATH' ;;
    *)
        warn "$INSTALL_DIR is not on your PATH"
        info "add this to your shell profile:"
        info "    export PATH=\"\$PATH:$INSTALL_DIR\""
        ;;
esac

# ---------------------------------------------------------------------------
# 3. Clean the machine now
# ---------------------------------------------------------------------------
step 'Hunting for PolinRider across this machine'
hunt_code=0
"$EXE" hunt || hunt_code=$?

# ---------------------------------------------------------------------------
# 4. Keep it clean
# ---------------------------------------------------------------------------
step 'Setting up the background guard'
"$EXE" install || true

printf '\n%bDone.%b\n' "$C_GREEN" "$C_OFF"
cat <<EOF
  polinrider-hunter status            what the guard is doing
  polinrider-hunter hunt              sweep the whole machine again
  polinrider-hunter hunt --drives     include other mount points
  polinrider-hunter uninstall         stop the guard, remove the hooks
EOF
if [ "$hunt_code" -ne 0 ]; then
    warn 'The hunt flagged files it could not clean automatically - see above.'
fi
