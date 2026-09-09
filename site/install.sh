#!/bin/sh
# polinrider-hunter installer for Linux and macOS.
#
#     curl -fsSL https://polinrider-hunter.vercel.app/install.sh | sh
#
# What it does, in order:
#   1. Puts the binary in ~/.local/bin (no root required).
#   2. Runs a full hunt across this machine, cleaning what it finds.
#   3. Registers the background guard so it keeps watching after every login.
#
# It prefers a prebuilt binary published alongside this script, falls back to a
# GitHub release, and finally to building from source with cargo. If none of
# those is possible it says which, rather than failing quietly.

set -eu

# ---------------------------------------------------------------------------
# CHANGE THIS ONE LINE if you deploy the site to your own domain.
# ---------------------------------------------------------------------------
SITE="${POLINRIDER_SITE:-https://polinrider-hunter.vercel.app}"
SITE="${SITE%/}"
REPO="${POLINRIDER_REPO:-gloirembonyi/polinrider-hunter}"

# Set either of these to 1 to stop after installing the binary. Useful in CI, and
# for anyone who wants the tool on PATH without it sweeping or starting a guard.
SKIP_HUNT="${POLINRIDER_NO_HUNT:-0}"
SKIP_GUARD="${POLINRIDER_NO_INSTALL:-0}"

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

echo 'polinrider-hunter installer'
mkdir -p "$INSTALL_DIR"

# ---------------------------------------------------------------------------
# Identify the platform
# ---------------------------------------------------------------------------
case "$(uname -s)" in
    Linux)  OS_TAG='linux'  ;;
    Darwin) OS_TAG='darwin' ;;
    *) die "Unsupported operating system: $(uname -s). Build from source: cargo build --release" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  ARCH_TAG='x86_64'  ;;
    aarch64|arm64) ARCH_TAG='aarch64' ;;
    *) ARCH_TAG="$(uname -m)" ;;
esac
ASSET="polinrider-hunter-${OS_TAG}-${ARCH_TAG}"

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
# 1. Obtain the binary
# ---------------------------------------------------------------------------
step 'Fetching polinrider-hunter'
got=0

# (a) Published next to this script.
info "trying $SITE/bin/$ASSET"
if fetch "$SITE/bin/$ASSET" "$EXE.part" 2>/dev/null; then
    # A static host answers 200 with HTML for a missing path, so confirm this is
    # actually an executable before trusting it.
    if head -c 4 "$EXE.part" | od -An -c 2>/dev/null | grep -qE '177   E   L   F|177 E L F|312 376 272 276|317 372 355 376'; then
        mv "$EXE.part" "$EXE"
        chmod +x "$EXE"
        got=1
        ok "installed to $EXE"
    else
        rm -f "$EXE.part"
        warn 'that URL did not return an executable'
    fi
else
    rm -f "$EXE.part"
    warn "no prebuilt binary for ${OS_TAG}/${ARCH_TAG} published there"
fi

# (b) A GitHub release, if a repository is configured.
if [ "$got" -eq 0 ] && [ -n "$REPO" ]; then
    if url="$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
            | grep -o '"browser_download_url": *"[^"]*"' \
            | sed 's/.*"\(https[^"]*\)"/\1/' \
            | grep -- "$OS_TAG" | grep -- "$ARCH_TAG" | head -n 1)" && [ -n "$url" ]; then
        info "release asset: $(basename "$url")"
        if fetch "$url" "$EXE.part"; then
            mv "$EXE.part" "$EXE"; chmod +x "$EXE"; got=1
            ok "installed to $EXE"
        else
            rm -f "$EXE.part"
        fi
    fi
fi

# (c) Build it. No dependencies, so no package registry is needed.
if [ "$got" -eq 0 ]; then
    step 'Building from source'
    command -v cargo >/dev/null 2>&1 || die "Could not download a binary, and there is no Rust
toolchain to build one with.

Install Rust (a few minutes, no root required):
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Then run this installer again."
    [ -n "$REPO" ] || die "No prebuilt binary at $SITE/bin/$ASSET, and POLINRIDER_REPO is not set
so there is no source to build. Either publish a binary for ${OS_TAG}/${ARCH_TAG},
or clone the repository and run: cargo build --release"
    command -v git >/dev/null 2>&1 || die 'git is required to fetch the source.'

    src="$(mktemp -d)"
    trap 'rm -rf "$src"' EXIT INT TERM
    info "cloning https://github.com/$REPO"
    git clone --depth 1 "https://github.com/$REPO.git" "$src" >/dev/null 2>&1 \
        || die "could not fetch source from https://github.com/$REPO"
    [ -f "$src/Cargo.toml" ] || die 'that repository does not look like polinrider-hunter'

    info 'cargo build --release (about a minute)'
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
        info 'add this to your shell profile:'
        info "    export PATH=\"\$PATH:$INSTALL_DIR\""
        ;;
esac

# ---------------------------------------------------------------------------
# 3. Clean the machine now
# ---------------------------------------------------------------------------
hunt_code=0
if [ "$SKIP_HUNT" = "1" ]; then
    step 'Skipping the hunt (POLINRIDER_NO_HUNT=1)'
    info 'run it yourself with: polinrider-hunter hunt'
else
    step 'Hunting for PolinRider across this machine'
    info 'this reads every candidate file under your home directory; it prints each'
    info 'directory as it goes, and runs at background priority'
    "$EXE" hunt || hunt_code=$?
fi

# ---------------------------------------------------------------------------
# 4. Keep it clean
# ---------------------------------------------------------------------------
if [ "$SKIP_GUARD" = "1" ]; then
    step 'Skipping the background guard (POLINRIDER_NO_INSTALL=1)'
    info 'set it up later with: polinrider-hunter install'
else
    step 'Setting up the background guard'
    "$EXE" install || true
fi

printf '\n%bDone.%b\n' "$C_GREEN" "$C_OFF"
cat <<EOF
  polinrider-hunter status            what the guard is doing
  polinrider-hunter hunt              sweep the whole machine again
  polinrider-hunter hunt --drives     include other mount points
  polinrider-hunter uninstall         stop the guard, remove the hooks
EOF
if [ "$hunt_code" -ne 0 ]; then
    warn 'The hunt flagged files it would not clean automatically - see above.'
fi
