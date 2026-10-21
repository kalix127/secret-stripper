#!/usr/bin/env bash
set -euo pipefail

# Served verbatim from https://secretstripper.download - this script is
# version-agnostic: it always resolves GitHub's "releases/latest" alias, so a
# new release never requires changing or re-uploading it.
REPO="${SECRET_STRIPPER_REPO:-kalix127/secret-stripper}"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

detect() {
    local arch
    case "$(uname -s)" in
        Linux*) ;;
        *)
            printf "Unsupported OS: %s. Secret Stripper supports Linux only.\n" \
                "$(uname -s)" >&2
            printf "The last macOS release is 1.5.2: %s\n" \
                "https://github.com/${REPO}/releases/tag/v1.5.2" >&2
            exit 1
            ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *)
            printf "Unsupported CPU: %s. Release builds are x86_64 and aarch64.\n" \
                "$(uname -m)" >&2
            exit 1
            ;;
    esac
    printf 'linux-%s' "$arch"
}

verify_sha256() {
    # Verify $1 (file) against the line in $2 (SHA256SUMS) whose filename
    # column equals $3 (basename). Exits non-zero if hash missing or mismatch.
    local file="$1" sums="$2" name="$3" expected actual
    expected=$(awk -v n="$name" '$2==n || $2=="*"n {print $1; exit}' "$sums" || true)
    if [ -z "$expected" ]; then
        printf "  ${RED}[FAIL]${NC} No SHA256 for %s in SHA256SUMS.\n" "$name" >&2
        return 1
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        printf "  ${RED}[FAIL]${NC} sha256sum not available; cannot verify binary.\n" >&2
        return 1
    fi
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [ "$expected" != "$actual" ]; then
        printf "  ${RED}[FAIL]${NC} SHA256 mismatch for %s:\n  expected: %s\n  actual:   %s\n" \
            "$name" "$expected" "$actual" >&2
        return 1
    fi
}

main() {
    local target asset_name url tmp sums bin_path
    target=$(detect)
    asset_name="secret-stripper-${target}"
    url="https://github.com/${REPO}/releases/latest/download/${asset_name}"

    printf "${CYAN}${BOLD}  Secret Stripper Installer${NC}\n\n"
    printf "  ${YELLOW}[~]${NC} Downloading ${asset_name}...\n"

    tmp=$(mktemp)
    sums=$(mktemp)

    if ! curl -fsSL "$url" -o "$tmp" 2>/dev/null; then
        printf "  ${RED}[FAIL]${NC} Download failed. No release binary for your platform.\n" >&2
        printf "  Build from source instead: https://rustup.rs\n" >&2
        rm -f "$tmp" "$sums"
        exit 1
    fi

    # Pull the release's SHA256SUMS and verify the downloaded asset against
    # it. Releases that don't publish SHA256SUMS (pre-1.0.0) refuse to
    # install; the user can override with SECRET_STRIPPER_SKIP_CHECKSUM=1.
    if ! curl -fsSL "https://github.com/${REPO}/releases/latest/download/SHA256SUMS" \
        -o "$sums" 2>/dev/null; then
        if [ "${SECRET_STRIPPER_SKIP_CHECKSUM:-}" = "1" ]; then
            printf "  ${YELLOW}[!]${NC} SHA256SUMS missing; SECRET_STRIPPER_SKIP_CHECKSUM=1, continuing unverified.\n"
        else
            printf "  ${RED}[FAIL]${NC} Could not fetch SHA256SUMS from the release. Refusing to install unverified binary.\n" >&2
            printf "  Override with SECRET_STRIPPER_SKIP_CHECKSUM=1 if you understand the risk.\n" >&2
            rm -f "$tmp" "$sums"
            exit 1
        fi
    elif ! verify_sha256 "$tmp" "$sums" "$asset_name"; then
        rm -f "$tmp" "$sums"
        exit 1
    else
        printf "  ${GREEN}[OK]${NC} Verified SHA256 of ${asset_name}\n"
    fi
    rm -f "$sums"

    chmod +x "$tmp"

    printf "  ${YELLOW}[~]${NC} Installing to /usr/local/bin (sudo may ask for your password; if it fails, ~/.local/bin is used)\n"
    if sudo mv "$tmp" /usr/local/bin/secret-stripper 2>/dev/null; then
        bin_path="/usr/local/bin/secret-stripper"
    else
        mkdir -p "$HOME/.local/bin"
        mv "$tmp" "$HOME/.local/bin/secret-stripper"
        bin_path="$HOME/.local/bin/secret-stripper"
        case ":$PATH:" in
            *":$HOME/.local/bin:"*) ;;
            *) printf "  ${YELLOW}[!]${NC} Add ~/.local/bin to your PATH\n" ;;
        esac
    fi
    printf "  ${GREEN}[OK]${NC} Installed to ${bin_path}\n\n"

    # An older copy earlier in PATH would shadow the new binary.
    local on_path
    on_path=$(command -v secret-stripper 2>/dev/null || true)
    if [ -n "$on_path" ] && [ "$on_path" != "$bin_path" ]; then
        printf "  ${YELLOW}[!]${NC} %s is another copy and runs first. Remove it: rm %s\n\n" \
            "$on_path" "$on_path"
    fi

    # init may ask before running sudo; under `curl | bash` stdin is the script.
    local input=/dev/null
    if (: </dev/tty) 2>/dev/null; then
        input=/dev/tty
    fi

    if ! "$bin_path" init <"$input"; then
        printf "  ${YELLOW}[!]${NC} Init had warnings. Run '${bin_path} menu' to fix.\n"
    fi

    printf "\n  ${BOLD}Secret Stripper is ready.${NC}\n"
    printf "  Copy text as usual, then press your hotkey to paste a redacted copy.\n"
    printf "  ${CYAN}secret-stripper menu${NC}    - settings, hotkey, notifications\n"
    printf "  ${CYAN}secret-stripper status${NC}  - show current state\n\n"
}

main "$@"
