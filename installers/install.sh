#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${TMPDIR:-/tmp}/secret-stripper-install.log"
BUILD_DIR="${PROJECT_DIR}/target"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'
SPIN='⣾⣽⣻⢿⡿⣟⣯⣷'
SPIN_LEN=${#SPIN}

detect_os() {
    case "$(uname -s)" in
        Linux*)
            if command -v apt-get &>/dev/null; then echo "debian"
            elif command -v pacman &>/dev/null; then echo "arch"
            elif command -v dnf &>/dev/null; then echo "fedora"
            elif command -v zypper &>/dev/null; then echo "suse"
            else echo "linux-other"; fi
            ;;
        Darwin*) echo "macos" ;;
        *) echo "unsupported" ;;
    esac
}

OS=$(detect_os)

log() { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"; }

print_banner() {
    printf "\n${CYAN}${BOLD}"
    printf "   ____ _ _       ____                     _    \n"
    printf "  / ___(_) |_    / ___|_   _ _ __ ___  __| |_  \n"
    printf " | |   | | __|  | |  _| | | | '__/ _ \/ _\` | | | |\n"
    printf " | |___| | |_   | |_| | |_| | | |  __/ (_| | |_| |\n"
    printf "  \____|_|\__|   \____|\__,_|_|  \___|\__,_|\__,_|\n"
    printf "${NC}\n"
    printf "${BLUE}${BOLD}  Clipboard PII & Secret Redactor${NC}\n"
    printf "${YELLOW}  Detected OS: ${OS} | Log: ${LOG_FILE}${NC}\n\n"
}

spinner() {
    local msg="$1"
    local pid="$2"
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}[${SPIN:$i:1}]${NC} ${msg}..."
        i=$(( (i+1) % SPIN_LEN ))
        sleep 0.1
    done
    wait "$pid"
    local ec=$?
    if [ $ec -eq 0 ]; then
        printf "\r${GREEN}[OK]${NC} ${msg}... ${GREEN}done${NC}\n"
    else
        printf "\r${RED}[FAIL]${NC} ${msg}... ${RED}FAILED${NC}\n"
        return $ec
    fi
}

step() { printf "\n${BOLD}[${CYAN}${1}${NC}${BOLD}]${NC} ${2}\n"; }

check_deps() {
    if ! command -v rustc &>/dev/null || ! command -v cargo &>/dev/null; then
        printf "  ${YELLOW}[~]${NC} Installing Rust via rustup...\n"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>>"$LOG_FILE"
        export PATH="$HOME/.cargo/bin:$PATH"
    fi

    case "$OS" in
        debian)
            local pkgs=(libx11-dev libxcb-shm0-dev libxcb-xfixes0-dev libxkbcommon-dev libgtk-3-dev)
            local install=()
            for pkg in "${pkgs[@]}"; do
                if ! dpkg -s "$pkg" &>/dev/null; then install+=("$pkg"); fi
            done
            if [ ${#install[@]} -gt 0 ]; then
                if command -v sudo &>/dev/null; then
                    sudo apt-get install -y "${install[@]}" >> "$LOG_FILE" 2>&1 || \
                    printf "  ${YELLOW}[~]${NC} Could not install system packages (run manually)\n"
                fi
            fi
            ;;
        arch)
            local pkgs=(libx11 libxcb libxkbcommon gtk3)
            local install=()
            for pkg in "${pkgs[@]}"; do
                if ! pacman -Qi "$pkg" &>/dev/null; then install+=("$pkg"); fi
            done
            if [ ${#install[@]} -gt 0 ]; then
                if command -v sudo &>/dev/null; then
                    sudo pacman -S --noconfirm "${install[@]}" >> "$LOG_FILE" 2>&1 || \
                    printf "  ${YELLOW}[~]${NC} Could not install system packages (run manually)\n"
                fi
            fi
            ;;
        macos)
            command -v pkg-config &>/dev/null || brew install pkg-config >> "$LOG_FILE" 2>&1
            ;;
    esac
}

build_release() {
    log "Building secret-stripper release..."
    if ! command -v cargo &>/dev/null; then
        printf "  ${RED}[FAIL]${NC} Cargo not found - install Rust first\n"
        return 1
    fi
    cargo build --release >> "$LOG_FILE" 2>&1 &
    spinner "Compiling Rust binary" $!
    local bin="$BUILD_DIR/release/secret-stripper"
    if [ ! -f "$bin" ]; then
        printf "  ${RED}[FAIL]${NC} Build failed - check ${LOG_FILE}\n"
        return 1
    fi
    local size
    size=$(du -h "$bin" 2>/dev/null | cut -f1)
    printf "  ${GREEN}[OK]${NC} Built (${size})\n"
}

install_binary() {
    local bin_path="/usr/local/bin"
    local bin="$BUILD_DIR/release/secret-stripper"
    log "Installing binary to ${bin_path}/secret-stripper"

    if command -v sudo &>/dev/null; then
        sudo cp "$bin" "${bin_path}/" >> "$LOG_FILE" 2>&1 && \
        sudo chmod +x "${bin_path}/secret-stripper" && \
        printf "  ${GREEN}[OK]${NC} Installed to ${bin_path}/secret-stripper\n" || \
        printf "  ${YELLOW}[~]${NC} sudo copy failed, trying without...\n"
    fi

    if [ ! -f "${bin_path}/secret-stripper" ]; then
        cp "$bin" "${bin_path}/" 2>>"$LOG_FILE" && \
        chmod +x "${bin_path}/secret-stripper" && \
        printf "  ${GREEN}[OK]${NC} Installed to ${bin_path}/secret-stripper\n" || \
        printf "  ${YELLOW}[~]${NC} Will run from build directory: ${bin}\n"
    fi
}

run_init() {
    log "Running init..."
    local bin="${BUILD_DIR}/release/secret-stripper"
    [ -f "/usr/local/bin/secret-stripper" ] && bin="/usr/local/bin/secret-stripper"

    if "$bin" init 2>>"$LOG_FILE"; then
        printf "  ${GREEN}[OK]${NC} Configuration written and hotkey bound to your desktop\n"
    else
        printf "  ${YELLOW}[~]${NC} Init skipped (run '${bin} init' later)\n"
    fi
}

print_summary() {
    printf "\n${GREEN}${BOLD}========================================${NC}\n"
    printf "${GREEN}${BOLD}  Secret Stripper installed successfully!${NC}\n"
    printf "${GREEN}${BOLD}========================================${NC}\n"
    printf "\n"
    printf "  ${BOLD}How to use:${NC} highlight any text and press your hotkey (default Ctrl+Alt+C).\n"
    printf "  The clipboard will hold a redacted version - paste with Ctrl+V.\n\n"
    printf "  ${CYAN}secret-stripper menu${NC}     - Toggle notifications, rebind hotkey, uninstall\n"
    printf "  ${CYAN}secret-stripper status${NC}   - Show current state\n"
    printf "  ${CYAN}secret-stripper trigger${NC}  - Manually run the redaction\n"
    printf "\n"
    printf "  ${YELLOW}Install log: ${LOG_FILE}${NC}\n"
    printf "\n"
}

failed() {
    printf "\n${RED}${BOLD}Installation failed!${NC}\n${YELLOW}Check: ${LOG_FILE}${NC}\n"
    exit 1
}

main() {
    clear
    print_banner
    > "$LOG_FILE"

    step "1" "Checking system requirements"
    check_deps
    printf "  ${GREEN}[OK]${NC} Rust toolchain ready\n"

    step "2" "Detecting platform"
    printf "  OS: ${CYAN}${OS}${NC} | Arch: ${CYAN}$(uname -m)${NC}\n"

    step "3" "Building Secret Stripper"
    build_release || failed

    step "4" "Installing binary"
    install_binary

    step "5" "Initializing config and binding hotkey"
    run_init

    print_summary
    trap - EXIT
}

cd "$PROJECT_DIR"
main "$@"
