#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}  Secret Stripper Uninstaller${NC}"
echo ""

uninstall_service() {
    if command -v secret-stripper &>/dev/null; then
        echo -e "  ${YELLOW}[~]${NC} Removing service..."
        secret-stripper uninstall 2>/dev/null || true
    fi
}

remove_binary() {
    echo -e "  ${YELLOW}[~]${NC} Removing binary..."
    sudo rm -f /usr/local/bin/secret-stripper 2>/dev/null || true
}

remove_config() {
    echo -e "  ${YELLOW}[~]${NC} Removing configuration..."
    rm -rf "${HOME}/.config/secret-stripper" 2>/dev/null || true
}

remove_service_files() {
    echo -e "  ${YELLOW}[~]${NC} Removing service files..."
    rm -f "${HOME}/.config/systemd/user/secret-stripper.service" 2>/dev/null || true
    rm -f "${HOME}/Library/LaunchAgents/com.secret-stripper.daemon.plist" 2>/dev/null || true
}

cleanup() {
    echo ""
    echo -e "${GREEN}[OK]${NC} Secret Stripper has been removed."
    echo -e "  ${YELLOW}Config directory was deleted.${NC}"
    echo ""
}

main() {
    uninstall_service
    remove_binary
    remove_service_files
    remove_config
    cleanup
}

main "$@"
