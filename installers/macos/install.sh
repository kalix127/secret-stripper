#!/bin/bash
# macOS installer script - delegates to the main install.sh with macOS-specific logic
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"${SCRIPT_DIR}/../install.sh"
