#!/usr/bin/env bash
#
# Installer for nxcsweep
# https://github.com/eh050/nxcsweep
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/eh050/nxcsweep/main/install.sh | bash
#
set -euo pipefail

REPO_RAW_URL="https://raw.githubusercontent.com/eh050/nxcsweep/main/nxcsweep.sh"
SCRIPT_NAME="nxcsweep"
INSTALL_DIR="/usr/local/bin"

echo "Installing ${SCRIPT_NAME}..."

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

if ! curl -sSL "$REPO_RAW_URL" -o "$TMP_FILE"; then
    echo "Error: failed to download ${SCRIPT_NAME} from ${REPO_RAW_URL}" >&2
    exit 1
fi

chmod +x "$TMP_FILE"

if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_FILE" "$INSTALL_DIR/$SCRIPT_NAME"
else
    echo "Requesting sudo to write to ${INSTALL_DIR}..."
    sudo mv "$TMP_FILE" "$INSTALL_DIR/$SCRIPT_NAME"
fi

trap - EXIT

echo "Installed to ${INSTALL_DIR}/${SCRIPT_NAME}"

if command -v "$SCRIPT_NAME" >/dev/null 2>&1; then
    echo "Done. Run '${SCRIPT_NAME}' from anywhere."
else
    echo "Done, but ${INSTALL_DIR} doesn't appear to be on your PATH."
    echo "Add it with: export PATH=\"${INSTALL_DIR}:\$PATH\""
fi
