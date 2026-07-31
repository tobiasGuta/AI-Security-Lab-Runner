#!/usr/bin/env bash
set -e

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "${INSTALL_DIR}"
cp lab-runner "${INSTALL_DIR}/lab-runner"
chmod +x "${INSTALL_DIR}/lab-runner"
echo "Installed lab-runner to ${INSTALL_DIR}/lab-runner"
