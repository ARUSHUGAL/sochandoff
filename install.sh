#!/bin/sh
# sochandoff one-line installer.
# Usage: curl -fsSL https://raw.githubusercontent.com/ARUSHUGAL/sochandoff/main/install.sh | sh
set -eu

REPO="https://github.com/ARUSHUGAL/sochandoff.git"

echo "Installing sochandoff..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required but not found." >&2
  exit 1
fi

if ! command -v pip3 >/dev/null 2>&1 && ! python3 -m pip --version >/dev/null 2>&1; then
  echo "error: pip is required but not found." >&2
  exit 1
fi

# Prefer pipx for an isolated install if available; fall back to pip --user.
if command -v pipx >/dev/null 2>&1; then
  pipx install "git+${REPO}"
else
  python3 -m pip install --user "git+${REPO}"
fi

echo ""
echo "Done. Run 'sochandoff' to try it with sample data."
echo "If the command is not found, add your user bin to PATH"
echo "(e.g. ~/.local/bin on Linux, ~/Library/Python/3.x/bin on macOS)."
