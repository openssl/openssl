#!/usr/bin/env bash
# Copyright(c) The Maintainers of Nanvix.
# Licensed under the MIT License.

# Thin wrapper that delegates to the nanvix-zutil CLI.
# Requires nanvix-zutil to be installed (pip install nanvix-zutil).

set -euo pipefail

# If nanvix-zutil is already on PATH (e.g. CI), use it directly.
if command -v nanvix-zutil &>/dev/null; then
	exec nanvix-zutil "$@"
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

VENV="$REPO_ROOT/.nanvix/venv"

if ! "$VENV/bin/nanvix-zutil" --version &>/dev/null && ! command -v nanvix-zutil &>/dev/null; then
	echo "nanvix-zutil not found — bootstrapping from nanvix/zutils latest release..." >&2
	WHEEL_URL=$(curl -fsSL "https://api.github.com/repos/nanvix/zutils/releases/latest" |
		python3 -c "
import sys, json
data = json.load(sys.stdin)
assets = data.get('assets') or []
wheel = next(
    (a['browser_download_url'] for a in assets if a.get('name', '').endswith('.whl')),
    None,
)
if not wheel:
    print('Error: no .whl asset in latest nanvix/zutils release.', file=sys.stderr)
    print('Install manually: pip install nanvix-zutil', file=sys.stderr)
    sys.exit(1)
print(wheel)
")
	if [ -d "$VENV" ]; then
		python3 -m venv --clear "$VENV"
	else
		python3 -m venv "$VENV"
	fi
	"$VENV/bin/pip" install --quiet "$WHEEL_URL"
fi

# Prefer the venv copy if it exists; otherwise use the global install.
if [ -x "$VENV/bin/nanvix-zutil" ]; then
	exec "$VENV/bin/nanvix-zutil" "$@"
elif command -v nanvix-zutil &>/dev/null; then
	exec nanvix-zutil "$@"
else
	echo "nanvix-zutil not found in venv ($VENV) or on PATH." >&2
	exit 1
fi
