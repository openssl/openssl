#!/usr/bin/env bash
# Copyright(c) The Maintainers of Nanvix.
# Licensed under the MIT License.

# Thin wrapper that delegates to the nanvix-zutil CLI.
# Requires nanvix-zutil to be installed (pip install nanvix-zutil).

set -euo pipefail

# In CI containers the checkout directory may be owned by a different uid than
# the process running this script, triggering git's "dubious ownership" check.
# Mark the current directory safe before calling git rev-parse.
if [ -n "${CI:-}" ]; then
	git config --global --add safe.directory "$(pwd)"
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
VENV="$REPO_ROOT/.nanvix/venv"

if ! "$VENV/bin/nanvix-zutil" --version &>/dev/null 2>&1 && ! command -v nanvix-zutil &>/dev/null; then
	echo "nanvix-zutil not found — bootstrapping from nanvix/zutils latest release..." >&2
	WHEEL_URL=$(curl -fsSL "https://api.github.com/repos/nanvix/zutils/releases/latest" |
		python3 -c "
import sys, json
data = json.load(sys.stdin)
wheel = next(
    a['browser_download_url']
    for a in data['assets']
    if a['name'].endswith('.whl')
)
print(wheel)
")
	python3 -m venv "$VENV"
	"$VENV/bin/pip" install --quiet "$WHEEL_URL"
fi

if [ -f "$VENV/bin/activate" ]; then
	# shellcheck source=/dev/null
	source "$VENV/bin/activate"
fi

exec nanvix-zutil "$@"
